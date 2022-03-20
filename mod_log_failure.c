/*
 * ProFTPD: mod_log_failure -- logs failures to a separate log file
 * Copyright (c) 2016-2022 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * This is mod_log_failure, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#include "logfmt.h"
#include "json.h"
#include "ccan-json.h"

#define MOD_LOG_FAILURE_VERSION		"mod_log_failure/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030606
# error "ProFTPD 1.3.6a or later required"
#endif

module log_failure_module;

static int log_failure_logfd = -1;
static pool *log_failure_pool = NULL;
static pr_table_t *log_failure_fields = NULL;
static char *log_failure_fmt = NULL;

static const char *trace_channel = "failure";

#define LOG_FAILURE_EVENT_FL_CONNECT	0x0001
#define LOG_FAILURE_EVENT_FL_DISCONNECT	0x0002

/* Entries in the field table identify the field name, and the data type, for
 * e.g. JSON (or other) formatting: * Boolean, number, or string.
 */
struct field_info {
  unsigned int field_type;
  const char *field_name;
  size_t field_namelen;
};

/* The LogFormat "meta" values are in the unsigned char range; for our
 * specific "meta" values, then, choose something greater than 256.
 */
#define LOG_FAILURE_META_CONNECT			427
#define LOG_FAILURE_META_DISCONNECT			428

#define LOG_FAILURE_FIELD_TYPE_BOOLEAN			1
#define LOG_FAILURE_FIELD_TYPE_NUMBER			2
#define LOG_FAILURE_FIELD_TYPE_STRING			3

/* Key comparison for the ID/name table. */
static int field_id_cmp(const void *k1, size_t ksz1, const void *k2,
  size_t ksz2) {

  /* Return zero to indicate a match, non-zero otherwise. */
  return (*((unsigned int *) k1) == *((unsigned int *) k2) ? 0 : 1);
}

/* Key "hash" callback for ID/name table. */
static unsigned int field_id_hash(const void *k, size_t ksz) {
  unsigned int c;
  unsigned int res;

  memcpy(&c, k, ksz);
  res = (c << 8);

  return res;
}

static int field_add(pool *p, pr_table_t *tab, unsigned int id,
    const char *name, unsigned int field_type) {
  unsigned int *k;
  struct field_info *fi;
  int res;

  k = palloc(p, sizeof(unsigned int));
  *k = id;

  fi = palloc(p, sizeof(struct field_info));
  fi->field_type = field_type;
  fi->field_name = name;
  fi->field_namelen = strlen(name) + 1;

  res = pr_table_kadd(tab, (const void *) k, sizeof(unsigned int),
    fi, sizeof(struct field_info *));
  return res;
}

static int log_failure_mkfields(pool *p) {
  pr_table_t *fields;

  fields = pr_table_alloc(p, 0);
  if (pr_table_ctl(fields, PR_TABLE_CTL_SET_KEY_CMP,
      (void *) field_id_cmp) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_INFO, "error setting key comparison callback for "
      "field ID/names: %s", strerror(errno));
    pr_table_free(fields);

    errno = xerrno;
    return -1;
  }

  if (pr_table_ctl(fields, PR_TABLE_CTL_SET_KEY_HASH,
      (void *) field_id_hash) < 0) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_INFO, "error setting key hash callback for "
      "field ID/names: %s", strerror(errno));
    pr_table_free(fields);

    errno = xerrno;
    return -1;
  }

  /* Now populate the table with the ID/name values.  The key is the
   * LogFormat "meta" ID, and the value is the corresponding name string,
   * for use e.g. as JSON object member names.
   */

  field_add(p, fields, LOGFMT_META_BYTES_SENT, "bytes_sent",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_FILENAME, "file",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_ENV_VAR, "ENV:",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_REMOTE_HOST, "remote_dns",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_REMOTE_IP, "remote_ip",
    LOG_FAILURE_FIELD_TYPE_STRING);

#if defined(LOGFMT_META_REMOTE_PORT)
  field_add(p, fields, LOGFMT_META_REMOTE_PORT, "remote_port",
    LOG_FAILURE_FIELD_TYPE_NUMBER);
#endif /* LOGFMT_META_REMOTE_PORT */

  field_add(p, fields, LOGFMT_META_IDENT_USER, "identd_user",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_PID, "pid",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_TIME, "local_time",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_SECONDS, "transfer_secs",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_COMMAND, "raw_command",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_LOCAL_NAME, "server_name",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_LOCAL_PORT, "local_port",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_LOCAL_IP, "local_ip",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_LOCAL_FQDN, "server_dns",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_USER, "user",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_ORIGINAL_USER, "original_user",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_RESPONSE_CODE, "response_code",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

#if defined(LOGFMT_META_RESPONSE_MS)
  field_add(p, fields, LOGFMT_META_RESPONSE_MS, "response_ms",
    LOG_FAILURE_FIELD_TYPE_NUMBER);
#endif /* LOGFMT_META_RESPONSE_MS */

  field_add(p, fields, LOGFMT_META_CLASS, "connection_class",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_ANON_PASS, "anon_password",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_METHOD, "command",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_XFER_PATH, "transfer_path",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_DIR_NAME, "dir_name",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_DIR_PATH, "dir_path",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_CMD_PARAMS, "command_params",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_RESPONSE_STR, "response_msg",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_PROTOCOL, "protocol",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_VERSION, "server_version",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_RENAME_FROM, "rename_from",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_FILE_MODIFIED, "file_modified",
    LOG_FAILURE_FIELD_TYPE_BOOLEAN);

  field_add(p, fields, LOGFMT_META_UID, "uid",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_GID, "gid",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_RAW_BYTES_IN, "session_bytes_rcvd",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_RAW_BYTES_OUT, "session_bytes_sent",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_EOS_REASON, "session_end_reason",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_VHOST_IP, "server_ip",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_NOTE_VAR, "NOTE:",
    LOG_FAILURE_FIELD_TYPE_STRING);

#if defined(LOGFMT_META_XFER_MS)
  field_add(p, fields, LOGFMT_META_XFER_MS, "transfer_ms",
    LOG_FAILURE_FIELD_TYPE_NUMBER);
#endif /* LOGFMT_META_XFER_MS */

  field_add(p, fields, LOGFMT_META_XFER_STATUS, "transfer_status",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_XFER_FAILURE, "transfer_failure",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_MICROSECS, "microsecs",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_MILLISECS, "millisecs",
    LOG_FAILURE_FIELD_TYPE_NUMBER);

  field_add(p, fields, LOGFMT_META_ISO8601, "timestamp",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOGFMT_META_GROUP, "group",
    LOG_FAILURE_FIELD_TYPE_STRING);

  field_add(p, fields, LOG_FAILURE_META_CONNECT, "connecting",
    LOG_FAILURE_FIELD_TYPE_BOOLEAN);

  field_add(p, fields, LOG_FAILURE_META_DISCONNECT, "disconnecting",
    LOG_FAILURE_FIELD_TYPE_BOOLEAN);

  log_failure_fields = fields;
  return 0;
}

#if PROFTPD_VERSION_NUMBER >= 0x0001030603
/* Out-of-memory handling. */
static void log_failure_oom(void) {
  pr_log_pri(PR_LOG_CRIT, MOD_LOG_FAILURE_VERSION ": Out of memory!");
  _exit(1);
}
#endif /* ProFTPD 1.3.6rc3 and later */

/* Logging */

static void log_failure_mkjson(void *json, const char *field_name,
    size_t field_namelen, unsigned int field_type, const void *field_value) {
  JsonNode *field = NULL;

  switch (field_type) {
    case LOG_FAILURE_FIELD_TYPE_STRING:
      field = json_mkstring((const char *) field_value);
      break;

    case LOG_FAILURE_FIELD_TYPE_NUMBER:
      field = json_mknumber(*((double *) field_value));
      break;

    case LOG_FAILURE_FIELD_TYPE_BOOLEAN:
      field = json_mkbool(*((int *) field_value));
      break;

    default:
      (void) pr_log_writefile(log_failure_logfd, MOD_LOG_FAILURE_VERSION,
        "unsupported field type: %u", field_type);
  }

  if (field != NULL) {
    json_append_member(json, field_name, field);
  }
}

static char *get_meta_arg(pool *p, unsigned char *m, size_t *arglen) {
  char buf[PR_TUNABLE_PATH_MAX+1], *ptr;
  size_t len;

  ptr = buf;
  len = 0;

  while (*m != LOGFMT_META_ARG_END) {
    pr_signals_handle();
    *ptr++ = (char) *m++;
    len++;
  }

  *ptr = '\0';
  *arglen = len;

  return pstrdup(p, buf);
}

static int find_next_meta(pool *p, int flags, cmd_rec *cmd,
    unsigned char **fmt, void *obj,
    void (*mkfield)(void *, const char *, size_t, unsigned int, const void *)) {
  const struct field_info *fi;
  unsigned char *m;
  unsigned int meta;

  m = (*fmt) + 1;

  meta = *m;
  fi = pr_table_kget(log_failure_fields, (const void *) &meta,
    sizeof(unsigned int), NULL);

  switch (*m) {
/* XXX How to deal with the fact that we're not dealing with cmd_recs here,
 * but rather other events.  The issue isn't the cmd so much as the LogFormat
 * variables which MAY be predicated on commands (e.g. %m, %r).  Skip them?
 * Ignore them, perhaps?
 *
 * For some (e.g. failed transfers), the paths/filenames would be useful,
 * but they would need to be provided via event data (perhaps?), rather than
 * a cmd_rec (or not).
 */

    default:
      pr_trace_msg(trace_channel, 7,
        "skipping unsupported LogFormat meta %d", *m);
      break;
  }

  *fmt = m;
  return 0;
}

static int log_failure_mkmsg(int flags, pool *p, cmd_rec *cmd,
    const unsigned char *fmt, void *json,
    void (*mkfield)(void *, const char *, size_t, unsigned int, const void *)) {

  if (flags == LOG_FAILURE_EVENT_FL_CONNECT &&
      session.prev_server == NULL) {
    unsigned int meta = LOG_FAILURE_META_CONNECT;
    const struct field_info *fi;
    int connecting = TRUE;

    fi = pr_table_kget(log_failure_fields, (const void *) &meta,
      sizeof(unsigned int), NULL);

    mkfield(json, fi->field_name, fi->field_namelen, fi->field_type,
      &connecting);

  } else if (flags == LOG_FAILURE_EVENT_FL_DISCONNECT) {
    unsigned int meta = LOG_FAILURE_META_DISCONNECT;
    const struct field_info *fi;
    int disconnecting = TRUE;

    fi = pr_table_kget(log_failure_fields, (const void *) &meta,
      sizeof(unsigned int), NULL);

    mkfield(json, fi->field_name, fi->field_namelen, fi->field_type,
      &disconnecting);
  }

  while (*fmt) {
    pr_signals_handle();

    if (*fmt == LOGFMT_META_START) {
      find_next_meta(p, flags, cmd, (unsigned char **) &fmt, json, mkfield);

    } else {
      fmt++;
    }
  }

  return 0;
}

static int log_failure_fmt_msg(pool *p, const unsigned char *fmt, cmd_rec *cmd,
    const char *event_name, char **msg, size_t *msg_len, int flags) {
  int res;
  char errstr[256], *json = NULL;
  void *obj = NULL;

  obj = json_mkobject();
  res = log_failure_mkmsg(flags, p, cmd, fmt, obj, log_failure_mkjson);

  if (!json_check(obj, errstr)) {
    pr_log_debug(DEBUG3, MOD_LOG_FAILURE_VERSION
      ": JSON structural problems: %s", errstr);
    errno = EINVAL;

    json_delete(obj);
    return -1;
  }

  json = json_encode(obj);
  pr_trace_msg(trace_channel, 3, "generated JSON payload: %s", json);

  *msg_len = strlen(json);
  *msg = palloc(p, *msg_len);
  memcpy(*msg, json, *msg_len);

  /* To avoid a memory leak via malloc(3), we have to explicitly call free(3)
   * on the returned JSON string.  Which is why we duplicate it out of the
   * given memory pool, for use outside of this function.
   */
  free(json);
  json_delete(obj);

  return 0;
}

static void log_failure_event(const char *event_name, int flags) {
  int res;
  cmd_rec *cmd = NULL;
  char *msg = NULL;
  size_t msg_len = 0;
  pool *p;

  p = make_sub_pool(log_failure_pool);
  pr_pool_tag(p, "FailureLog Message Pool");

  res = log_failure_fmt_msg(p, log_failure_fmt, cmd, event_name, &msg, &msg_len,
    flags);
  if (res < 0) {
    pr_trace_msg(trace_channel, 2, "error formatting message: %s",
      strerror(errno));

  } else {
    res = write(log_failure_logfd, msg, msg_len);
    while (res < 0) {
      int xerrno = errno;

      if (xerrno == EINTR) {
        pr_signals_handle();
        res = write(log_failure_logfd, msg, msg_len);
        continue;
      }

      pr_trace_msg(trace_channel, 2, "error writing message to FailureLog: %s",
        strerror(xerrno));
      break;
    }
  }

  destroy_pool(p);
}

/* Configuration directive */

/* usage: FailureLog path [logfmt-name] */
MODRET set_failurelog(cmd_rec *cmd) {
  config_rec *c;
  const char *path;
  char *log_fmt = NULL;

  if (cmd->argc < 2 ||
      cmd->argc > 3) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  path = cmd->argv[1];
  if (*path != '/') {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  if (cmd->argc == 3) {
    const char *fmt_name;

    fmt_name = cmd->argv[2];

    /* Double-check that logfmt-name is valid, defined, etc. Look up the
     * format string, and stash a pointer to that in the config_rec (but NOT
     * a copy of the format string; don't need to use that much memory).
     */
    c = find_config(cmd->server->conf, CONF_PARAM, "LogFormat", FALSE);
    while (c != NULL) {
      if (strcmp(c->argv[0], fmt_name) == 0) {
        log_fmt = c->argv[1];
        break;
      }

      log_fmt = NULL;
      c = find_config_next(c, c->next, CONF_PARAM, "LogFormat", FALSE);
    }

    if (log_fmt == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "no such LogFormat '",
        cmd->argv[2], "' configured", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, path);
  c->argv[1] = log_fmt;

  return PR_HANDLED(cmd);
}

/* Event listeners */

#if defined(PR_SHARED_MODULE)
static void log_failure_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_log_failure.c", (const char *) event_data) == 0) {
    pr_event_unregister(&log_failure_module, NULL, NULL);
    destroy_pool(log_failure_pool);
    log_failure_pool = NULL;

    (void) close(log_failure_logfd);
    log_failure_logfd = -1;
  }
}
#endif /* PR_SHARED_MODULE */

static void log_failure_restart_ev(const void *event_data, void *user_data) {
  destroy_pool(log_failure_pool);
  log_failure_fields = NULL;

  log_failure_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(log_failure_pool, MOD_LOG_FAILURE_VERSION);

  if (log_failure_mkfields(log_failure_pool) < 0) {
    pr_trace_msg(trace_channel, 3, "error creating fields table: %s",
      strerror(errno));
  }
}

static void log_failure_auth_code_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_empty_passwd_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_logins_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_clients_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_clients_per_class_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_clients_per_host_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_clients_per_user_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_conns_per_host_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_max_hosts_per_user_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_timeout_idle_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_timeout_login_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_timeout_noxfer_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_timeout_session_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_timeout_stalled_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_tls_ctrl_handshake_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_tls_data_handshake_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_tls_verify_client_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_sftp_auth_pubkey_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_sftp_auth_kbdint_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_sftp_auth_passwd_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_sftp_kex_err_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_ban_ban_user_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_ban_ban_host_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_ban_ban_class_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_geoip_denied_ev(const void *event_data,
    void *user_data) {
}

static void log_failure_wrap_denied_ev(const void *event_data,
    void *user_data) {
}

/* Initialization routines */

static int log_failure_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&log_failure_module, "core.module-unload",
    log_failure_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&log_failure_module, "core.restart",
    log_failure_restart_ev, NULL);

  log_failure_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(log_failure_pool, MOD_LOG_FAILURE_VERSION);

  if (log_failure_mkfields(log_failure_pool) < 0) {
    return -1;
  }

#if PROFTPD_VERSION_NUMBER >= 0x0001030603
  /* Use our own OOM handler. */
  json_set_oom(log_failure_oom);
#endif /* ProFTPD 1.3.6rc3 and later */

  return 0;
}

static int log_failure_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "FailureLog", FALSE);
  if (c == NULL) {
    return 0;
  }

  /* XXX Open FailureLog */

  /* "Authentication" class */
  pr_event_register(&log_failure_module, "mod_auth.authentication-code",
    log_failure_auth_code_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.empty-password",
    log_failure_empty_passwd_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-login-attempts",
    log_failure_max_logins_ev, NULL);

  /* XXX Include AnonRejectPassword? */

  /* "Connection" class */
  pr_event_register(&log_failure_module, "mod_auth.max-clients",
    log_failure_max_clients_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-clients-per-class",
    log_failure_max_clients_per_class_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-clients-per-host",
    log_failure_max_clients_per_host_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-clients-per-user",
    log_failure_max_clients_per_user_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-connections-per-host",
    log_failure_max_conns_per_host_ev, NULL);
  pr_event_register(&log_failure_module, "mod_auth.max-hosts-per-user",
    log_failure_max_hosts_per_user_ev, NULL);

  /* XXX "Transfer" class, for failed uploads/downloads/dirlists */

  /* "Timeout" class */
  pr_event_register(&log_failure_module, "core.timeout-idle",
    log_failure_timeout_idle_ev, NULL);
  pr_event_register(&log_failure_module, "core.timeout-login",
    log_failure_timeout_login_ev, NULL);
  pr_event_register(&log_failure_module, "core.timeout-no-transfer",
    log_failure_timeout_noxfer_ev, NULL);
  pr_event_register(&log_failure_module, "core.timeout-session",
    log_failure_timeout_session_ev, NULL);
  pr_event_register(&log_failure_module, "core.timeout-stalled",
    log_failure_timeout_stalled_ev, NULL);

  if (pr_module_exists("mod_tls.c") == TRUE) {
    /* "Connection" class */
    pr_event_register(&log_failure_module, "mod_tls.ctrl-handshake-failed",
      log_failure_tls_ctrl_handshake_err_ev, NULL);
    pr_event_register(&log_failure_module, "mod_tls.data-handshake-failed",
      log_failure_tls_data_handshake_err_ev, NULL);
    pr_event_register(&log_failure_module, "mod_tls.verify-client-failed",
      log_failure_tls_verify_client_err_ev, NULL);
  }

  if (pr_module_exists("mod_sftp.c") == TRUE) {
    /* "Authentication" class */
    pr_event_register(&log_failure_module,
      "mod_sftp.ssh2.auth-publickey.failed",
      log_failure_sftp_auth_pubkey_err_ev, NULL);
    pr_event_register(&log_failure_module, "mod_sftp.ssh2.auth-kbdint.failed",
      log_failure_sftp_auth_kbdint_err_ev, NULL);
    pr_event_register(&log_failure_module, "mod_sftp.ssh2.auth-password.failed",
      log_failure_sftp_auth_passwd_err_ev, NULL);

    /* "Connection" class */
    pr_event_register(&log_failure_module, "mod_sftp.ssh2.kex.failed",
      log_failure_sftp_kex_err_ev, NULL);
  }

  if (pr_module_exists("mod_ban.c") == TRUE) {
    /* "Connection" class */
    pr_event_register(&log_failure_module, "mod_ban.ban-user",
      log_failure_ban_ban_user_ev, NULL);
    pr_event_register(&log_failure_module, "mod_ban.ban-host",
      log_failure_ban_ban_host_ev, NULL);
    pr_event_register(&log_failure_module, "mod_ban.ban-class",
      log_failure_ban_ban_class_ev, NULL);
  }

  if (pr_module_exists("mod_geoip.c") == TRUE) {
    /* "Connection" class */
    pr_event_register(&log_failure_module, "mod_geoip.connection-denied",
      log_failure_geoip_denied_ev, NULL);
  }

  if (pr_module_exists("mod_wrap.c") == TRUE ||
      pr_module_exists("mod_wrap2.c") == TRUE) {
    /* "Connection" class */
    pr_event_register(&log_failure_module, "mod_wrap.connection-denied",
      log_failure_wrap_denied_ev, NULL);
  }

  return 0;
}

/* Module API tables */

static conftable log_failure_conftab[] = {
  { "FailureLog",		set_failurelog,			NULL },

  { NULL }
};

module log_failure_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "log_failure",

  /* Module configuration handler table */
  log_failure_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  log_failure_init,

  /* Session initialization function */
  log_failure_sess_init,

  /* Module version */
  MOD_LOG_FAILURE_VERSION
};

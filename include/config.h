#ifndef RL_CONFIG_H
#define RL_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include "ratelimit.h"

/* Text config, line based. '#' starts a comment. A zone line:
 *
 *   zone <name> type=ip|token|route key=<prefix|$ip|$token|anon> \
 *        alg=token_bucket|sliding_log rate=<n>/s|/m burst=<n>
 *
 * Examples in tests/rlproxy.conf. Unknown keys are hard errors so a
 * typo cannot silently disable a limit. */

typedef enum { ZT_IP = 0, ZT_TOKEN = 1, ZT_ROUTE = 2 } zone_type_t;

typedef struct {
    char        name[64];
    zone_type_t type;
    char        match[256];   /* route prefix, or "" for ip/token zones */
    rl_params_t params;
} zone_cfg_t;

typedef struct {
    char     listen_host[64];
    int      listen_port;
    char     upstream_host[128];
    int      upstream_port;
    char     token_header[64];   /* header carrying the user token */
    int      max_conns;          /* hard cap on client connections */
    int      idle_timeout_ms;    /* no-data timeout on either leg */
    int      head_timeout_ms;    /* deadline for full request head */
    int      stats_interval_s;   /* 0 disables periodic stats */
    int      trust_xff;          /* take client IP from X-Forwarded-For */
    zone_cfg_t zones[64];
    int      nzones;
} config_t;

void config_init_defaults(config_t *c);

/* Parse path into *out. Returns 0 on success; on failure returns -1 and
 * writes a human message (with 1-based line number) into err/errlen. */
int  config_load(const char *path, config_t *out, char *err, size_t errlen);

/* mtime check for hot reload; st_mtime_ms is opaque per-path. */
int64_t config_mtime_ms(const char *path);

#endif

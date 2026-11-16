#ifndef RL_PROXY_H
#define RL_PROXY_H

#include "event_loop.h"
#include "config.h"
#include "ratelimit.h"
#include "hashmap.h"

/* The proxy object owns the live zone set and the live config.
 * Hot reload swaps config and reconciles zones without touching any
 * in-flight connection — connections hold no pointers into config. */

typedef struct proxy {
    event_loop_t *el;
    config_t      cfg;
    hashmap_t    *zones;          /* name -> rl_zone_t* */
    int           listen_fd;
    int           nconns;         /* current client connections */
    uint64_t      total_conns;
    uint64_t      total_requests;
    uint64_t      total_denied;
    uint64_t      total_shed;     /* 503 from max_conns */
    int           reloading;
} proxy_t;

proxy_t *proxy_create(event_loop_t *el, const char *config_path,
                      char *err, size_t errlen);
void     proxy_destroy(proxy_t *p);

/* Hot reload: parse new config, reconfigure existing zones by name,
 * create added ones, drop removed ones. Existing sockets untouched.
 * Returns 0 on success, -1 with err filled (old config stays live). */
int proxy_reload(proxy_t *p, const char *config_path,
                 char *err, size_t errlen);

/* Snapshot stats for the SIGUSR1 dump / periodic printer. */
void proxy_dump_stats(proxy_t *p);

#endif

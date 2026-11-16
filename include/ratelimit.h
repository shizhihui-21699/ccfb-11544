#ifndef RL_RATELIMIT_H
#define RL_RATELIMIT_H

#include <stdint.h>
#include "hashmap.h"

/* Two independent algorithms per limit zone:
 *   token_bucket  — burst-friendly: capacity burst, sustained rate rate/window
 *   sliding_log   — sliding window log: at most rate timestamps in window ms
 *
 * State is keyed by an arbitrary string the proxy builds
 * (client IP, "anon"/token id, or route prefix). Zones own their maps. */

typedef enum { ALG_TOKEN_BUCKET = 0, ALG_SLIDING_LOG = 1 } alg_t;

typedef struct {
    alg_t    alg;
    long long rate;        /* sustained requests per window */
    long long burst;       /* bucket capacity (token bucket only) */
    long long window_ms;
} rl_params_t;

typedef struct {
    int       allowed;
    long long retry_after_s;   /* >=1 when denied; 0 when allowed */
    long long remaining;       /* tokens left / window slots left */
    long long limit;           /* effective ceiling for the key */
} rl_decision_t;

typedef struct rl_zone rl_zone_t;

rl_zone_t *rl_zone_create(const char *name, const rl_params_t *p);
void       rl_zone_destroy(rl_zone_t *z);

/* Reconfigure in place without dropping counters (hot reload).
 * Returns 0 on success, -1 on allocation failure (old state kept). */
int rl_zone_reconfigure(rl_zone_t *z, const rl_params_t *p);

/* The core check. now_ms supplied by caller so tests stay deterministic. */
rl_decision_t rl_zone_check(rl_zone_t *z, const char *key, int64_t now_ms);

/* Sweep keys idle longer than idle_ms. Called periodically by the proxy. */
void rl_zone_sweep(rl_zone_t *z, int64_t now_ms, int64_t idle_ms);

/* Stats / introspection. */
void rl_zone_stats(rl_zone_t *z, size_t *keys_out,
                   uint64_t *allowed_out, uint64_t *denied_out);
const char *rl_zone_name(rl_zone_t *z);
void        rl_zone_get_params(rl_zone_t *z, rl_params_t *out);

#endif

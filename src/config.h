#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>
#include "limiter.h"

#define MAX_ROUTES 64

typedef struct {
    char           prefix[256];
    limit_params_t p;
} route_cfg_t;

typedef struct {
    char          listen[256];    /* host:port */
    char          upstream[256];  /* host:port */
    int           max_conns;
    int           header_timeout_ms;
    int           idle_timeout_ms;
    int           ip_on;
    int           token_on;
    limit_params_t ip;
    limit_params_t token;
    route_cfg_t   routes[MAX_ROUTES];
    int           nroutes;
} config_t;

/* Loads config; *out is fully initialized (defaults applied first).
 * Returns 0 on success, -1 on error (err filled). */
int config_load(const char *path, config_t *out, char *err, size_t errcap);

#endif

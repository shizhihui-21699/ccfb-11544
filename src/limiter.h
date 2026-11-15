#ifndef LIMITER_H
#define LIMITER_H

#include <stddef.h>
#include <stdint.h>

typedef enum { ALG_TOKEN_BUCKET = 0, ALG_SLIDING_WINDOW = 1 } alg_t;

typedef struct {
    alg_t  alg;
    double rate;       /* token bucket: tokens per second */
    double burst;      /* token bucket: bucket capacity */
    int    limit;      /* sliding window: max requests per window */
    int    window_ms;  /* sliding window: window size */
} limit_params_t;

typedef struct entry {
    char    *key;
    /* token bucket state */
    double   tokens;
    uint64_t last_ms;
    /* sliding window log state (ring buffer of timestamps) */
    uint64_t *log;
    int      log_head, log_count, log_cap;
    uint64_t touch_ms;
    struct entry *next;
} entry_t;

typedef struct {
    limit_params_t p;
    entry_t      **tab;
    size_t         ntab;
    size_t         count;
    char           name[280];
} layer_t;

void layer_init(layer_t *l, const char *name, const limit_params_t *p);
void layer_free(layer_t *l);
/* Hot reload: swap parameters, keep per-key state. */
void layer_set_params(layer_t *l, const limit_params_t *p);
/* Returns 1 allow (consumes), 0 deny and sets *retry_ms. */
int  layer_check(layer_t *l, const char *key, uint64_t now_ms_, uint64_t *retry_ms);
/* Evict entries idle longer than their algorithm needs. */
void layer_sweep(layer_t *l, uint64_t now_ms_);

#endif

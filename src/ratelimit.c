#include "ratelimit.h"
#include "hashmap_internal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ---------- per-key state, one struct shape per algorithm ---------- */

typedef struct {
    double  tokens;
    int64_t last_refill_ms;
    int64_t last_seen_ms;
} tb_entry_t;

typedef struct {
    int64_t *ring;   /* timestamps in ms; ring holds at most rate items */
    size_t   cap;    /* allocated slots */
    size_t   head;   /* index of oldest */
    size_t   count;
    int64_t  last_seen_ms;
} sl_entry_t;

struct rl_zone {
    char        name[64];
    rl_params_t params;
    hashmap_t  *keys;
    uint64_t    allowed;
    uint64_t    denied;
};

static void *entry_create(alg_t alg, const rl_params_t *p, int64_t now_ms) {
    if (alg == ALG_TOKEN_BUCKET) {
        tb_entry_t *e = calloc(1, sizeof(*e));
        if (!e) return NULL;
        /* Start full so a freshly seen client gets its burst up front. */
        e->tokens = (double)(p->burst > 0 ? p->burst : p->rate);
        e->last_refill_ms = now_ms;
        e->last_seen_ms = now_ms;
        return e;
    }
    sl_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    size_t cap = (size_t)p->rate;
    if (cap > 1024) cap = 1024;       /* grow on demand up to rate */
    if (cap < 4) cap = 4;
    e->ring = malloc(cap * sizeof(int64_t));
    if (!e->ring) { free(e); return NULL; }
    e->cap = cap;
    e->last_seen_ms = now_ms;
    return e;
}

static void entry_destroy(alg_t alg, void *v) {
    if (!v) return;
    if (alg == ALG_SLIDING_LOG) free(((sl_entry_t *)v)->ring);
    free(v);
}

rl_zone_t *rl_zone_create(const char *name, const rl_params_t *p) {
    rl_zone_t *z = calloc(1, sizeof(*z));
    if (!z) return NULL;
    snprintf(z->name, sizeof(z->name), "%s", name);
    z->params = *p;
    z->keys = hm_create(64);
    if (!z->keys) { free(z); return NULL; }
    return z;
}

void rl_zone_destroy(rl_zone_t *z) {
    if (!z) return;
    for (size_t i = 0; i < z->keys->cap; i++) {
        if (z->keys->slots[i].key)
            entry_destroy(z->params.alg, z->keys->slots[i].value);
    }
    hm_destroy(z->keys);
    free(z);
}

int rl_zone_reconfigure(rl_zone_t *z, const rl_params_t *p) {
    if (z->params.alg != p->alg) {
        /* Algorithm swap: old counters are meaningless, start clean. */
        hashmap_t *old = z->keys;
        hashmap_t *fresh = hm_create(64);
        if (!fresh) return -1;
        z->keys = fresh;
        for (size_t i = 0; i < old->cap; i++) {
            if (old->slots[i].key)
                entry_destroy(z->params.alg, old->slots[i].value);
        }
        hm_destroy(old);
    }
    z->params = *p;
    return 0;
}

/* ---------- token bucket ---------- */

static rl_decision_t tb_check(rl_zone_t *z, const char *key, int64_t now_ms) {
    rl_decision_t d = {0};
    rl_params_t *p = &z->params;
    tb_entry_t *e = hm_get(z->keys, key);
    if (!e) {
        e = entry_create(ALG_TOKEN_BUCKET, p, now_ms);
        if (!e) { d.allowed = 1; d.limit = p->burst; return e ? d : d; }
        if (hm_put(z->keys, key, e) < 0) { free(e); d.allowed = 1; return d; }
    }
    e->last_seen_ms = now_ms;

    double refill_rate = (double)p->rate / (double)p->window_ms; /* tokens/ms */
    double elapsed = (double)(now_ms - e->last_refill_ms);
    if (elapsed > 0) {
        double add = elapsed * refill_rate;
        e->tokens += add;
        double cap = (double)p->burst;
        if (e->tokens > cap) e->tokens = cap;
        e->last_refill_ms = now_ms;
    }

    d.limit = p->burst;
    if (e->tokens >= 1.0) {
        e->tokens -= 1.0;
        d.allowed = 1;
        d.remaining = (long long)e->tokens;
    } else {
        d.allowed = 0;
        double need_ms = (1.0 - e->tokens) / refill_rate;
        d.retry_after_s = (long long)ceil(need_ms / 1000.0);
        if (d.retry_after_s < 1) d.retry_after_s = 1;
        d.remaining = 0;
    }
    return d;
}

/* ---------- sliding window log ---------- */

static int sl_grow(sl_entry_t *e, size_t need, size_t max_cap) {
    if (need <= e->cap) return 0;
    size_t ncap = e->cap;
    while (ncap < need) ncap *= 2;
    if (ncap > max_cap) ncap = max_cap;
    if (ncap <= e->cap) return -1;
    int64_t *nr = malloc(ncap * sizeof(int64_t));
    if (!nr) return -1;
    /* Unroll old ring into the new one in chronological order. */
    for (size_t i = 0; i < e->count; i++)
        nr[i] = e->ring[(e->head + i) % e->cap];
    free(e->ring);
    e->ring = nr;
    e->cap = ncap;
    e->head = 0;
    return 0;
}

static rl_decision_t sl_check(rl_zone_t *z, const char *key, int64_t now_ms) {
    rl_decision_t d = {0};
    rl_params_t *p = &z->params;
    sl_entry_t *e = hm_get(z->keys, key);
    if (!e) {
        e = entry_create(ALG_SLIDING_LOG, p, now_ms);
        if (!e) { d.allowed = 1; return d; } /* fail open on OOM */
        if (hm_put(z->keys, key, e) < 0) {
            entry_destroy(ALG_SLIDING_LOG, e);
            d.allowed = 1;
            return d;
        }
    }
    e->last_seen_ms = now_ms;

    /* Drop timestamps that slid out of the window. The window is the
     * half-open interval (now - window, now]: a request exactly window
     * ms old is still counted, so evict only strictly older entries. */
    int64_t cutoff = now_ms - p->window_ms;
    while (e->count > 0 && e->ring[e->head] < cutoff) {
        e->head = (e->head + 1) % e->cap;
        e->count--;
    }

    d.limit = p->rate;
    if ((long long)e->count < p->rate) {
        if (sl_grow(e, e->count + 1, (size_t)p->rate) < 0) {
            d.allowed = 1; /* fail open rather than crash under pressure */
            return d;
        }
        size_t idx = (e->head + e->count) % e->cap;
        e->ring[idx] = now_ms;
        e->count++;
        d.allowed = 1;
        d.remaining = p->rate - (long long)e->count;
    } else {
        d.allowed = 0;
        int64_t oldest = e->ring[e->head];
        int64_t wait_ms = oldest + p->window_ms - now_ms;
        d.retry_after_s = (wait_ms + 999) / 1000;
        if (d.retry_after_s < 1) d.retry_after_s = 1;
        d.remaining = 0;
    }
    return d;
}

rl_decision_t rl_zone_check(rl_zone_t *z, const char *key, int64_t now_ms) {
    rl_decision_t d = z->params.alg == ALG_TOKEN_BUCKET
        ? tb_check(z, key, now_ms)
        : sl_check(z, key, now_ms);
    if (d.allowed) z->allowed++; else z->denied++;
    return d;
}

/* ---------- idle sweep ---------- */

typedef struct {
    char   **keys;
    size_t   n, cap;
    int64_t  cutoff;
    alg_t    alg;
} sweep_ctx_t;

static int sweep_collect(const char *key, void *value, void *arg) {
    sweep_ctx_t *c = arg;
    int64_t seen = c->alg == ALG_TOKEN_BUCKET
        ? ((tb_entry_t *)value)->last_seen_ms
        : ((sl_entry_t *)value)->last_seen_ms;
    if (seen < c->cutoff) {
        if (c->n == c->cap) {
            c->cap = c->cap ? c->cap * 2 : 32;
            c->keys = realloc(c->keys, c->cap * sizeof(char *));
        }
        c->keys[c->n++] = strdup(key);
    }
    return 0;
}

void rl_zone_sweep(rl_zone_t *z, int64_t now_ms, int64_t idle_ms) {
    sweep_ctx_t c = {0};
    c.cutoff = now_ms - idle_ms;
    c.alg = z->params.alg;
    hm_iter(z->keys, sweep_collect, &c);
    for (size_t i = 0; i < c.n; i++) {
        void *v = hm_remove(z->keys, c.keys[i]);
        entry_destroy(z->params.alg, v);
        free(c.keys[i]);
    }
    free(c.keys);
}

void rl_zone_stats(rl_zone_t *z, size_t *keys_out,
                   uint64_t *allowed_out, uint64_t *denied_out) {
    if (keys_out) *keys_out = hm_size(z->keys);
    if (allowed_out) *allowed_out = z->allowed;
    if (denied_out) *denied_out = z->denied;
}

const char *rl_zone_name(rl_zone_t *z) { return z->name; }

void rl_zone_get_params(rl_zone_t *z, rl_params_t *out) { *out = z->params; }

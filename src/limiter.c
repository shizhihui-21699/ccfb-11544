#include "limiter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t hash_key(const char *s)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a */
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

void layer_init(layer_t *l, const char *name, const limit_params_t *p)
{
    memset(l, 0, sizeof(*l));
    l->p = *p;
    l->ntab = 1024;
    l->tab = calloc(l->ntab, sizeof(entry_t *));
    snprintf(l->name, sizeof(l->name), "%s", name ? name : "?");
}

void layer_free(layer_t *l)
{
    if (!l || !l->tab) return;
    for (size_t i = 0; i < l->ntab; i++) {
        entry_t *e = l->tab[i];
        while (e) {
            entry_t *nx = e->next;
            free(e->key);
            free(e->log);
            free(e);
            e = nx;
        }
    }
    free(l->tab);
    l->tab = NULL;
    l->ntab = 0;
    l->count = 0;
}

void layer_set_params(layer_t *l, const limit_params_t *p)
{
    l->p = *p;
}

static entry_t *entry_new(const char *key, const limit_params_t *p, uint64_t now)
{
    entry_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->key = strdup(key);
    e->touch_ms = now;
    e->last_ms = now;
    if (p->alg == ALG_TOKEN_BUCKET) {
        e->tokens = p->burst; /* new keys start with a full bucket */
    } else {
        e->log_cap = 16;
        e->log = calloc((size_t)e->log_cap, sizeof(uint64_t));
    }
    return e;
}

static void layer_grow(layer_t *l)
{
    size_t nn = l->ntab * 2;
    entry_t **nt = calloc(nn, sizeof(entry_t *));
    if (!nt) return;
    for (size_t i = 0; i < l->ntab; i++) {
        entry_t *e = l->tab[i];
        while (e) {
            entry_t *nx = e->next;
            size_t h = hash_key(e->key) & (nn - 1);
            e->next = nt[h];
            nt[h] = e;
            e = nx;
        }
    }
    free(l->tab);
    l->tab = nt;
    l->ntab = nn;
}

static entry_t *layer_get(layer_t *l, const char *key, uint64_t now)
{
    size_t h = hash_key(key) & (l->ntab - 1);
    for (entry_t *e = l->tab[h]; e; e = e->next)
        if (strcmp(e->key, key) == 0) return e;
    if (l->count > (l->ntab * 3) / 4) {
        layer_grow(l);
        h = hash_key(key) & (l->ntab - 1);
    }
    entry_t *e = entry_new(key, &l->p, now);
    if (!e) return NULL;
    e->next = l->tab[h];
    l->tab[h] = e;
    l->count++;
    return e;
}

static int sw_push(entry_t *e, int limit, uint64_t now)
{
    if (e->log_count == e->log_cap) {
        if (e->log_cap >= limit) return -1; /* shouldn't happen */
        int nc = e->log_cap * 2;
        if (nc > limit) nc = limit;
        uint64_t *nl = calloc((size_t)nc, sizeof(uint64_t));
        if (!nl) return -1;
        /* linearize ring: oldest first */
        for (int i = 0; i < e->log_count; i++)
            nl[i] = e->log[(e->log_head - e->log_count + i + e->log_cap) % e->log_cap];
        free(e->log);
        e->log = nl;
        e->log_cap = nc;
        e->log_head = e->log_count;
    }
    e->log[e->log_head] = now;
    e->log_head = (e->log_head + 1) % e->log_cap;
    e->log_count++;
    return 0;
}

int layer_check(layer_t *l, const char *key, uint64_t now, uint64_t *retry_ms)
{
    entry_t *e = layer_get(l, key, now);
    if (!e) return 1; /* OOM: fail open rather than take the service down */
    e->touch_ms = now;

    if (l->p.alg == ALG_TOKEN_BUCKET) {
        double el = (double)(now - e->last_ms) / 1000.0;
        e->last_ms = now;
        e->tokens += el * l->p.rate;
        if (e->tokens > l->p.burst) e->tokens = l->p.burst;
        if (e->tokens >= 1.0) {
            e->tokens -= 1.0;
            return 1;
        }
        *retry_ms = (uint64_t)((1.0 - e->tokens) / l->p.rate * 1000.0) + 1;
        return 0;
    }

    /* sliding window log: evict timestamps outside the window */
    while (e->log_count > 0) {
        uint64_t oldest = e->log[(e->log_head - e->log_count + e->log_cap) % e->log_cap];
        if (now - oldest >= (uint64_t)l->p.window_ms) e->log_count--;
        else break;
    }
    if (e->log_count < l->p.limit) {
        if (sw_push(e, l->p.limit, now) == 0) return 1;
    }
    if (e->log_count > 0) {
        uint64_t oldest = e->log[(e->log_head - e->log_count + e->log_cap) % e->log_cap];
        *retry_ms = (uint64_t)l->p.window_ms - (now - oldest) + 1;
    } else {
        *retry_ms = (uint64_t)l->p.window_ms;
    }
    return 0;
}

void layer_sweep(layer_t *l, uint64_t now)
{
    uint64_t idle_ms;
    if (l->p.alg == ALG_SLIDING_WINDOW)
        idle_ms = (uint64_t)l->p.window_ms * 2 + 1000;
    else
        idle_ms = 300000; /* token bucket state is cheap to rebuild */

    for (size_t i = 0; i < l->ntab; i++) {
        entry_t **pp = &l->tab[i];
        while (*pp) {
            entry_t *e = *pp;
            if (now - e->touch_ms > idle_ms) {
                *pp = e->next;
                free(e->key);
                free(e->log);
                free(e);
                l->count--;
            } else {
                pp = &e->next;
            }
        }
    }
}

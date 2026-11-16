#include "hashmap_internal.h"

#include <stdlib.h>
#include <string.h>

/* FNV-1a, then Fibonacci mixing. Good enough for short ASCII keys;
 * the proxy keys are IPs, tokens and route prefixes. */
uint64_t hm_hash(const char *s, size_t len) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

typedef hm_slot_t slot_t;

static size_t next_pow2(size_t n) {
    size_t c = 8;
    while (c < n) c *= 2;
    return c;
}

hashmap_t *hm_create(size_t initial_cap) {
    hashmap_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->cap = next_pow2(initial_cap ? initial_cap : 8);
    m->slots = calloc(m->cap, sizeof(slot_t));
    if (!m->slots) { free(m); return NULL; }
    return m;
}

void hm_destroy(hashmap_t *m) {
    if (!m) return;
    for (size_t i = 0; i < m->cap; i++) free(m->slots[i].key);
    free(m->slots);
    free(m);
}

static slot_t *find_slot(hashmap_t *m, const char *key, uint64_t h) {
    size_t mask = m->cap - 1;
    size_t idx = h & mask;
    for (;;) {
        slot_t *s = &m->slots[idx];
        if (!s->key) return s;
        if (s->hash == h && strcmp(s->key, key) == 0) return s;
        idx = (idx + 1) & mask;
    }
}

static int hm_grow(hashmap_t *m) {
    size_t old_cap = m->cap;
    slot_t *old = m->slots;
    m->cap *= 2;
    m->slots = calloc(m->cap, sizeof(slot_t));
    if (!m->slots) { m->slots = old; m->cap = old_cap; return -1; }
    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].key) continue;
        slot_t *dst = find_slot(m, old[i].key, old[i].hash);
        *dst = old[i];
    }
    free(old);
    return 0;
}

void *hm_get(hashmap_t *m, const char *key) {
    uint64_t h = hm_hash(key, strlen(key));
    slot_t *s = find_slot(m, key, h);
    return s->key ? s->value : NULL;
}

int hm_put(hashmap_t *m, const char *key, void *value) {
    if ((m->size + 1) * 10 >= m->cap * 7) {
        if (hm_grow(m) < 0) return -1;
    }
    uint64_t h = hm_hash(key, strlen(key));
    slot_t *s = find_slot(m, key, h);
    if (s->key) { s->value = value; return 0; }
    s->key = strdup(key);
    if (!s->key) return -1;
    s->value = value;
    s->hash = h;
    m->size++;
    return 0;
}

void *hm_remove(hashmap_t *m, const char *key) {
    /* Rebuild the table without the key. Open addressing without
     * tombstones keeps lookups branch-light on the hot path. */
    uint64_t h = hm_hash(key, strlen(key));
    slot_t *s = find_slot(m, key, h);
    if (!s->key) return NULL;
    void *val = s->value;
    free(s->key);
    s->key = NULL;
    s->value = NULL;
    m->size--;

    size_t cap = m->cap;
    slot_t *old = m->slots;
    m->slots = calloc(cap, sizeof(slot_t));
    if (!m->slots) { m->slots = old; return val; } /* table stays usable */
    for (size_t i = 0; i < cap; i++) {
        if (!old[i].key) continue;
        slot_t *dst = find_slot(m, old[i].key, old[i].hash);
        *dst = old[i];
    }
    free(old);
    return val;
}

size_t hm_size(hashmap_t *m) { return m->size; }

void hm_iter(hashmap_t *m, hm_iter_fn fn, void *arg) {
    for (size_t i = 0; i < m->cap; i++) {
        if (m->slots[i].key && fn(m->slots[i].key, m->slots[i].value, arg))
            return;
    }
}

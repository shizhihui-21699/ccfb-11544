#ifndef RL_HASHMAP_H
#define RL_HASHMAP_H

#include <stddef.h>
#include <stdint.h>

/* Open-addressing string hashmap. Entries are owned by the table via
 * strdup of the key; values are caller-owned pointers.
 * Not thread safe — the proxy is single-threaded by design. */

typedef struct hashmap hashmap_t;
typedef int (*hm_iter_fn)(const char *key, void *value, void *arg);
                            /* return non-zero to stop iteration */

hashmap_t *hm_create(size_t initial_cap);
void       hm_destroy(hashmap_t *m);          /* frees keys, not values */
void      *hm_get(hashmap_t *m, const char *key);
int        hm_put(hashmap_t *m, const char *key, void *value);
void      *hm_remove(hashmap_t *m, const char *key);
size_t     hm_size(hashmap_t *m);
void       hm_iter(hashmap_t *m, hm_iter_fn fn, void *arg);

uint64_t   hm_hash(const char *s, size_t len);

#endif

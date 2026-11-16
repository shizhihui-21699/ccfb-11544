#ifndef RL_HASHMAP_INTERNAL_H
#define RL_HASHMAP_INTERNAL_H

#include "hashmap.h"

/* In-project only: direct slot access used by sweeps and stats dumps. */
typedef struct hm_slot {
    char    *key;
    void    *value;
    uint64_t hash;
} hm_slot_t;

struct hashmap {
    hm_slot_t *slots;
    size_t     cap;
    size_t     size;
};
#endif

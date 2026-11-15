#ifndef BUF_H
#define BUF_H

#include <stdlib.h>
#include <string.h>

/* Simple growable byte buffer. */
typedef struct {
    char  *p;
    size_t len;
    size_t cap;
} buf_t;

static inline int buf_reserve(buf_t *b, size_t need)
{
    if (b->len + need <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->len + need) nc *= 2;
    char *np = realloc(b->p, nc);
    if (!np) return -1;
    b->p = np;
    b->cap = nc;
    return 0;
}

static inline int buf_put(buf_t *b, const void *d, size_t n)
{
    if (buf_reserve(b, n) < 0) return -1;
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

static inline void buf_consume(buf_t *b, size_t n)
{
    if (n >= b->len) { b->len = 0; return; }
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
}

static inline void buf_reset(buf_t *b) { b->len = 0; }

static inline void buf_free(buf_t *b)
{
    free(b->p);
    b->p = NULL;
    b->len = b->cap = 0;
}

#endif

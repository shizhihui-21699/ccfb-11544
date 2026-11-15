#ifndef EVLOOP_H
#define EVLOOP_H

#include <stdint.h>

#define EV_READ  0x1u
#define EV_WRITE 0x2u

typedef struct evloop evloop_t;
typedef void (*ev_handler)(void *ud, uint32_t events);

evloop_t *evloop_new(void);
void      evloop_free(evloop_t *l);
int       ev_add(evloop_t *l, int fd, uint32_t events, ev_handler fn, void *ud);
int       ev_mod(evloop_t *l, int fd, uint32_t events);
int       ev_del(evloop_t *l, int fd);
/* Wait up to timeout_ms, dispatch ready events to handlers. Returns #events. */
int       ev_wait(evloop_t *l, int timeout_ms);

uint64_t  now_ms(void); /* CLOCK_MONOTONIC in milliseconds */

#endif

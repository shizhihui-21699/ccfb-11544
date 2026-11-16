#ifndef RL_EVENT_LOOP_H
#define RL_EVENT_LOOP_H

#include <stdint.h>

/* Platform abstraction over kqueue (macOS/BSD) and epoll (Linux).
 * Level-triggered, non-blocking IO throughout. */

#define EL_READ  0x01
#define EL_WRITE 0x02

typedef struct event_loop event_loop_t;
typedef void (*el_io_cb)(event_loop_t *el, int fd, int events, void *arg);
typedef void (*el_timer_cb)(event_loop_t *el, void *arg);
typedef void (*el_signal_cb)(event_loop_t *el, int sig, void *arg);

event_loop_t *el_create(void);
void          el_destroy(event_loop_t *el);

/* Associate a fd with the loop. Watch 0 initially. Modify later with
 * el_watch(). Re-adding the same fd with different arg replaces it. */
int el_watch(event_loop_t *el, int fd, int events, el_io_cb cb, void *arg);
int el_unwatch(event_loop_t *el, int fd);

/* One-shot timer. Returns an id (>0); 0 on failure. */
uint64_t el_timer_add(event_loop_t *el, int64_t delay_ms,
                      el_timer_cb cb, void *arg);
void     el_timer_cancel(event_loop_t *el, uint64_t id);

/* Signal is delivered via the self-pipe; callback runs in loop context. */
int el_signal(event_loop_t *el, int sig, el_signal_cb cb, void *arg);

int64_t el_now(event_loop_t *el);

/* Runs until el_stop() or no watched fds/timers remain. */
void el_run(event_loop_t *el);
void el_stop(event_loop_t *el);

#endif

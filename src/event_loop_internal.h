#ifndef RL_EVENT_LOOP_INTERNAL_H
#define RL_EVENT_LOOP_INTERNAL_H

#include "event_loop.h"
#include <sys/types.h>

#define EL_MAX_FDS 65536

typedef struct io_entry {
    el_io_cb  cb;
    void     *arg;
    int       events;   /* currently registered mask, 0 = idle slot */
    int       active;
} io_entry_t;

typedef struct timer {
    uint64_t     id;
    int64_t      deadline_ms;
    el_timer_cb  cb;
    void        *arg;
    int          cancelled;
} timer_t;

struct event_loop {
    /* platform backend handle (kq fd or epoll fd) */
    int          backend_fd;
    io_entry_t   ios[EL_MAX_FDS];

    /* min-heap of timers, array indexed 1..heap_n */
    timer_t    **heap;
    size_t       heap_cap, heap_n;
    uint64_t     next_timer_id;

    /* self-pipe for signal wakeups */
    int          sigpipe[2];
    el_signal_cb sig_cb[32];
    void        *sig_arg[32];

    int          stop;
    int64_t      now_cache_ms;
};

/* Backend hooks implemented in event_loop_kqueue.c / event_loop_epoll.c */
int  el_backend_init(event_loop_t *el);
void el_backend_wait(event_loop_t *el, int timeout_ms);
int  el_backend_add(event_loop_t *el, int fd, int events);
int  el_backend_mod(event_loop_t *el, int fd, int events);
int  el_backend_del(event_loop_t *el, int fd);

/* Heap helpers (event_loop.c) */
int      el_heap_push(event_loop_t *el, timer_t *t);
timer_t *el_heap_pop(event_loop_t *el);
void     el_heap_cancel_id(event_loop_t *el, uint64_t id);
int64_t  el_heap_next_deadline(event_loop_t *el);

#endif

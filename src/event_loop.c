#include "event_loop_internal.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>

/* ---------------- timer min-heap ---------------- */

static int heap_less(const timer_t *a, const timer_t *b) {
    if (a->deadline_ms != b->deadline_ms)
        return a->deadline_ms < b->deadline_ms;
    return a->id < b->id;
}

static void heap_swap(event_loop_t *el, size_t i, size_t j) {
    timer_t *t = el->heap[i];
    el->heap[i] = el->heap[j];
    el->heap[j] = t;
}

static void heap_sift_up(event_loop_t *el, size_t i) {
    while (i > 1) {
        size_t p = i / 2;
        if (!heap_less(el->heap[i], el->heap[p])) break;
        heap_swap(el, i, p);
        i = p;
    }
}

static void heap_sift_down(event_loop_t *el, size_t i) {
    for (;;) {
        size_t l = i * 2, r = l + 1, best = i;
        if (l <= el->heap_n && heap_less(el->heap[l], el->heap[best])) best = l;
        if (r <= el->heap_n && heap_less(el->heap[r], el->heap[best])) best = r;
        if (best == i) break;
        heap_swap(el, i, best);
        i = best;
    }
}

int el_heap_push(event_loop_t *el, timer_t *t) {
    if (el->heap_n + 1 >= el->heap_cap) {
        size_t ncap = el->heap_cap ? el->heap_cap * 2 : 64;
        timer_t **nh = realloc(el->heap, ncap * sizeof(*nh));
        if (!nh) return -1;
        el->heap = nh;
        el->heap_cap = ncap;
    }
    el->heap[++el->heap_n] = t;
    heap_sift_up(el, el->heap_n);
    return 0;
}

timer_t *el_heap_pop(event_loop_t *el) {
    if (el->heap_n == 0) return NULL;
    timer_t *t = el->heap[1];
    el->heap[1] = el->heap[el->heap_n--];
    if (el->heap_n) heap_sift_down(el, 1);
    return t;
}

void el_heap_cancel_id(event_loop_t *el, uint64_t id) {
    for (size_t i = 1; i <= el->heap_n; i++) {
        if (el->heap[i]->id == id) { el->heap[i]->cancelled = 1; return; }
    }
}

int64_t el_heap_next_deadline(event_loop_t *el) {
    if (el->heap_n == 0) return -1;
    return el->heap[1]->deadline_ms;
}

/* ---------------- signals via self-pipe ---------------- */

static event_loop_t *g_signal_el;

static void sig_handler(int sig) {
    if (!g_signal_el) return;
    int save = errno;
    unsigned char s = (unsigned char)sig;
    (void)write(g_signal_el->sigpipe[1], &s, 1);
    errno = save;
}

static void sigpipe_readable(event_loop_t *el, int fd, int ev, void *arg) {
    (void)fd; (void)ev; (void)arg;
    unsigned char buf[64];
    ssize_t n;
    while ((n = read(el->sigpipe[0], buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            int sig = buf[i];
            if (sig >= 0 && sig < 32 && el->sig_cb[sig])
                el->sig_cb[sig](el, sig, el->sig_arg[sig]);
        }
    }
}

/* ---------------- lifecycle ---------------- */

event_loop_t *el_create(void) {
    event_loop_t *el = calloc(1, sizeof(*el));
    if (!el) return NULL;
    el->backend_fd = -1;
    el->sigpipe[0] = el->sigpipe[1] = -1;

    if (pipe(el->sigpipe) < 0) { free(el); return NULL; }
    if (set_nonblock(el->sigpipe[0]) < 0 || set_nonblock(el->sigpipe[1]) < 0 ||
        set_cloexec(el->sigpipe[0]) < 0 || set_cloexec(el->sigpipe[1]) < 0)
        goto fail;

    if (el_backend_init(el) < 0) goto fail;
    if (el_watch(el, el->sigpipe[0], EL_READ, sigpipe_readable, NULL) < 0)
        goto fail;

    g_signal_el = el;
    el->now_cache_ms = now_ms();
    return el;

fail:
    if (el->backend_fd >= 0) close(el->backend_fd);
    if (el->sigpipe[0] >= 0) close(el->sigpipe[0]);
    if (el->sigpipe[1] >= 0) close(el->sigpipe[1]);
    free(el->heap);
    free(el);
    return NULL;
}

void el_destroy(event_loop_t *el) {
    if (!el) return;
    for (size_t i = 1; i <= el->heap_n; i++) free(el->heap[i]);
    free(el->heap);
    if (el->backend_fd >= 0) close(el->backend_fd);
    if (el->sigpipe[0] >= 0) close(el->sigpipe[0]);
    if (el->sigpipe[1] >= 0) close(el->sigpipe[1]);
    free(el);
}

int el_watch(event_loop_t *el, int fd, int events, el_io_cb cb, void *arg) {
    if (fd < 0 || fd >= EL_MAX_FDS) { errno = EBADF; return -1; }
    io_entry_t *e = &el->ios[fd];
    int rc;
    if (!e->active) {
        rc = el_backend_add(el, fd, events);
        if (rc < 0) return -1;
        e->active = 1;
    } else if (e->events != events) {
        rc = el_backend_mod(el, fd, events);
        if (rc < 0) return -1;
    }
    e->events = events;
    e->cb = cb;
    e->arg = arg;
    return 0;
}

int el_unwatch(event_loop_t *el, int fd) {
    if (fd < 0 || fd >= EL_MAX_FDS) return -1;
    io_entry_t *e = &el->ios[fd];
    if (!e->active) return 0;
    int rc = el_backend_del(el, fd);
    e->active = 0;
    e->events = 0;
    e->cb = NULL;
    e->arg = NULL;
    return rc;
}

uint64_t el_timer_add(event_loop_t *el, int64_t delay_ms,
                      el_timer_cb cb, void *arg) {
    timer_t *t = malloc(sizeof(*t));
    if (!t) return 0;
    t->id = ++el->next_timer_id;
    t->deadline_ms = el->now_cache_ms + delay_ms;
    t->cb = cb;
    t->arg = arg;
    t->cancelled = 0;
    if (el_heap_push(el, t) < 0) { free(t); return 0; }
    return t->id;
}

void el_timer_cancel(event_loop_t *el, uint64_t id) {
    if (id) el_heap_cancel_id(el, id);
}

int el_signal(event_loop_t *el, int sig, el_signal_cb cb, void *arg) {
    if (sig < 0 || sig >= 32) return -1;
    el->sig_cb[sig] = cb;
    el->sig_arg[sig] = arg;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    return sigaction(sig, &sa, NULL);
}

int64_t el_now(event_loop_t *el) { return el->now_cache_ms; }

void el_stop(event_loop_t *el) { el->stop = 1; }

void el_run(event_loop_t *el) {
    while (!el->stop) {
        el->now_cache_ms = now_ms();

        /* Fire due timers. Pop first so callbacks may add/cancel freely. */
        int fired = 0;
        while (el->heap_n) {
            timer_t *t = el->heap[1];
            if (t->deadline_ms > el->now_cache_ms) break;
            el_heap_pop(el);
            if (!t->cancelled) {
                el_timer_cb cb = t->cb;
                void *arg = t->arg;
                free(t);
                cb(el, arg);
                fired = 1;
            } else {
                free(t);
            }
        }
        if (el->stop) break;
        if (fired) continue; /* cheap timers may be due immediately */

        int timeout_ms = -1;
        int64_t next = el_heap_next_deadline(el);
        if (next >= 0) {
            int64_t wait = next - el->now_cache_ms;
            timeout_ms = wait < 0 ? 0 : (wait > 60000 ? 60000 : (int)wait);
        } else {
            timeout_ms = 60000; /* cap blocking so stats ticks survive */
        }
        el_backend_wait(el, timeout_ms);
        el->now_cache_ms = now_ms();
    }
}

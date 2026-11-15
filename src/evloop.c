#include "evloop.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#else
#include <sys/event.h>
#endif

struct evloop {
    int         fd;     /* kqueue or epoll fd */
    int         cap;    /* per-fd table capacity */
    ev_handler *fns;
    void      **uds;
    uint32_t   *masks;  /* currently registered interest per fd */
};

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

evloop_t *evloop_new(void)
{
    evloop_t *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
#ifdef __linux__
    l->fd = epoll_create1(0);
#else
    l->fd = kqueue();
#endif
    if (l->fd < 0) { free(l); return NULL; }
    return l;
}

void evloop_free(evloop_t *l)
{
    if (!l) return;
    close(l->fd);
    free(l->fns); free(l->uds); free(l->masks);
    free(l);
}

static int grow(evloop_t *l, int fd)
{
    if (fd < l->cap) return 0;
    int nc = l->cap ? l->cap : 256;
    while (nc <= fd) nc *= 2;
    ev_handler *nf = realloc(l->fns, (size_t)nc * sizeof(ev_handler));
    if (!nf) return -1;
    l->fns = nf;
    void **nu = realloc(l->uds, (size_t)nc * sizeof(void *));
    if (!nu) return -1;
    l->uds = nu;
    uint32_t *nm = realloc(l->masks, (size_t)nc * sizeof(uint32_t));
    if (!nm) return -1;
    l->masks = nm;
    for (int i = l->cap; i < nc; i++) {
        l->fns[i] = NULL; l->uds[i] = NULL; l->masks[i] = 0;
    }
    l->cap = nc;
    return 0;
}

int ev_mod(evloop_t *l, int fd, uint32_t ev)
{
    if (fd >= l->cap) return -1;
    uint32_t old = l->masks[fd];
    if (old == ev) return 0;
#ifdef __linux__
    struct epoll_event ee;
    memset(&ee, 0, sizeof ee);
    ee.events = ((ev & EV_READ) ? EPOLLIN : 0) | ((ev & EV_WRITE) ? EPOLLOUT : 0);
    ee.data.fd = fd;
    int op;
    if (ev == 0)         op = EPOLL_CTL_DEL;
    else if (old == 0)   op = EPOLL_CTL_ADD;
    else                 op = EPOLL_CTL_MOD;
    if (epoll_ctl(l->fd, op, fd, &ee) < 0) {
        if (!(op == EPOLL_CTL_DEL && (errno == ENOENT || errno == EBADF))) return -1;
    }
#else
    struct kevent kev[4];
    int n = 0;
    uint32_t del = old & ~ev;
    if (del & EV_READ)  EV_SET(&kev[n++], fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    if (del & EV_WRITE) EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    if (ev & EV_READ)   EV_SET(&kev[n++], fd, EVFILT_READ,  EV_ADD, 0, 0, NULL);
    if (ev & EV_WRITE)  EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    if (n) (void)kevent(l->fd, kev, n, NULL, 0, NULL); /* errors harmless */
#endif
    l->masks[fd] = ev;
    return 0;
}

int ev_add(evloop_t *l, int fd, uint32_t ev, ev_handler fn, void *ud)
{
    if (grow(l, fd) < 0) return -1;
    l->fns[fd] = fn;
    l->uds[fd] = ud;
    l->masks[fd] = 0;
    return ev_mod(l, fd, ev);
}

int ev_del(evloop_t *l, int fd)
{
    if (fd >= l->cap) return -1;
    ev_mod(l, fd, 0);
    l->fns[fd] = NULL;
    l->uds[fd] = NULL;
    return 0;
}

int ev_wait(evloop_t *l, int timeout_ms)
{
#ifdef __linux__
    struct epoll_event evs[256];
    int n = epoll_wait(l->fd, evs, 256, timeout_ms);
    for (int i = 0; i < n; i++) {
        int fd = evs[i].data.fd;
        if (fd >= l->cap || !l->fns[fd]) continue;
        uint32_t m = 0;
        if (evs[i].events & (EPOLLIN | EPOLLHUP | EPOLLERR)) m |= EV_READ;
        if (evs[i].events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) m |= EV_WRITE;
        l->fns[fd](l->uds[fd], m);
    }
    return n;
#else
    struct kevent evs[256];
    struct timespec ts;
    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
    int n = kevent(l->fd, NULL, 0, evs, 256, &ts);
    for (int i = 0; i < n; i++) {
        int fd = (int)evs[i].ident;
        if (fd >= l->cap || !l->fns[fd]) continue;
        uint32_t m = (evs[i].filter == EVFILT_READ) ? EV_READ : EV_WRITE;
        l->fns[fd](l->uds[fd], m);
    }
    return n;
#endif
}

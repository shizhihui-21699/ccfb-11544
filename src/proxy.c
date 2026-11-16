#include "proxy_internal.h"
#include "hashmap_internal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---------- periodic maintenance ---------- */

static void maintenance_timer(event_loop_t *el, void *arg);

static void schedule_maintenance(proxy_t *p) {
    el_timer_add(p->el, 1000, maintenance_timer, p);
}

static void maintenance_timer(event_loop_t *el, void *arg) {
    proxy_t *p = arg;

    /* Idle-key sweep: 10 windows of inactivity is plenty; zones with
     * short windows release memory quickly after an attack stops. */
    for (size_t i = 0; i < p->zones->cap; i++) {
        if (!p->zones->slots[i].key) continue;
        rl_zone_t *z = p->zones->slots[i].value;
        rl_params_t pp;
        rl_zone_get_params(z, &pp);
        int64_t idle = pp.window_ms * 10;
        if (idle < 30000) idle = 30000;
        rl_zone_sweep(z, el_now(el), idle);
    }

    if (p->cfg.stats_interval_s > 0)
        proxy_dump_stats(p);

    schedule_maintenance(p);
}

/* ---------- accept loop ---------- */

static void listen_readable(event_loop_t *el, int lfd, int ev, void *arg) {
    (void)el; (void)ev;
    proxy_t *p = arg;
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break; /* drained */
            if (errno == EMFILE || errno == ENFILE) {
                /* Table exhaustion: back off, do not spin. */
                log_err("accept fd table exhausted, pausing 100ms");
                struct timespec ts = {0, 100 * 1000000L};
                nanosleep(&ts, NULL);
                break;
            }
            log_err("accept: %s", strerror(errno));
            break;
        }
        if (set_nonblock(cfd) < 0 || set_cloexec(cfd) < 0) {
            close(cfd);
            continue;
        }
        if (p->nconns >= p->cfg.max_conns) {
            /* Shed at the door with 503 + Retry-After. This is the
             * connection-level backstop the IP/route limits sit behind. */
            static const char msg[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Connection: close\r\n"
                "Retry-After: 1\r\n"
                "Content-Length: 0\r\n\r\n";
            (void)write(cfd, msg, sizeof(msg) - 1);
            close(cfd);
            p->total_shed++;
            continue;
        }
        conn_t *c = conn_accept(p, cfd);
        if (!c) {
            close(cfd);
            log_err("conn_accept failed: %s", strerror(errno));
        }
    }
}

/* ---------- construction / teardown ---------- */

proxy_t *proxy_create(event_loop_t *el, const char *config_path,
                      char *err, size_t errlen) {
    proxy_t *p = calloc(1, sizeof(*p));
    if (!p) { snprintf(err, errlen, "oom"); return NULL; }
    p->el = el;
    p->listen_fd = -1;

    if (config_load(config_path, &p->cfg, err, errlen) < 0) {
        free(p);
        return NULL;
    }
    p->zones = hm_create(32);
    if (!p->zones) { snprintf(err, errlen, "oom"); free(p); return NULL; }

    for (int i = 0; i < p->cfg.nzones; i++) {
        zone_cfg_t *zc = &p->cfg.zones[i];
        rl_zone_t *z = rl_zone_create(zc->name, &zc->params);
        if (!z || hm_put(p->zones, zc->name, z) < 0) {
            snprintf(err, errlen, "oom creating zone %s", zc->name);
            return NULL;
        }
    }

    p->listen_fd = listen_tcp(p->cfg.listen_host, p->cfg.listen_port, 16384);
    if (p->listen_fd < 0) {
        snprintf(err, errlen, "listen %s:%d: %s",
                 p->cfg.listen_host, p->cfg.listen_port, strerror(errno));
        return NULL;
    }
    if (el_watch(el, p->listen_fd, EL_READ, listen_readable, p) < 0) {
        snprintf(err, errlen, "kqueue/epoll watch failed");
        return NULL;
    }
    schedule_maintenance(p);
    log_info("proxy listening on %s:%d -> %s:%d, %d zones",
             p->cfg.listen_host, p->cfg.listen_port,
             p->cfg.upstream_host, p->cfg.upstream_port, p->cfg.nzones);
    return p;
}

/* ---------- hot reload ---------- */

int proxy_reload(proxy_t *p, const char *config_path,
                 char *err, size_t errlen) {
    if (p->reloading) return 0;
    p->reloading = 1;

    config_t fresh;
    if (config_load(config_path, &fresh, err, errlen) < 0)
        goto fail;

    /* Reconcile zones by name. Existing key maps survive a parameter
     * change — token buckets keep refilling, window logs keep aging. */
    for (int i = 0; i < fresh.nzones; i++) {
        zone_cfg_t *zc = &fresh.zones[i];
        rl_zone_t *z = hm_get(p->zones, zc->name);
        if (z) {
            if (rl_zone_reconfigure(z, &zc->params) < 0) {
                snprintf(err, errlen, "oom reconfiguring zone %s", zc->name);
                goto fail;
            }
        } else {
            z = rl_zone_create(zc->name, &zc->params);
            if (!z || hm_put(p->zones, zc->name, z) < 0) {
                snprintf(err, errlen, "oom adding zone %s", zc->name);
                goto fail;
            }
            log_info("reload: zone %s added", zc->name);
        }
    }
    /* Drop zones absent from the new config. */
    for (size_t i = 0; i < p->zones->cap; i++) {
        if (!p->zones->slots[i].key) continue;
        const char *name = p->zones->slots[i].key;
        int found = 0;
        for (int j = 0; j < fresh.nzones; j++) {
            if (!strcmp(fresh.zones[j].name, name)) { found = 1; break; }
        }
        if (!found) {
            rl_zone_t *z = hm_remove(p->zones, name);
            log_info("reload: zone %s removed", name);
            rl_zone_destroy(z);
        }
    }

    int old_port = p->cfg.listen_port;
    p->cfg = fresh;
    if (fresh.listen_port != old_port) {
        /* Port change needs a new listener; the old one is closed only
         * after the new one binds so a bad reload never drops service. */
        int nfd = listen_tcp(fresh.listen_host, fresh.listen_port, 16384);
        if (nfd < 0) {
            snprintf(err, errlen, "new listener bind failed: %s", strerror(errno));
            goto fail;
        }
        if (el_watch(p->el, nfd, EL_READ, listen_readable, p) < 0) {
            close(nfd);
            snprintf(err, errlen, "new listener watch failed");
            goto fail;
        }
        el_unwatch(p->el, p->listen_fd);
        close(p->listen_fd);
        p->listen_fd = nfd;
        log_info("reload: listener moved to %s:%d",
                 fresh.listen_host, fresh.listen_port);
    }
    p->reloading = 0;
    return 0;

fail:
    p->reloading = 0;
    return -1;
}

void proxy_dump_stats(proxy_t *p) {
    log_info("stats conns=%llu active=%d requests=%llu denied=%llu shed=%llu",
             (unsigned long long)p->total_conns, p->nconns,
             (unsigned long long)p->total_requests,
             (unsigned long long)p->total_denied,
             (unsigned long long)p->total_shed);
    for (size_t i = 0; i < p->zones->cap; i++) {
        if (!p->zones->slots[i].key) continue;
        rl_zone_t *z = p->zones->slots[i].value;
        size_t keys; uint64_t allow, deny;
        rl_zone_stats(z, &keys, &allow, &deny);
        rl_params_t pp;
        rl_zone_get_params(z, &pp);
        log_info("  zone %-12s alg=%-12s keys=%-6zu allow=%llu deny=%llu",
                 rl_zone_name(z),
                 pp.alg == ALG_TOKEN_BUCKET ? "token_bucket" : "sliding_log",
                 keys,
                 (unsigned long long)allow,
                 (unsigned long long)deny);
    }
}

void proxy_destroy(proxy_t *p) {
    if (!p) return;
    for (size_t i = 0; i < p->zones->cap; i++) {
        if (p->zones->slots[i].key)
            rl_zone_destroy(p->zones->slots[i].value);
    }
    hm_destroy(p->zones);
    if (p->listen_fd >= 0) close(p->listen_fd);
    free(p);
}

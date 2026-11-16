#include "proxy.h"
#include "proxy_internal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

static char         g_config_path[1024];
static int64_t      g_config_mtime;
static char         g_pidfile[1024];

static void do_reload(proxy_t *p) {
    char err[512];
    if (proxy_reload(p, g_config_path, err, sizeof(err)) < 0)
        log_err("reload rejected, keeping old config: %s", err);
    else {
        g_config_mtime = config_mtime_ms(g_config_path);
        log_info("config reloaded from %s", g_config_path);
    }
}

static void on_sighup(event_loop_t *el, int sig, void *arg) {
    (void)el; (void)sig;
    log_info("SIGHUP received");
    do_reload(arg);
}

static void on_sigusr1(event_loop_t *el, int sig, void *arg) {
    (void)el; (void)sig;
    proxy_dump_stats(arg);
}

static event_loop_t *g_el;
static proxy_t      *g_px;

static void on_sigterm(event_loop_t *el, int sig, void *arg) {
    (void)sig; (void)arg;
    log_info("termination signal received, shutting down");
    if (g_pidfile[0]) unlink(g_pidfile);
    proxy_dump_stats(g_px);
    el_stop(el);
}

/* Once per second: notice a replaced config file even without SIGHUP.
 * mtime is monotonic enough for this purpose; an edit that rewrites
 * identical bytes still reloads, which is harmless and cheap. */
static void mtime_tick(event_loop_t *el, void *arg) {
    (void)el;
    proxy_t *p = arg;
    int64_t mt = config_mtime_ms(g_config_path);
    if (mt >= 0 && mt != g_config_mtime) {
        log_info("config file changed on disk");
        do_reload(p);
    }
    el_timer_add(p->el, 1000, mtime_tick, p);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s -f <config> [-p pidfile] [-v] [-h]\n"
        "  -f  config file (required)\n"
        "  -p  write pid to file\n"
        "  -v  verbose (debug logging, repeat for more)\n",
        prog);
}

int main(int argc, char **argv) {
    const char *config_path = NULL;
    const char *pidfile = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "f:p:vh")) != -1) {
        switch (opt) {
            case 'f': config_path = optarg; break;
            case 'p': pidfile = optarg; break;
            case 'v': log_set_level(2); break;
            case 'h': default: usage(argv[0]); return opt == 'h' ? 0 : 2;
        }
    }
    if (!config_path) { usage(argv[0]); return 2; }

    snprintf(g_config_path, sizeof(g_config_path), "%s", config_path);
    g_config_mtime = config_mtime_ms(config_path);
    if (g_config_mtime < 0) {
        fprintf(stderr, "cannot stat config %s: %s\n",
                config_path, strerror(errno));
        return 1;
    }
    if (pidfile) snprintf(g_pidfile, sizeof(g_pidfile), "%s", pidfile);

    /* Ignore SIGPIPE globally; writes to dead peers return EPIPE. */
    signal(SIGPIPE, SIG_IGN);

    event_loop_t *el = el_create();
    if (!el) { perror("event loop"); return 1; }

    char err[512];
    proxy_t *p = proxy_create(el, config_path, err, sizeof(err));
    if (!p) {
        fprintf(stderr, "startup failed: %s\n", err);
        el_destroy(el);
        return 1;
    }
    g_el = el;
    g_px = p;

    el_signal(el, SIGHUP, on_sighup, p);
    el_signal(el, SIGUSR1, on_sigusr1, p);
    el_signal(el, SIGINT, on_sigterm, p);
    el_signal(el, SIGTERM, on_sigterm, p);
    el_timer_add(el, 1000, mtime_tick, p);

    if (pidfile) {
        FILE *f = fopen(pidfile, "w");
        if (f) { fprintf(f, "%d\n", (int)getpid()); fclose(f); }
        else log_err("pidfile %s: %s", pidfile, strerror(errno));
    }

    el_run(el);

    proxy_destroy(p);
    el_destroy(el);
    if (g_pidfile[0]) unlink(g_pidfile);
    log_info("stopped");
    return 0;
}

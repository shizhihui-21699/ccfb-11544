#ifndef PROXY_H
#define PROXY_H

/* Runs the proxy: loads config, listens, serves until SIGTERM/SIGINT.
 * SIGHUP triggers a hot config reload (limits, upstream, listen address)
 * without dropping established connections. Returns exit code. */
int server_run(const char *conf_path);

#endif

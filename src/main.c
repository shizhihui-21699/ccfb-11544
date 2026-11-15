#include <stdio.h>
#include <string.h>

#include "proxy.h"

int main(int argc, char **argv)
{
    const char *conf = "conf/proxy.conf";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc) {
            conf = argv[++i];
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fprintf(stderr, "usage: rlproxy [-c config]\n");
            return 0;
        } else {
            fprintf(stderr, "usage: rlproxy [-c config]\n");
            return 1;
        }
    }
    return server_run(conf);
}

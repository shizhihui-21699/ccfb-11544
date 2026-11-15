CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11
CPPFLAGS += -Isrc

PROXY_SRCS  = src/main.c src/proxy.c src/evloop.c src/http.c src/limiter.c src/config.c
REPLAY_SRCS = tools/replay.c src/evloop.c src/http.c

all: rlproxy rlreplay

rlproxy: $(PROXY_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(PROXY_SRCS)

rlreplay: $(REPLAY_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(REPLAY_SRCS)

clean:
	rm -f rlproxy rlreplay

.PHONY: all clean

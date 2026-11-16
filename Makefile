CC      ?= cc
CSTD    ?= -std=c11
WARN     = -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
           -Wstrict-prototypes -Wmissing-prototypes -Wwrite-strings
OPT      = -O2 -g
CPPFLAGS = -Iinclude -D_GNU_SOURCE
CFLAGS  += $(CSTD) $(WARN) $(OPT) $(CPPFLAGS)
LDFLAGS +=
LDLIBS   = -lm

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
EV_SRC = src/event_loop_epoll.c
else
EV_SRC = src/event_loop_kqueue.c
endif

CORE_SRC = \
	src/util.c \
	src/sbuf.c \
	src/hashmap.c \
	src/event_loop.c \
	$(EV_SRC) \
	src/http.c \
	src/ratelimit.c \
	src/config.c \
	src/proxy.c \
	src/request.c \
	src/upstream.c

PROXY_OBJ = $(CORE_SRC:.c=.o) src/main.o
REPLAY_OBJ = \
	src/util.o src/sbuf.o src/hashmap.o src/event_loop.o $(EV_SRC:.c=.o) \
	src/http.o tools/replay.o
UPSTREAM_OBJ = \
	src/util.o src/sbuf.o src/hashmap.o src/event_loop.o $(EV_SRC:.c=.o) \
	src/http.o tools/upstream_echo.o

BIN = rlproxy replay upstream_echo

TEST_OBJ = src/ratelimit.o src/hashmap.o src/util.o tests/test_ratelimit.o

all: $(BIN)

test_unit: $(TEST_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	./test_unit

rlproxy: $(PROXY_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

replay: $(REPLAY_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

upstream_echo: $(UPSTREAM_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o tools/*.o tests/*.o $(BIN) test_unit

.PHONY: all clean test_unit

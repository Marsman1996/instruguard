
CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

COMM_HDR    = ../alloc-inl.h ../config.h ../debug.h ../types.h

all: ../afl-ig afl-as-ig

../afl-ig: afl-ig.c $(COMM_HDR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

afl-as-ig: afl-as-ig.c afl-as-ig.h $(COMM_HDR)
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)
	ln -sf afl-as-ig as

clean:
	rm -r ../afl-ig afl-as-ig as
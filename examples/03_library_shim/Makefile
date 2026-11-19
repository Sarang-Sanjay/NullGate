CC ?= clang-18
CFLAGS ?= -Wall -Wextra -Werror -fcf-protection=full -mshstk -I../../include
SHIM_LDFLAGS ?= -shared -fPIC -L../../build/src/libnullgate -Wl,--no-as-needed -lnullgate -lnullgate_shim -ldl -pthread -Wl,--as-needed -Wl,-rpath,../../build/src/libnullgate
LIB_LDFLAGS ?= -shared -fPIC
APP_LDFLAGS ?= -L. -lparser -Wl,-rpath,.

all: libparser.so libparser_shim.so app

libparser.so: parser.c
	$(CC) $(CFLAGS) -fPIC $(LIB_LDFLAGS) $< -o $@

libparser_shim.so: shim.c
	$(CC) $(CFLAGS) -fPIC $< -o $@ $(SHIM_LDFLAGS)

app: main.c libparser.so
	$(CC) $(CFLAGS) $< -o $@ $(APP_LDFLAGS)

run: all
	@echo "--- 1. Native Unconfined Run ---"
	./app
	@echo "--- 2. Transparent Sandboxed Run via LD_PRELOAD ---"
	LD_PRELOAD=./libparser_shim.so ./app

clean:
	rm -f libparser.so libparser_shim.so app

.PHONY: all run clean

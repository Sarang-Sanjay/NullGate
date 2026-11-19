CC ?= clang-18
CFLAGS ?= -O2 -Wall -Wextra -Werror -fcf-protection=full -mshstk -I../../include
LDFLAGS ?= -L../../build/src/libnullgate -lnullgate -pthread -Wl,-rpath,../../build/src/libnullgate

TARGET = zero_copy_ipc

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean

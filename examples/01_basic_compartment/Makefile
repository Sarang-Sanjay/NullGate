CC ?= clang-18
CFLAGS ?= -Wall -Wextra -Werror -fcf-protection=full -mshstk -I../../include
LDFLAGS ?= -L../../build/src/libnullgate -lnullgate -pthread -Wl,-rpath,../../build/src/libnullgate

TARGET = basic_compartment

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all run clean

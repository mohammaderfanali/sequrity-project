# confparse build.
#
# CFLAGS and LDFLAGS use '?=' so that the environment wins. dynAn drives the
# release and sanitized profiles purely through those variables, which is how
# one Makefile serves both builds without knowing dynAn exists.

CC ?= cc
CFLAGS ?= -O2 -g
LDFLAGS ?=

BIN := build/confparse
SRC := src/confparse.c

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC) | build
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

build:
	mkdir -p build

clean:
	rm -rf build

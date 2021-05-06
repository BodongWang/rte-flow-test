#SPDX-License-Identifier: BSD-3-Clause
#Copyright 2021 Nvidia

# binary name
APP = rte-flow-test
CC=gcc

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O0 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)

LDFLAGS = -lc -lstdc++ -lm -pthread -lev

# all source are stored in SRCS-y
SRCS-y := main.c

build/$(APP): $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_SHARED) $(LDFLAGS) 

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP)

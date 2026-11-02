CC ?= gcc
AR ?= ar
ARFLAGS = rcs

CFLAGS ?= -Wall -Wextra -pthread -O2 -std=gnu11 -Iinclude
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    DYLIB_EXT = dylib
    SHARED_FLAGS = -dynamiclib -install_name @rpath/libadvnet.$(DYLIB_EXT)
else
    DYLIB_EXT = so
    SHARED_FLAGS = -shared -fPIC -Wl,-soname,libadvnet.$(DYLIB_EXT)
endif

SRC_DIR = src
BUILD_DIR = build
LIB_DIR = lib
ROOT_LIB_DIR = ../../lib

SRCS = $(SRC_DIR)/net_core.c \
       $(SRC_DIR)/net_io.c \
       $(SRC_DIR)/net_proxy_proto.c

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

STATIC_LIB = $(LIB_DIR)/libadvnet.a
SHARED_LIB = $(LIB_DIR)/libadvnet.$(DYLIB_EXT)

all: directories static shared export

directories:
	@mkdir -p $(BUILD_DIR) $(LIB_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

static: directories $(STATIC_LIB)
$(STATIC_LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

shared dynamic: directories $(SHARED_LIB)
$(SHARED_LIB): $(OBJS)
	$(CC) $(SHARED_FLAGS) $(OBJS) -o $@

export: static shared
	@if [ -d "$(ROOT_LIB_DIR)" ]; then \
		cp -f $(STATIC_LIB) $(ROOT_LIB_DIR)/; \
		cp -f $(SHARED_LIB) $(ROOT_LIB_DIR)/; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)

.PHONY: all directories static shared dynamic export clean


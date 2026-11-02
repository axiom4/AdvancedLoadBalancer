CC ?= gcc
AR ?= ar
ARFLAGS = rcs

CFLAGS ?= -Wall -Wextra -pthread -O2 -std=gnu11
override CFLAGS += -Iinclude -I../libadvnet/include
UNAME_S := $(shell uname -s)

NET_LIB_DIR ?= ../libadvnet/lib
ROOT_LIB_DIR = ../../lib

ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@4 2>/dev/null || echo /opt/homebrew/opt/openssl)
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        override CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDLIBS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lncurses
    else
        LDLIBS = -lncurses
    endif
    DYLIB_EXT = dylib
    SHARED_FLAGS = -dynamiclib -install_name @rpath/libadvlb.$(DYLIB_EXT)
    RPATH_FLAGS = -Wl,-rpath,@loader_path -Wl,-rpath,@loader_path/../libadvnet/lib
else
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        LDLIBS = -lssl -lcrypto -lncurses
    else
        LDLIBS = -lncurses
    endif
    DYLIB_EXT = so
    SHARED_FLAGS = -shared -fPIC -Wl,-soname,libadvlb.$(DYLIB_EXT)
    RPATH_FLAGS = -Wl,-rpath,'$$ORIGIN' -Wl,-rpath,'$$ORIGIN/../libadvnet/lib'
endif

SRC_DIR = src
BUILD_DIR = build
LIB_DIR = lib

SRCS = $(SRC_DIR)/config.c \
       $(SRC_DIR)/utils.c \
       $(SRC_DIR)/log.c \
       $(SRC_DIR)/net_utils.c \
       $(SRC_DIR)/proxy_proto.c \
       $(SRC_DIR)/ssl_engine.c \
       $(SRC_DIR)/balancer.c \
       $(SRC_DIR)/health_check.c \
       $(SRC_DIR)/conn_pool.c \
       $(SRC_DIR)/session_table.c \
       $(SRC_DIR)/cluster.c \
       $(SRC_DIR)/proxy.c \
       $(SRC_DIR)/udp_proxy.c \
       $(SRC_DIR)/tui.c \
       $(SRC_DIR)/cli.c

OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

STATIC_LIB = $(LIB_DIR)/libadvlb.a
SHARED_LIB = $(LIB_DIR)/libadvlb.$(DYLIB_EXT)

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
	$(CC) $(SHARED_FLAGS) $(OBJS) -L$(NET_LIB_DIR) -ladvnet $(RPATH_FLAGS) -o $@ $(LDFLAGS) $(LDLIBS)

export: static shared
	@if [ -d "$(ROOT_LIB_DIR)" ]; then \
		cp -f $(STATIC_LIB) $(ROOT_LIB_DIR)/; \
		cp -f $(SHARED_LIB) $(ROOT_LIB_DIR)/; \
	fi

clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)

.PHONY: all directories static shared dynamic export clean

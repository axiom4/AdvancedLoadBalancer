CC ?= gcc

CFLAGS ?= -Wall -Wextra -pthread -O2 -std=gnu11
override CFLAGS += -I../include -I../libs/libadvlb/include -I../libs/libadvnet/include
UNAME_S := $(shell uname -s)

NET_LIB_DIR ?= ../libs/libadvnet/lib
LB_LIB_DIR  ?= ../libs/libadvlb/lib
BIN_DIR     ?= ..

ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@4 2>/dev/null || echo /opt/homebrew/opt/openssl)
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        override CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDLIBS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lncurses
    else
        LDLIBS = -lncurses
    endif
    RPATH_BIN = -Wl,-rpath,@executable_path/lib -Wl,-rpath,@loader_path/lib -Wl,-rpath,@executable_path/libs/libadvlb/lib -Wl,-rpath,@executable_path/libs/libadvnet/lib
else
    NCURSES_LIB ?= $(shell pkg-config --libs ncursesw 2>/dev/null || echo "-lncursesw")
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        LDLIBS = -lssl -lcrypto $(NCURSES_LIB)
    else
        LDLIBS = $(NCURSES_LIB)
    endif
    RPATH_BIN = -Wl,-rpath,'$$ORIGIN/lib' -Wl,-rpath,'$$ORIGIN/libs/libadvlb/lib' -Wl,-rpath,'$$ORIGIN/libs/libadvnet/lib'
endif

SRC = main.c
OBJ = main.o
TARGET = $(BIN_DIR)/advanced_load_balancer

all: static

static: $(TARGET)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Default static link target
$(TARGET): $(OBJ) $(LB_LIB_DIR)/libadvlb.a $(NET_LIB_DIR)/libadvnet.a
	$(CC) $(CFLAGS) $(OBJ) $(LB_LIB_DIR)/libadvlb.a $(NET_LIB_DIR)/libadvnet.a -o $(TARGET) $(LDFLAGS) $(LDLIBS)

# Dynamic link target
dynamic: $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -L$(LB_LIB_DIR) -L$(NET_LIB_DIR) -ladvlb -ladvnet $(RPATH_BIN) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all static dynamic clean

CC ?= gcc

CFLAGS ?= -Wall -Wextra -pthread -O2 -std=gnu11
override CFLAGS += -I../include -I../libs/libadvlb/include -I../libs/libadvnet/include -MMD -MP
UNAME_S := $(shell uname -s)

NET_LIB_DIR ?= ../libs/libadvnet/lib
LB_LIB_DIR  ?= ../libs/libadvlb/lib
BIN_DIR     ?= ..

ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@4 2>/dev/null || echo /opt/homebrew/opt/openssl)
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        override CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDLIBS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lncurses -lm
    else
        LDLIBS = -lncurses -lm
    endif
else
    NCURSES_LIB ?= $(shell pkg-config --libs ncursesw 2>/dev/null || echo "-lncursesw")
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        LDLIBS = -lssl -lcrypto $(NCURSES_LIB) -lm
    else
        LDLIBS = $(NCURSES_LIB) -lm
    endif
endif

SRC = test_suite.c
OBJ = test_suite.o
TARGET = $(BIN_DIR)/test_suite

all: $(TARGET)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) $(LB_LIB_DIR)/libadvlb.a $(NET_LIB_DIR)/libadvnet.a
	$(CC) $(CFLAGS) $(OBJ) $(LB_LIB_DIR)/libadvlb.a $(NET_LIB_DIR)/libadvnet.a -o $(TARGET) $(LDFLAGS) $(LDLIBS)

run: $(TARGET)
	@$(TARGET)

clean:
	rm -f $(OBJ) $(OBJ:.o=.d) $(TARGET)

-include $(OBJ:.o=.d)

.PHONY: all run clean

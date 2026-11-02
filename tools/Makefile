CC ?= gcc

CFLAGS ?= -Wall -Wextra -pthread -O2 -std=gnu11
UNAME_S := $(shell uname -s)
BIN_DIR ?= ..

ifeq ($(UNAME_S),Darwin)
    OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || brew --prefix openssl@3 2>/dev/null || brew --prefix openssl@4 2>/dev/null || echo /opt/homebrew/opt/openssl)
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDLIBS = -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lm
    else
        LDLIBS = -lm
    endif
else
    ifneq ($(findstring -DNO_SSL,$(CFLAGS)),-DNO_SSL)
        LDLIBS = -lssl -lcrypto -lm
    else
        LDLIBS = -lm
    endif
endif

SRC = test_client.c
OBJ = test_client.o
TARGET = $(BIN_DIR)/test_client

all: $(TARGET)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean


# ============================================================================
# MASTER MAKEFILE - Advanced Load Balancer Modular Architecture
# ============================================================================

MAKE ?= make
ROOT_DIR := $(shell pwd)
LIB_DIR = $(ROOT_DIR)/lib
LIBS_NET_DIR = $(ROOT_DIR)/libs/libadvnet
LIBS_LB_DIR  = $(ROOT_DIR)/libs/libadvlb
APP_DIR      = $(ROOT_DIR)/app

TARGET = advanced_load_balancer

# Default: build all libraries (static/shared) and the main application
all: directories net-lib lb-lib app-target

directories:
	@mkdir -p $(LIB_DIR)

# Standalone build of network library (libadvnet)
net net-lib: directories
	@$(MAKE) -C $(LIBS_NET_DIR) ROOT_LIB_DIR=$(LIB_DIR) all

# Standalone build of load balancer library (libadvlb)
lb lb-lib: directories net-lib
	@$(MAKE) -C $(LIBS_LB_DIR) ROOT_LIB_DIR=$(LIB_DIR) NET_LIB_DIR=$(LIBS_NET_DIR)/lib all

# Build of the main application
app app-target: lb-lib
	@$(MAKE) -C $(APP_DIR) static

# Dynamically linked binary with libadvlb and libadvnet
dynamic dynamic-bin: directories net-lib lb-lib
	@$(MAKE) -C $(APP_DIR) dynamic

# NO_SSL build (pure Layer 4 without cryptographic dependencies)
nossl: clean directories
	@$(MAKE) -C $(LIBS_NET_DIR) ROOT_LIB_DIR=$(LIB_DIR) CFLAGS="-Wall -Wextra -pthread -O2 -std=gnu11 -Iinclude -DNO_SSL" all
	@$(MAKE) -C $(LIBS_LB_DIR) ROOT_LIB_DIR=$(LIB_DIR) NET_LIB_DIR=$(LIBS_NET_DIR)/lib CFLAGS="-Wall -Wextra -pthread -O2 -std=gnu11 -Iinclude -I../libadvnet/include -DNO_SSL" all
	@$(MAKE) -C $(APP_DIR) CFLAGS="-Wall -Wextra -pthread -O2 -std=gnu11 -I../include -I../libs/libadvlb/include -I../libs/libadvnet/include -DNO_SSL" static

# Debug build with AddressSanitizer and UndefinedBehaviorSanitizer
debug: clean directories
	@$(MAKE) -C $(LIBS_NET_DIR) ROOT_LIB_DIR=$(LIB_DIR) CFLAGS="-Wall -Wextra -pthread -g -O0 -std=gnu11 -Iinclude -fsanitize=address,undefined" all
	@$(MAKE) -C $(LIBS_LB_DIR) ROOT_LIB_DIR=$(LIB_DIR) NET_LIB_DIR=$(LIBS_NET_DIR)/lib CFLAGS="-Wall -Wextra -pthread -g -O0 -std=gnu11 -Iinclude -I../libadvnet/include -fsanitize=address,undefined" all
	@$(MAKE) -C $(APP_DIR) CFLAGS="-Wall -Wextra -pthread -g -O0 -std=gnu11 -I../include -I../libs/libadvlb/include -I../libs/libadvnet/include -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" static

# Clean all modules
clean:
	@$(MAKE) -C $(LIBS_NET_DIR) clean || true
	@$(MAKE) -C $(LIBS_LB_DIR) clean || true
	@$(MAKE) -C $(APP_DIR) clean || true
	rm -rf $(LIB_DIR) build $(TARGET)

.PHONY: all directories net net-lib lb lb-lib app app-target dynamic dynamic-bin nossl debug clean

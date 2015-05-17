#
# (C) Copyright 2000-2015
# Ken <ken.i18n@gmail.com>
#

MAJOR = 0
MINOR = 1
PATCH = 6
NAME = xsocks

ifdef O
ifeq ("$(origin O)", "command line")
BUILD_DIR := $(O)
endif
endif

ifneq ($(BUILD_DIR),)
saved-output := $(BUILD_DIR)

# Attempt to create a output directory.
$(shell [ -d ${BUILD_DIR} ] || mkdir -p ${BUILD_DIR})

# Verify if it was successful.
BUILD_DIR := $(shell cd $(BUILD_DIR) && /bin/pwd)
$(if $(BUILD_DIR),,$(error output directory "$(saved-output)" does not exist))
endif # ifneq ($(BUILD_DIR),)

INSTALL_DIR := /usr/local/bin

OBJTREE		:= $(if $(BUILD_DIR),$(BUILD_DIR),$(CURDIR))
SRCTREE		:= $(CURDIR)
export SRCTREE OBJTREE

#########################################################################

ifdef CROSS
CROSS_COMPILE = $(CROSS)
endif

ifdef CROSS_COMPILE
CPPFLAGS = -DCROSS_COMPILE
HOST = $(patsubst %-,%,$(CROSS_COMPILE))
endif

CFLAGS = \
	-Os	\
	-std=gnu99 \
	-Wall \
	$(PLATFORM_CFLAGS)

CFLAGS += -fomit-frame-pointer -fdata-sections -ffunction-sections
ifneq (,$(findstring android,$(CROSS_COMPILE)))
CFLAGS += -pie -fPIE
endif
EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/libsodium/src/libsodium/include -I3rd/c-ares/

LDFLAGS = -Wl,--gc-sections
ifneq (,$(findstring android,$(CROSS_COMPILE)))
LDFLAGS += -pie -fPIE
else
LDFLAGS += -lrt
endif
LDFLAGS += -pthread -ldl
LDFLAGS += 3rd/libuv/.libs/libuv.a 3rd/libsodium/src/libsodium/.libs/libsodium.a

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

ifndef CROSS_COMPILE
all: libuv libsodium c-ares xsocksd xsocks xtproxy xforwarder xtunnel
else
all: libuv libsodium xsocks xtproxy xforwarder xtunnel
endif

3rd/libuv/autogen.sh:
	$(Q)git submodule update --init

3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	$(Q)cd 3rd/libuv && ./autogen.sh && ./configure --host=$(HOST) LDFLAGS= && $(MAKE)

libuv: 3rd/libuv/Makefile

3rd/libsodium/autogen.sh:
	$(Q)git submodule update --init

3rd/libsodium/Makefile: | 3rd/libsodium/autogen.sh
	$(Q)cd 3rd/libsodium && ./autogen.sh && ./configure --host=$(HOST) LDFLAGS= && $(MAKE)

libsodium: 3rd/libsodium/Makefile

3rd/c-ares/configure:
	$(Q)git submodule update --init

3rd/c-ares/Makefile: | 3rd/c-ares/configure
	$(Q)cd 3rd/c-ares && ./buildconf && ./configure --host=$(HOST) LDFLAGS= && $(MAKE) MAKEFLAGS=-rRs

c-ares: 3rd/c-ares/Makefile

xsocksd: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/resolver.o \
	src/daemon.o \
	src/signal.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xsocksd_udprelay.o \
	src/xsocksd_client.o \
	src/xsocksd_remote.o \
	src/xsocksd.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS) 3rd/c-ares/.libs/libcares.a

xsocks: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/daemon.o \
	src/signal.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xsocks_udprelay.o \
	src/xsocks_client.o \
	src/xsocks_remote.o \
	src/xsocks.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

xtproxy: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/cache.o \
	src/daemon.o \
	src/signal.o \
	src/consumer.o \
	src/xtproxy_udprelay.o \
	src/xtproxy_client.o \
	src/xtproxy_remote.o \
	src/xtproxy.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

xforwarder: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/daemon.o \
	src/signal.o \
	src/consumer.o \
	src/cache.o \
	src/xforwarder_udprelay.o \
	src/xforwarder_client.o \
	src/xforwarder_remote.o \
	src/xforwarder.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

xtunnel: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/daemon.o \
	src/signal.o \
	src/consumer.o \
	src/xtunnel_source.o \
	src/xtunnel_target.o \
	src/xtunnel.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)

clean:
	@find $(OBJTREE)/src -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f xsocksd xsocks xtproxy xforwarder xtunnel

distclean: clean
	$(Q)cd 3rd/libsodium && make distclean
	$(Q)cd 3rd/libuv && make distclean
	$(Q)cd 3rd/c-ares && make distclean

ifndef CROSS_COMPILE
install:
	$(Q)$(STRIP) --strip-unneeded xsocksd && cp xsocksd $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded xsocks && cp xsocks $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded xtproxy && cp xtproxy $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded xforwarder && cp xforwarder $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded xtunnel && cp xtunnel $(INSTALL_DIR)
else
install:
endif

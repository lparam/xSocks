MAJOR = 0
MINOR = 3
PATCH = 1
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

OBJTREE	:= $(if $(BUILD_DIR),$(BUILD_DIR),$(CURDIR))
SRCTREE	:= $(CURDIR)
export SRCTREE OBJTREE

#########################################################################

ifdef HOST
CROSS_COMPILE = $(HOST)-
endif

# for OpenWrt
ifdef CROSS
CROSS_COMPILE = $(CROSS)
HOST = $(patsubst %-,%,$(CROSS_COMPILE))
ifneq (,$(findstring openwrt,$(CROSS_COMPILE)))
OPENWRT = 1
endif
endif

ifdef CROSS_COMPILE
CPPFLAGS = -DCROSS_COMPILE
endif

CFLAGS = \
	-Os	\
	-g \
	-std=gnu99 \
	-Wall \
	$(PLATFORM_CFLAGS)

CFLAGS += -fomit-frame-pointer -fdata-sections -ffunction-sections

ifneq (,$(findstring android,$(CROSS_COMPILE)))
CFLAGS += -pie -fPIE
ANDROID = 1
endif

ifneq (,$(findstring mingw32,$(CROSS_COMPILE)))
MINGW32 = 1
endif

EXTRA_CFLAGS =

#########################################################################

CPPFLAGS += -Isrc -I3rd/libuv/include
CPPFLAGS += -I3rd/libsodium/src/libsodium/include
ifneq ($(OBJTREE),$(SRCTREE))
CPPFLAGS += -I3rd/libsodium/src/libsodium/include/sodium
CPPFLAGS += -I$(OBJTREE)/3rd/libsodium/src/libsodium/include
endif
CPPFLAGS += -I3rd/c-ares -I3rd/libcork/include -I3rd/libipset/include

LDFLAGS = -Wl,--gc-sections

ifdef ANDROID
LDFLAGS += -pie -fPIE
else
	ifndef MINGW32
		LIBS += -lrt
	endif
endif

LIBCORK = $(OBJTREE)/3rd/libcork/libcork.a
LIBIPSET = $(OBJTREE)/3rd/libipset/libipset.a
LIBS += $(OBJTREE)/3rd/libuv/.libs/libuv.a $(OBJTREE)/3rd/libsodium/src/libsodium/.libs/libsodium.a

ifdef MINGW32
LIBS += -lws2_32 -lpsapi -liphlpapi -luserenv
else
LIBS += -pthread -ldl
endif

LDFLAGS += $(LIBS)

XSOCKSD=$(OBJTREE)/xsocksd
XSOCKS=$(OBJTREE)/xsocks
XTPROXY=$(OBJTREE)/xtproxy
XFORWARDER=$(OBJTREE)/xforwarder
XTUNNEL=$(OBJTREE)/xtunnel

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

ifdef OPENWRT
all: libuv libsodium xsocks xtproxy xforwarder xtunnel
else
all: libuv libsodium c-ares $(XSOCKSD) $(XSOCKS) $(XTPROXY) $(XFORWARDER) $(XTUNNEL)
endif

android: libuv libsodium $(XSOCKS) $(XFORWARDER)
mingw32: libuv libsodium c-ares xsocksd.exe xsocks.exe xforwarder.exe xtunnel.exe

3rd/libuv/autogen.sh:
	$(Q)git submodule update --init

$(OBJTREE)/3rd/libuv/Makefile: | 3rd/libuv/autogen.sh
	$(Q)mkdir -p $(OBJTREE)/3rd/libuv
	$(Q)cd 3rd/libuv && ./autogen.sh
	$(Q)cd $(OBJTREE)/3rd/libuv && $(SRCTREE)/3rd/libuv/configure --host=$(HOST) LDFLAGS= && $(MAKE)

libuv: $(OBJTREE)/3rd/libuv/Makefile

3rd/libsodium/autogen.sh:
	$(Q)git submodule update --init

$(OBJTREE)/3rd/libsodium/Makefile: | 3rd/libsodium/autogen.sh
	$(Q)mkdir -p $(OBJTREE)/3rd/libsodium
	$(Q)cd 3rd/libsodium && ./autogen.sh
	$(Q)cd $(OBJTREE)/3rd/libsodium && $(SRCTREE)/3rd/libsodium/configure --host=$(HOST) LDFLAGS= && $(MAKE)

libsodium: $(OBJTREE)/3rd/libsodium/Makefile

$(OBJTREE)/3rd/c-ares/configure:
	$(Q)git submodule update --init

$(OBJTREE)/3rd/c-ares/Makefile: | $(OBJTREE)/3rd/c-ares/configure
	$(Q)mkdir -p $(OBJTREE)/3rd/c-ares
	$(Q)cd 3rd/c-ares && ./buildconf
	$(Q)cd $(OBJTREE)/3rd/c-ares && $(SRCTREE)/3rd/c-ares/configure --host=$(HOST) --enable-static --disable-shared LDFLAGS= && $(MAKE) MAKEFLAGS=-rRs

c-ares: $(OBJTREE)/3rd/c-ares/Makefile

$(LIBCORK): \
	$(OBJTREE)/3rd/libcork/src/core/allocator.o \
	$(OBJTREE)/3rd/libcork/src/core/error.o \
	$(OBJTREE)/3rd/libcork/src/core/ip-address.o \
	$(OBJTREE)/3rd/libcork/src/ds/array.o \
	$(OBJTREE)/3rd/libcork/src/ds/hash-table.o \
	$(OBJTREE)/3rd/libcork/src/ds/buffer.o \
	$(OBJTREE)/3rd/libcork/src/ds/dllist.o \
	$(OBJTREE)/3rd/libcork/src/posix/process.o
	$(BUILD_AR) rcu $@ $^
	$(BUILD_RANLIB) $@

$(LIBIPSET): \
	$(OBJTREE)/3rd/libipset/src/bdd/bdd-iterator.o \
	$(OBJTREE)/3rd/libipset/src/bdd/read.o \
	$(OBJTREE)/3rd/libipset/src/bdd/assignments.o \
	$(OBJTREE)/3rd/libipset/src/bdd/write.o \
	$(OBJTREE)/3rd/libipset/src/bdd/basics.o \
	$(OBJTREE)/3rd/libipset/src/bdd/reachable.o \
	$(OBJTREE)/3rd/libipset/src/bdd/expanded.o \
	$(OBJTREE)/3rd/libipset/src/general.o \
	$(OBJTREE)/3rd/libipset/src/map/inspection.o \
	$(OBJTREE)/3rd/libipset/src/map/storage.o \
	$(OBJTREE)/3rd/libipset/src/map/allocation.o \
	$(OBJTREE)/3rd/libipset/src/map/ipv6_map.o \
	$(OBJTREE)/3rd/libipset/src/map/ipv4_map.o \
	$(OBJTREE)/3rd/libipset/src/set/ipv4_set.o \
	$(OBJTREE)/3rd/libipset/src/set/inspection.o \
	$(OBJTREE)/3rd/libipset/src/set/iterator.o \
	$(OBJTREE)/3rd/libipset/src/set/storage.o \
	$(OBJTREE)/3rd/libipset/src/set/ipv6_set.o \
	$(OBJTREE)/3rd/libipset/src/set/allocation.o
	$(BUILD_AR) rcu $@ $^
	$(BUILD_RANLIB) $@

lib3rd: $(LIBCORK) $(LIBIPSET)

ifndef MINGW32
$(XSOCKSD): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/common.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/resolver.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/consumer.o \
	$(OBJTREE)/src/cache.o \
	$(OBJTREE)/src/packet.o \
	$(OBJTREE)/src/xsocksd_udprelay.o \
	$(OBJTREE)/src/xsocksd_client.o \
	$(OBJTREE)/src/xsocksd_remote.o \
	$(OBJTREE)/src/xsocksd.o
	$(LINK) $^ -o $@ $(LDFLAGS) $(OBJTREE)/3rd/c-ares/.libs/libcares.a
else
xsocksd.exe: \
	src/util.o \
	src/logger.o \
	src/common.o \
	src/crypto.o \
	src/resolver.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xsocksd_udprelay.o \
	src/xsocksd_client.o \
	src/xsocksd_remote.o \
	src/xsocksd.o
	$(LINK) $^ -o $@ 3rd/c-ares/.libs/libcares.a $(LDFLAGS)
endif

ifndef MINGW32
$(XSOCKS): \
	$(OBJTREE)/src/acl.o \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/common.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/consumer.o \
	$(OBJTREE)/src/cache.o \
	$(OBJTREE)/src/packet.o \
	$(OBJTREE)/src/xsocks_udprelay.o \
	$(OBJTREE)/src/xsocks_client.o \
	$(OBJTREE)/src/xsocks_remote.o \
	$(OBJTREE)/src/xsocks.o \
	| lib3rd
	$(LINK) $^ -o $@ $(LDFLAGS) $(LIBIPSET) $(LIBCORK)
else
xsocks.exe: \
	src/util.o \
	src/logger.o \
	src/common.o \
	src/crypto.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xsocks_udprelay.o \
	src/xsocks_client.o \
	src/xsocks_remote.o \
	src/xsocks.o
	$(LINK) $^ -o $@ $(LDFLAGS)
endif

$(XTPROXY): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/packet.o \
	$(OBJTREE)/src/cache.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/consumer.o \
	$(OBJTREE)/src/xtproxy_udprelay.o \
	$(OBJTREE)/src/xtproxy_client.o \
	$(OBJTREE)/src/xtproxy_remote.o \
	$(OBJTREE)/src/xtproxy.o
	$(LINK) $^ -o $@ $(LDFLAGS)

ifndef MINGW32
$(XFORWARDER): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/packet.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/consumer.o \
	$(OBJTREE)/src/cache.o \
	$(OBJTREE)/src/xforwarder_udprelay.o \
	$(OBJTREE)/src/xforwarder_client.o \
	$(OBJTREE)/src/xforwarder_remote.o \
	$(OBJTREE)/src/xforwarder.o
	$(LINK) $^ -o $@ $(LDFLAGS)
else
xforwarder.exe: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/consumer.o \
	src/cache.o \
	src/xforwarder_udprelay.o \
	src/xforwarder_client.o \
	src/xforwarder_remote.o \
	src/xforwarder.o
	$(LINK) $^ -o $@ $(LDFLAGS)
endif

ifndef MINGW32
$(XTUNNEL): \
	$(OBJTREE)/src/util.o \
	$(OBJTREE)/src/logger.o \
	$(OBJTREE)/src/crypto.o \
	$(OBJTREE)/src/packet.o \
	$(OBJTREE)/src/daemon.o \
	$(OBJTREE)/src/signal.o \
	$(OBJTREE)/src/consumer.o \
	$(OBJTREE)/src/xtunnel_source.o \
	$(OBJTREE)/src/xtunnel_target.o \
	$(OBJTREE)/src/xtunnel.o
	$(LINK) $^ -o $@ $(LDFLAGS)
else
xtunnel.exe: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/consumer.o \
	src/xtunnel_source.o \
	src/xtunnel_target.o \
	src/xtunnel.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)
endif

clean:
	@find src $(OBJTREE)/src $(OBJTREE)/3rd/libcork $(OBJTREE)/3rd/libipset -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f $(XSOCKSD) $(XSOCKS) $(XTPROXY) $(XFORWARDER) $(XTUNNEL)

distclean: clean
ifeq ($(OBJTREE)/3rd/libsodium/Makefile, $(wildcard $(OBJTREE)/3rd/libsodium/Makefile))
	$(Q)cd $(OBJTREE)/3rd/libsodium && make distclean
endif
ifeq ($(OBJTREE)/3rd/libuv/Makefile, $(wildcard $(OBJTREE)/3rd/libuv/Makefile))
	$(Q)cd $(OBJTREE)/3rd/libuv && make distclean
endif
ifeq ($(OBJTREE)/3rd/c-ares/Makefile, $(wildcard $(OBJTREE)/3rd/c-ares/Makefile))
	$(Q)cd $(OBJTREE)/3rd/c-ares && make distclean
endif

ifndef CROSS_COMPILE
install:
	$(Q)$(STRIP) --strip-unneeded $(XSOCKSD) && cp $(XSOCKSD) $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded $(XSOCKS) && cp $(XSOCKS) $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded $(XTPROXY) && cp $(XTPROXY) $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded $(XFORWARDER) && cp $(XFORWARDER) $(INSTALL_DIR)
	$(Q)$(STRIP) --strip-unneeded $(XTUNNEL) && cp $(XTUNNEL) $(INSTALL_DIR)
else
install:
endif

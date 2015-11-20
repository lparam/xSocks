MAJOR = 0
MINOR = 4
PATCH = 3
NAME = xSocks

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
endif

ifneq (,$(findstring openwrt,$(CROSS_COMPILE)))
OPENWRT = 1
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
CPPFLAGS += -DANDROID
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
CPPFLAGS += -I3rd/c-ares
CPPFLAGS += -I3rd/libcork/include -I3rd/libipset/include

ifdef ANDROID
	CPPFLAGS += -I3rd/libancillary
endif

LDFLAGS = -Wl,--gc-sections

ifdef ANDROID
LDFLAGS += -pie -fPIE
LIBS += -llog
else
	ifndef MINGW32
		LIBS += -lrt
	endif
endif

LIBCORK = $(OBJTREE)/3rd/libcork/libcork.a
LIBIPSET = $(OBJTREE)/3rd/libipset/libipset.a
LIBANCILLARY = $(OBJTREE)/3rd/libancillary/libancillary.a
LIBS += $(OBJTREE)/3rd/libuv/.libs/libuv.a $(OBJTREE)/3rd/libsodium/src/libsodium/.libs/libsodium.a

ifdef MINGW32
LIBS += -lws2_32 -lpsapi -liphlpapi -luserenv
else
LIBS += -pthread -ldl
endif

LDFLAGS += $(LIBS)

XSOCKSD=$(OBJTREE)/xSocksd
XSOCKS=$(OBJTREE)/xSocks
XTPROXY=$(OBJTREE)/xTproxy
XFORWARDER=$(OBJTREE)/xForwarder
XTUNNEL=$(OBJTREE)/xTunnel

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

ifdef OPENWRT
all: libuv libsodium $(XSOCKS) $(XTPROXY) $(XFORWARDER) $(XTUNNEL)
else
all: libuv libsodium c-ares $(XSOCKSD) $(XSOCKS) $(XTPROXY) $(XFORWARDER) $(XTUNNEL)
endif

android: libuv libsodium $(XSOCKS) $(XFORWARDER)
mingw32: libuv libsodium c-ares $(XSOCKS).exe $(XTPROXY).exe $(XFORWARDER).exe $(XTUNNEL).exe

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

$(LIBANCILLARY): \
	$(OBJTREE)/3rd/libancillary/fd_recv.o \
	$(OBJTREE)/3rd/libancillary/fd_send.o
	$(BUILD_AR) rcu $@ $^
	$(BUILD_RANLIB) $@

ifdef ANDROID
LIB3RD = $(LIBIPSET) $(LIBCORK) $(LIBANCILLARY)
lib3rd: $(LIBCORK) $(LIBIPSET) $(LIBANCILLARY)
else
LIB3RD = $(LIBIPSET) $(LIBCORK)
lib3rd: $(LIBCORK) $(LIBIPSET)
endif

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
	$(OBJTREE)/src/xSocksd_udprelay.o \
	$(OBJTREE)/src/xSocksd_client.o \
	$(OBJTREE)/src/xSocksd_remote.o \
	$(OBJTREE)/src/xSocksd.o
	$(LINK) $^ -o $@ $(LDFLAGS) $(OBJTREE)/3rd/c-ares/.libs/libcares.a
else
$(XSOCKSD).exe: \
	src/util.o \
	src/logger.o \
	src/common.o \
	src/crypto.o \
	src/resolver.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xSocksd_udprelay.o \
	src/xSocksd_client.o \
	src/xSocksd_remote.o \
	src/xSocksd.o
	$(LINK) $^ -o $@ 3rd/c-ares/.libs/libcares.a $(LDFLAGS)
endif

XSOCKS_OBJS = \
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
	$(OBJTREE)/src/xSocks_udprelay.o \
	$(OBJTREE)/src/xSocks_client.o \
	$(OBJTREE)/src/xSocks_remote.o \
	$(OBJTREE)/src/xSocks.o

ifdef ANDROID
	XSOCKS_OBJS += $(OBJTREE)/src/android.o
endif

ifndef MINGW32
$(XSOCKS): \
	$(XSOCKS_OBJS) \
	| lib3rd
	$(LINK) $^ -o $@ $(LDFLAGS) $(LIB3RD)
else
$(XSOCKS).exe: \
	src/util.o \
	src/logger.o \
	src/common.o \
	src/crypto.o \
	src/consumer.o \
	src/cache.o \
	src/packet.o \
	src/xSocks_udprelay.o \
	src/xSocks_client.o \
	src/xSocks_remote.o \
	src/xSocks.o
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
	$(OBJTREE)/src/xTproxy_udprelay.o \
	$(OBJTREE)/src/xTproxy_client.o \
	$(OBJTREE)/src/xTproxy_remote.o \
	$(OBJTREE)/src/xTproxy.o
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
	$(OBJTREE)/src/xForwarder_udprelay.o \
	$(OBJTREE)/src/xForwarder_client.o \
	$(OBJTREE)/src/xForwarder_remote.o \
	$(OBJTREE)/src/xForwarder.o
	$(LINK) $^ -o $@ $(LDFLAGS)
else
$(XFORWARDER).exe: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/consumer.o \
	src/cache.o \
	src/xForwarder_udprelay.o \
	src/xForwarder_client.o \
	src/xForwarder_remote.o \
	src/xForwarder.o
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
	$(OBJTREE)/src/xTunnel_source.o \
	$(OBJTREE)/src/xTunnel_target.o \
	$(OBJTREE)/src/xTunnel.o
	$(LINK) $^ -o $@ $(LDFLAGS)
else
$(XTUNNEL).exe: \
	src/util.o \
	src/logger.o \
	src/crypto.o \
	src/packet.o \
	src/consumer.o \
	src/xTunnel_source.o \
	src/xTunnel_target.o \
	src/xTunnel.o
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)
endif

clean:
	@find $(OBJTREE)/src -type f \
	\( -name '*.o' -o -name '*~' \
	-o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f $(XSOCKSD) $(XSOCKS) $(XTPROXY) $(XFORWARDER) $(XTUNNEL)

distclean: clean
	@find $(OBJTREE)/3rd/libcork $(OBJTREE)/3rd/libipset -type f \
	\( -name '*.o' -o -name '*~' \
	-o -name '*.tmp' \) -print \
	| xargs rm -f
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

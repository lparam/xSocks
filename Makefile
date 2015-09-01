MAJOR = 0
MINOR = 2
PATCH = 3
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

CPPFLAGS += -Isrc
CPPFLAGS += -I3rd/libuv/include -I3rd/libsodium/src/libsodium/include -I3rd/c-ares/

LDFLAGS = -Wl,--gc-sections

ifdef ANDROID
LDFLAGS += -pie -fPIE
else
	ifndef MINGW32
		LIBS += -lrt
	endif
endif

LIBS += 3rd/libuv/.libs/libuv.a 3rd/libsodium/src/libsodium/.libs/libsodium.a

ifdef MINGW32
LIBS += -lws2_32 -lpsapi -liphlpapi -luserenv
else
LIBS += -pthread -ldl
endif

LDFLAGS += $(LIBS)

#########################################################################
include $(SRCTREE)/config.mk
#########################################################################

ifdef OPENWRT
all: libuv libsodium xsocks xtproxy xforwarder xtunnel
else
all: libuv libsodium c-ares xsocksd xsocks xtproxy xforwarder xtunnel
endif

android: libuv libsodium xsocks xforwarder
mingw32: libuv libsodium c-ares xsocksd.exe xsocks.exe xforwarder.exe xtunnel.exe

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
	$(Q)cd 3rd/c-ares && ./buildconf && ./configure --host=$(HOST) --enable-static --disable-shared LDFLAGS= && $(MAKE) MAKEFLAGS=-rRs

c-ares: 3rd/c-ares/Makefile

ifndef MINGW32
xsocksd: \
	src/util.o \
	src/logger.o \
	src/common.o \
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
	$(LINK) $^ -o $(OBJTREE)/$@ 3rd/c-ares/.libs/libcares.a $(LDFLAGS)
endif

ifndef MINGW32
xsocks: \
	src/util.o \
	src/logger.o \
	src/common.o \
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
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)
endif

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

ifndef MINGW32
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
	$(LINK) $^ -o $(OBJTREE)/$@ $(LDFLAGS)
endif

ifndef MINGW32
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
	@find $(OBJTREE)/src -type f \
	\( -name '*.bak' -o -name '*~' \
	-o -name '*.o' -o -name '*.tmp' \) -print \
	| xargs rm -f
	@rm -f xsocksd xsocksd.exe xsocks xsocks.exe xtproxy xforwarder xforwarder.exe xtunnel xtunnel.exe

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

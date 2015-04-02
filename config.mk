#
# (C) Copyright 2000-2015
# Ken <ken.i18n@gmail.com>
#

#########################################################################

ifneq ($(OBJTREE),$(SRCTREE))
ifeq ($(CURDIR),$(SRCTREE))
dir :=
else
dir := $(subst $(SRCTREE)/,,$(CURDIR))
endif
obj := $(if $(dir),$(OBJTREE)/$(dir)/,$(OBJTREE)/)
src := $(if $(dir),$(SRCTREE)/$(dir)/,$(SRCTREE)/)
$(shell mkdir -p $(obj))
else
# current object directory
obj :=
src :=
endif

#########################################################################

#
# Include the make variables (CC, etc...)
#
AS	= $(CROSS_COMPILE)as
CC	= $(CROSS_COMPILE)gcc
LD	= $(CROSS_COMPILE)ld
CPP	= $(CC) -E
AR	= $(CROSS_COMPILE)ar
NM	= $(CROSS_COMPILE)nm
LDR	= $(CROSS_COMPILE)ldr
STRIP	= $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
RANLIB	= $(CROSS_COMPILE)ranlib

#########################################################################

export CROSS_COMPILE \
	AS LD CC CPP AR NM STRIP OBJCOPY OBJDUMP MAKE

#########################################################################

MAKEFLAGS += -rR --no-print-directory

ifndef V
  Q = @
endif

FINAL_CFLAGS = $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS)
FINAL_LDFLAGS =

CCC=$(QUIET_CC)$(CC) $(FINAL_CFLAGS)
LINK=$(QUIET_LINK)$(CC) $(FINAL_LDFLAGS)
INSTALL=$(QUIET_INSTALL)

CCCOLOR="\033[34m"
LINKCOLOR="\033[34;1m"
SRCCOLOR="\033[33m"
BINCOLOR="\033[32;1m"
MAKECOLOR="\033[32;1m"
ECHOCOLOR="\033[32;1m"
ENDCOLOR="\033[0m"

ifndef V
QUIET_CC = @printf '    %b %b\n' $(CCCOLOR)CC$(ENDCOLOR) $(SRCCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_LINK = @printf '    %b %b\n' $(LINKCOLOR)LINK$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_INSTALL = @printf '    %b %b\n' $(LINKCOLOR)INSTALL$(ENDCOLOR) $(BINCOLOR)$@$(ENDCOLOR) 1>&2;
QUIET_STRIP_OPTION = > /dev/null
endif

ifneq ($(OBJTREE),$(SRCTREE))
cobj = $(subst $(OBJTREE)/,,$@)
else
cobj = $(subst $(OBJTREE)/,,$(CURDIR)/$@)
endif

$(obj)%.o:	%.c
	$(shell [ -d $(dir $@) ] || mkdir -p $(dir $@))
	$(CCC) -c $< -o $(cobj)


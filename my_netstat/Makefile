# path to the net-lib support library. Default: lib
NET_LIB_PATH = lib
NET_LIB_NAME = net-tools

PROGS = netstat

# Compiler and Linker Options
CFLAGS ?= -O2 -g
CFLAGS += -Wall
CFLAGS += -fno-strict-aliasing # code needs a lot of work before strict aliasing is safe
CPPFLAGS += -D_GNU_SOURCE
# Turn on transparent support for LFS
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

ifeq ($(origin CC), undefined)
CC	= gcc
endif
LD	= $(CC)
PKG_CONFIG ?= pkg-config

# -------- end of user definitions --------

.EXPORT_ALL_VARIABLES:

ifeq ("$(NET_LIB_PATH)","lib2")
TOPDIR   = ..
else
TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)
endif

NET_LIB = $(NET_LIB_PATH)/lib$(NET_LIB_NAME).a

CPPFLAGS += -I. -I$(TOPDIR)/include -I$(NET_LIB_PATH)
LDFLAGS  += -L$(NET_LIB_PATH)

SUBDIRS	= $(NET_LIB_PATH)/

NLIB	= -l$(NET_LIB_NAME)

%.o:		%.c config.h intl.h $<
		$(CC) $(CFLAGS) $(CPPFLAGS) -c $<

all:		config.h subdirs $(NET_LIB) netstat.o

clean:
		rm -f -- *.o lib/*.o
		rm -f -- ../$(PROGS)
		@for i in $(SUBDIRS); do (cd $$i && $(MAKE) clean) ; done

$(NET_LIB):	config.h intl.h libdir

libdir:
		@$(MAKE) -C $(NET_LIB_PATH)

# use libdir target for lib/ to avoid parallel build issues
subdirs:	libdir
		@for i in $(SUBDIRS:$(NET_LIB_PATH)/=); do $(MAKE) -C $$i || exit $$? ; done

# netstat:	$(NET_LIB) netstat.o
# 		$(CC) $(CFLAGS) $(LDFLAGS) -o $@ netstat.o $(NLIB)

# End of Makefile.

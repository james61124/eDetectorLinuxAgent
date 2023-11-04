# path to the net-lib support library. Default: lib
PROC_PATH = proc
PROC_NAME = proc-tools

PROGS = ps

# Compiler and Linker Options
CFLAGS ?= -O2 -g
CFLAGS += -Wall
CFLAGS += -fno-strict-aliasing
CPPFLAGS += -D_GNU_SOURCE
CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

ifeq ($(origin CC), undefined)
CC	= gcc
endif
LD	= $(CC)
PKG_CONFIG ?= pkg-config

# -------- end of user definitions --------

.EXPORT_ALL_VARIABLES:

ifeq ("$(PROC_PATH)","lib2")
TOPDIR   = ..
else
TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)
endif

PROC = $(PROC_PATH)/lib$(PROC_NAME).a

CPPFLAGS += -I. -I$(TOPDIR)/include -I$(PROC_PATH)
LDFLAGS  += -L$(PROC_PATH)

SUBDIRS	= $(PROC_PATH)/

PLIB	= -l$(PROC_NAME)

%.o:		%.c common.h $<
		$(CC) -c $(CFLAGS) $(CPPFLAGS) -c $<

all:		common.h subdirs $(PROC) output.o

clean:
		rm -f -- *.o proc/*.o
		rm -f -- ../$(PROGS)
		@for i in $(SUBDIRS); do (cd $$i && $(MAKE) clean) ; done

$(PROC):	common.h libdir

libdir:
		@$(MAKE) -C $(PROC_PATH)

# use libdir target for lib/ to avoid parallel build issues
subdirs:	libdir
		@for i in $(SUBDIRS:$(PROC_PATH)/=); do $(MAKE) -C $$i || exit $$? ; done

#ps:		$(PROC) output.o
#		$(CC) $(CFLAGS) $(LDFLAGS) -o $@ output.o $(PLIB)

# End of Makefile.

# Default Name
NET_LIB_NAME = net-tools

OBJS	= af.o inet.o inet6.o proc.o util.o sysinfo.o

# This can be overwritten by the TOPLEVEL Makefile
TOPDIR=..
CFLAGS += -I$(TOPDIR) -I$(TOPDIR)/include

all:	lib$(NET_LIB_NAME).a

lib$(NET_LIB_NAME).a:	Makefile $(TOPDIR)/config.h $(OBJS)
			@$(AR) rcs $@ $(OBJS)

clean:
		rm -f -- *.o lib$(NET_LIB_NAME).a

# End of lib/Makefile.

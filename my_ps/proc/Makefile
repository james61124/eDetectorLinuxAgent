# Default Name
PROC_NAME = proc-tools

OBJS	= readproc.o sysinfo.o

TOPDIR=..
CFLAGS += -I$(TOPDIR) -I$(TOPDIR)/include

all:	lib$(PROC_NAME).a

lib$(PROC_NAME).a:	Makefile $(OBJS)
			@$(AR) rcs $@ $(OBJS)

readproc.o: readproc.h readproc.cpp

sysinfo.o: sysinfo.h sysinfo.cpp

clean:
		rm -f -- *.o lib$(PROC_NAME).a

# End of lib/Makefile.

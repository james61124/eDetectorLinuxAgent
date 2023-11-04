IR_LIB_NAME = irfile-tools

OBJS = irfilelist.o

all:	lib$(IR_LIB_NAME).a

lib$(IR_LIB_NAME).a:	Makefile $(OBJS)
			@$(AR) rcs $@ $(OBJS)

clean:
		rm -f -- *.o lib$(IR_LIB_NAME).a

# End of lib/Makefile.

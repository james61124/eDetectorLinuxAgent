# PROGS = main

# NET_LIB_PATH = my_netstat
# PS_LIB_PATH = my_ps
# TASK_LIB_PATH = my_task

# IR_LIB_NAME = irfile-tools
# NET_LIB_NAME = net-tools
# PS_LIB_NAME = proc-tools
# AES_LIB_NAME = libMyAES-d

# # Compiler and Linker Options
# CFLAGS ?= -O2 -g
# CFLAGS += -Wall
# CFLAGS += -fno-strict-aliasing # code needs a lot of work before strict aliasing is safe
# CPPFLAGS += -D_GNU_SOURCE
# # Turn on transparent support for LFS
# CPPFLAGS += -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE

# ifeq ($(origin CC), undefined)
# CC	= gcc
# endif
# LD	= $(CC)
# PKG_CONFIG ?= pkg-config
# # -------- end of user definitions --------

# # IR_LIB = $(IR_LIB_PATH)/lib$(IR_LIB_NAME).a
# # CPPFLAGS += -I. -I$(IR_LIB_PATH) -I$(NET_LIB_PATH) -I$(PS_LIB_PATH)
# # LDFLAGS  += -L$(IR_LIB_PATH) -L$(NET_LIB_PATH)/lib -L$(PS_LIB_PATH)/proc

# # IRLIB = -l$(IR_LIB_NAME)
# NLIB	= -l$(NET_LIB_NAME)
# PSLIB	= -l$(PS_LIB_NAME)
# # AESLIB	= -l$(AES_LIB_NAME)

# %.o:	%.cpp
# 	$(CC) -std=c++17 $(CFLAGS) $(CPPFLAGS) -c $<
	
# all:	$(PROGS) 

# main:	$(IR_LIB) netstat.o main.o output.o socket_manager.o caes.o explorer.o info.o Log.o scan.o socket_send.o task.o tools.o 
# 	$(CC) -std=c++17 $(CFLAGS) $(LDFLAGS) -o $@ main.o $(NET_LIB_PATH)/netstat.o $(PS_LIB_PATH)/output.o $(TASK_LIB_PATH)/socket_manager.o $(TASK_LIB_PATH)/caes.o $(TASK_LIB_PATH)/explorer.o $(TASK_LIB_PATH)/info.o $(TASK_LIB_PATH)/Log.o $(TASK_LIB_PATH)/scan.o $(TASK_LIB_PATH)/socket_send.o $(TASK_LIB_PATH)/task.o $(TASK_LIB_PATH)/tools.o $(NLIB) $(PSLIB) -lpthread -lstdc++ 
# # $(CC) -std=c++17 $(CFLAGS) $(LDFLAGS) -o $@ main.o $(NET_LIB_PATH)/netstat.o $(PS_LIB_PATH)/output.o $(TASK_LIB_PATH)/socket_manager.o $(TASK_LIB_PATH)/caes.o $(TASK_LIB_PATH)/explorer.o $(TASK_LIB_PATH)/info.o $(TASK_LIB_PATH)/Log.o $(TASK_LIB_PATH)/scan.o $(TASK_LIB_PATH)/socket_send.o $(TASK_LIB_PATH)/task.o $(TASK_LIB_PATH)/tools.o $(NLIB) $(PSLIB) -lpthread -lstdc++ 

# # $(IR_LIB):
# # 	@$(MAKE) -C $(IR_LIB_PATH)
	
# netstat.o:
# 	@$(MAKE) -C $(NET_LIB_PATH)
	
# output.o:
# 	@$(MAKE) -C $(PS_LIB_PATH)

# socket_manager.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# caes.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# explorer.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# info.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# Log.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# scan.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# socket_send.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# task.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# tools.o:
# 	@$(MAKE) -C $(TASK_LIB_PATH)

# clean:
# 	rm -f -- *.o
# 	rm -f -- $(PROGS)
# 	@for i in $(NET_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
# 	@for i in $(PS_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
# 	@for i in $(TASK_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done


PROGS = main

IR_LIB_PATH = my_IRfiletar
NET_LIB_PATH = my_netstat
PS_LIB_PATH = my_ps
TASK_LIB_PATH = my_task

IR_LIB_NAME = irfile-tools
NET_LIB_NAME = net-tools
PS_LIB_NAME = proc-tools
AES_LIB_NAME = libMyAES-d

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

IR_LIB = $(IR_LIB_PATH)/lib$(IR_LIB_NAME).a
CPPFLAGS += -I. -I$(IR_LIB_PATH) -I$(NET_LIB_PATH) -I$(PS_LIB_PATH)
LDFLAGS  += -L$(IR_LIB_PATH) -L$(NET_LIB_PATH)/lib -L$(PS_LIB_PATH)/proc

IRLIB = -l$(IR_LIB_NAME)
NLIB	= -l$(NET_LIB_NAME)
PSLIB	= -l$(PS_LIB_NAME)
# AESLIB	= -l$(AES_LIB_NAME)

%.o:	%.cpp
	$(CC) -std=c++17 $(CFLAGS) $(CPPFLAGS) -c $<
	
all:	$(PROGS) 

# main:	$(IR_LIB) netstat.o main.o output.o socket_manager.o caes.o explorer.o info.o Log.o scan.o socket_send.o task.o tools.o 
# 	$(CC) -std=c++17 $(CFLAGS) $(LDFLAGS) -o $@ main.o $(NET_LIB_PATH)/netstat.o $(PS_LIB_PATH)/output.o $(TASK_LIB_PATH)/socket_manager.o $(TASK_LIB_PATH)/caes.o $(TASK_LIB_PATH)/explorer.o $(TASK_LIB_PATH)/info.o $(TASK_LIB_PATH)/Log.o $(TASK_LIB_PATH)/scan.o $(TASK_LIB_PATH)/socket_send.o $(TASK_LIB_PATH)/task.o $(TASK_LIB_PATH)/tools.o $(NLIB) $(PSLIB) -lpthread -lstdc++ 
# # $(CC) -std=c++17 $(CFLAGS) $(LDFLAGS) -o $@ main.o $(NET_LIB_PATH)/netstat.o $(PS_LIB_PATH)/output.o $(TASK_LIB_PATH)/socket_manager.o $(TASK_LIB_PATH)/caes.o $(TASK_LIB_PATH)/explorer.o $(TASK_LIB_PATH)/info.o $(TASK_LIB_PATH)/Log.o $(TASK_LIB_PATH)/scan.o $(TASK_LIB_PATH)/socket_send.o $(TASK_LIB_PATH)/task.o $(TASK_LIB_PATH)/tools.o $(NLIB) $(PSLIB) -lpthread -lstdc++ 

main:	$(IR_LIB) netstat.o main.o output.o socket_manager.o caes.o explorer.o info.o Log.o scan.o socket_send.o task.o tools.o 
	$(CC) -std=c++17 $(CFLAGS) $(LDFLAGS) -o $@ main.o $(NET_LIB_PATH)/netstat.o $(PS_LIB_PATH)/output.o $(TASK_LIB_PATH)/socket_manager.o $(TASK_LIB_PATH)/caes.o $(TASK_LIB_PATH)/explorer.o $(TASK_LIB_PATH)/info.o $(TASK_LIB_PATH)/Log.o $(TASK_LIB_PATH)/scan.o $(TASK_LIB_PATH)/socket_send.o $(TASK_LIB_PATH)/task.o $(TASK_LIB_PATH)/tools.o $(IRLIB) $(NLIB) $(PSLIB) -lpthread -lstdc++ 

$(IR_LIB):
	@$(MAKE) -C $(IR_LIB_PATH)
	
netstat.o:
	@$(MAKE) -C $(NET_LIB_PATH)
	
output.o:
	@$(MAKE) -C $(PS_LIB_PATH)

socket_manager.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

caes.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

explorer.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

info.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

Log.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

scan.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

socket_send.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

task.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

tools.o:
	@$(MAKE) -C $(TASK_LIB_PATH)

clean:
	rm -f -- *.o
	rm -f -- $(PROGS)
	@for i in $(IR_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
	@for i in $(NET_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
	@for i in $(PS_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
	@for i in $(TASK_LIB_PATH); do (cd $$i && $(MAKE) clean) ; done
	

	

CC = g++
CFLAGS = -c -Wall

SOURCES = caes.cpp explorer.cpp info.cpp Log.cpp scan.cpp socket_manager.cpp socket_send.cpp task.cpp tools.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(OBJECTS)

%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS)

.PHONY: clean
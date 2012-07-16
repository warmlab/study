CC=g++
CFLAGS=-g3
LIBS:=-lssl -lboost_iostreams -lboost_system

all: server client
server: server.cpp
	$(CC) $(CFLAGS) $(LIBS) server.cpp -o server
client: client.cpp
	$(CC) $(CFLAGS) $(LIBS) client.cpp -o client

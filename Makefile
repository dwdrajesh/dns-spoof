
#LDFLAGS := /usr/lib/x86_64-linux-gnu/
#export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu 
CFLAGS += -ggdb
CC = g++

all:
	$(CC) $(CFLAGS) main.cpp -o main
	$(CC) $(CFLAGS) raw_socket_parse.cpp -o raw_socket_parse

run:
	./main
clean:
	rm -rf main raw_socket_parse 

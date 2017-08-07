
#LDFLAGS := /usr/lib/x86_64-linux-gnu/
#export LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu 
CFLAGS += -ggdb
CC = g++

all:
	$(CC) $(CFLAGS) main.cpp -o main

run:
	./main
clean:
	rm -rf main

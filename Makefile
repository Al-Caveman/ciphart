CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -O3 -g

all:
	$(CC) ciphart.c -o ciphart -lsodium $(CFLAGS)

clean:
	rm -f ciphart

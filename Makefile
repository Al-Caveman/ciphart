CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -O3 -g
#C=clang
#CFLAGS=-Wall -Wextra -march=native -mtune=native -g

all:
	$(CC) ciphart.c -o ciphart -lsodium -lm -pthread $(CFLAGS)

clean:
	rm -f ciphart

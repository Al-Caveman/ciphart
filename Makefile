CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -O2 -std=c99 -pedantic

all:
	$(CC) ciphart.c -o ciphart -lsodium -lm -pthread $(CFLAGS)

test:  test-prepare test-docs test-ed test-k test-edk

test-prepare:
	mkdir -p tests/current/{docs,ed,k,edk}
	dd count=100000 if=/dev/urandom of=tests/truth/data.clr

test-docs:
	./ciphart -h           &> tests/current/docs/help.txt
	./ciphart -w           &> tests/current/docs/warn.txt
	./ciphart -w           &> tests/current/docs/cond.txt
	./ciphart -h -p auto   &> tests/current/docs/help.pauto.txt
	./ciphart -w -p auto   &> tests/current/docs/warn.pauto.txt
	./ciphart -w -p auto   &> tests/current/docs/cond.pauto.txt
	./ciphart -h -p always &> tests/current/docs/help.palways.txt
	./ciphart -w -p always &> tests/current/docs/warn.palways.txt
	./ciphart -w -p always &> tests/current/docs/cond.palways.txt
	./ciphart -h -p never  &> tests/current/docs/help.pnever.txt
	./ciphart -w -p never  &> tests/current/docs/warn.pnever.txt
	./ciphart -w -p never  &> tests/current/docs/cond.pnever.txt
	diff tests/current/docs/help.txt         tests/truth/docs/help.txt
	diff tests/current/docs/warn.txt         tests/truth/docs/warn.txt
	diff tests/current/docs/cond.txt         tests/truth/docs/cond.txt
	diff tests/current/docs/help.pauto.txt   tests/truth/docs/help.pauto.txt
	diff tests/current/docs/warn.pauto.txt   tests/truth/docs/warn.pauto.txt
	diff tests/current/docs/cond.pauto.txt   tests/truth/docs/cond.pauto.txt
	diff tests/current/docs/help.palways.txt tests/truth/docs/help.palways.txt
	diff tests/current/docs/warn.palways.txt tests/truth/docs/warn.palways.txt
	diff tests/current/docs/cond.palways.txt tests/truth/docs/cond.palways.txt
	diff tests/current/docs/help.pnever.txt  tests/truth/docs/help.pnever.txt
	diff tests/current/docs/warn.pnever.txt  tests/truth/docs/warn.pnever.txt
	diff tests/current/docs/cond.pnever.txt  tests/truth/docs/cond.pnever.txt

test-ed:
	echo "lol" | ./ciphart -zse -i tests/truth/data.clr          -o tests/current/ed/data.clr.enc
	echo "lol" | ./ciphart -sd  -i tests/current/ed/data.clr.enc -o tests/current/ed/data.clr.enc.clr
	diff tests/current/ed/data.clr.enc.clr tests/truth/data.clr

test-k:
	echo "lol" | ./ciphart -sk       -o tests/current/k/key
	echo "lol" | ./ciphart -sk -j 1  -o tests/current/k/key.j1
	echo "lol" | ./ciphart -sk -j 3  -o tests/current/k/key.j3
	echo "lol" | ./ciphart -sk -j 30 -o tests/current/k/key.j30
	echo "lol" | ciphart -skt8 -m16 -r100 -n24.5 -j5 -o tests/current/k/key.t8.m16.r100.n24.5.j5
	diff tests/current/k/key                      tests/truth/k/key
	diff tests/current/k/key.j1                   tests/truth/k/key.j1
	diff tests/current/k/key.j3                   tests/truth/k/key.j3
	diff tests/current/k/key.j30                  tests/truth/k/key.j30
	diff tests/current/k/key.t8.m16.r100.n24.5.j5 tests/truth/k/key.t8.m16.r100.n24.5.j5

test-edk:
	echo "lol" | ./ciphart -zske -i tests/truth/data.clr           -o tests/current/edk/data.clr.enc
	echo "lol" | ./ciphart -skd  -i tests/current/edk/data.clr.enc -o tests/current/edk/data.clr.enc.clr
	diff tests/current/edk/data.clr.enc.clr tests/truth/edk/data.clr

clean:
	rm -rf ciphart tests/current tests/truth/data.clr

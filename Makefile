CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -O2 -std=c99 -pedantic

APP=./ciphart
TRU=tests/truth
CUR=tests/current
DIF=diff --color=always -u
PAS=echo "testing password 123 let me in!"

all: ${APP}

${APP}:
	$(CC) ${APP}.c -o ${APP} -lsodium -lm -pthread $(CFLAGS)

test: test-prepare test-docs test-ed test-k test-edk

test-prepare:
	mkdir -p ${CUR}/{docs,ed,k,edk}
	dd count=100000 if=/dev/urandom of=${TRU}/data.clr

test-docs: ${APP} test-prepare
	${APP} -h           &> ${CUR}/docs/help.txt
	${APP} -w           &> ${CUR}/docs/warn.txt
	${APP} -w           &> ${CUR}/docs/cond.txt
	${APP} -h -p auto   &> ${CUR}/docs/help.pauto.txt
	${APP} -w -p auto   &> ${CUR}/docs/warn.pauto.txt
	${APP} -w -p auto   &> ${CUR}/docs/cond.pauto.txt
	${APP} -h -p always &> ${CUR}/docs/help.palways.txt
	${APP} -w -p always &> ${CUR}/docs/warn.palways.txt
	${APP} -w -p always &> ${CUR}/docs/cond.palways.txt
	${APP} -h -p never  &> ${CUR}/docs/help.pnever.txt
	${APP} -w -p never  &> ${CUR}/docs/warn.pnever.txt
	${APP} -w -p never  &> ${CUR}/docs/cond.pnever.txt
	${DIF} ${CUR}/docs/help.txt         ${TRU}/docs/help.txt
	${DIF} ${CUR}/docs/warn.txt         ${TRU}/docs/warn.txt
	${DIF} ${CUR}/docs/cond.txt         ${TRU}/docs/cond.txt
	${DIF} ${CUR}/docs/help.pauto.txt   ${TRU}/docs/help.pauto.txt
	${DIF} ${CUR}/docs/warn.pauto.txt   ${TRU}/docs/warn.pauto.txt
	${DIF} ${CUR}/docs/cond.pauto.txt   ${TRU}/docs/cond.pauto.txt
	${DIF} ${CUR}/docs/help.palways.txt ${TRU}/docs/help.palways.txt
	${DIF} ${CUR}/docs/warn.palways.txt ${TRU}/docs/warn.palways.txt
	${DIF} ${CUR}/docs/cond.palways.txt ${TRU}/docs/cond.palways.txt
	${DIF} ${CUR}/docs/help.pnever.txt  ${TRU}/docs/help.pnever.txt
	${DIF} ${CUR}/docs/warn.pnever.txt  ${TRU}/docs/warn.pnever.txt
	${DIF} ${CUR}/docs/cond.pnever.txt  ${TRU}/docs/cond.pnever.txt

test-ed: ${APP} test-prepare
	${PAS} | ${APP} -zse -i ${TRU}/data.clr        -o ${CUR}/ed/data.clr.enc
	${PAS} | ${APP} -sd  -i ${CUR}/ed/data.clr.enc -o ${CUR}/ed/data.clr.enc.clr
	${DIF} ${CUR}/ed/data.clr.enc.clr ${TRU}/data.clr

test-k: ${APP} test-prepare
	${PAS} | ${APP} -sk       -o ${CUR}/k/key
	${PAS} | ${APP} -sk -j 1  -o ${CUR}/k/key.j1
	${PAS} | ${APP} -sk -j 3  -o ${CUR}/k/key.j3
	${PAS} | ${APP} -sk -j 30 -o ${CUR}/k/key.j30
	${PAS} | ${APP} -skt8 -m16 -r100 -n24.5 -j5 -o ${CUR}/k/key.t8.m16.r100.n24.5.j5
	${DIF} ${CUR}/k/key                      ${TRU}/k/key
	${DIF} ${CUR}/k/key.j1                   ${TRU}/k/key.j1
	${DIF} ${CUR}/k/key.j3                   ${TRU}/k/key.j3
	${DIF} ${CUR}/k/key.j30                  ${TRU}/k/key.j30
	${DIF} ${CUR}/k/key.t8.m16.r100.n24.5.j5 ${TRU}/k/key.t8.m16.r100.n24.5.j5

test-edk: ${APP} test-prepare
	${PAS} | ${APP} -zske -i ${TRU}/data.clr           -o ${CUR}/edk/data.clr.enc
	${PAS} | ${APP} -skd  -i ${CUR}/edk/data.clr.enc -o ${CUR}/edk/data.clr.enc.clr
	${DIF} ${CUR}/edk/data.clr.enc.clr ${TRU}/data.clr

clean:
	rm -rf ${APP} ${CUR} ${TRU}/data.clr

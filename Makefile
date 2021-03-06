CC=gcc
CFLAGS=-Wall -Wextra -march=native -mtune=native -std=c99 -pedantic -g

APP=./ciphart
TRU=tests/truth
CUR=tests/current
PAS=echo -n "testing password 123 let me in!"
DIF=diff --color=always -u

.PHONY: all
all: $(APP)

$(APP): $(APP).c
	$(CC) $(APP).c -o $(APP) -lsodium -lm -pthread $(CFLAGS)

.PHONY: test
test: test-prepare test-docs test-ed test-k test-edk

.PHONY: test-prepare
test-prepare:
	mkdir -p $(CUR)/{docs,ed,k,edk}
	dd count=100000 if=/dev/urandom of=$(TRU)/data.clr

.PHONY: test-docs
test-docs: $(APP) test-prepare
	$(APP) -h > $(CUR)/docs/help.txt
	$(APP) -w > $(CUR)/docs/warn.txt
	$(APP) -w > $(CUR)/docs/cond.txt
	$(DIF) 	    $(CUR)/docs/help.txt $(TRU)/docs/help.txt
	$(DIF) 	    $(CUR)/docs/warn.txt $(TRU)/docs/warn.txt
	$(DIF) 	    $(CUR)/docs/cond.txt $(TRU)/docs/cond.txt

.PHONY: test-ed
test-ed: $(APP) test-prepare
	$(PAS) | $(APP) -zsve -i $(TRU)/data.clr        -o $(CUR)/ed/data.clr.enc
	$(PAS) | $(APP) -svd  -i $(CUR)/ed/data.clr.enc -o $(CUR)/ed/data.clr.enc.clr
	$(DIF) $(CUR)/ed/data.clr.enc.clr $(TRU)/data.clr

.PHONY: test-k
test-k: $(APP) test-prepare
	$(PAS) | $(APP) -svk       -o $(CUR)/k/key
	$(PAS) | $(APP) -svk -j 1  -o $(CUR)/k/key.j1
	$(PAS) | $(APP) -svk -j 3  -o $(CUR)/k/key.j3
	$(PAS) | $(APP) -svk -j 30 -o $(CUR)/k/key.j30
	$(PAS) | $(APP) -svkt16 -m32 -r100 -n24 -j5 -o $(CUR)/k/key.t8.m16.r100.n24.j5
	$(DIF) $(CUR)/k/key                      $(TRU)/k/key
	$(DIF) $(CUR)/k/key.j1                   $(TRU)/k/key.j1
	$(DIF) $(CUR)/k/key.j3                   $(TRU)/k/key.j3
	$(DIF) $(CUR)/k/key.j30                  $(TRU)/k/key.j30
	$(DIF) $(CUR)/k/key.t8.m16.r100.n24.j5 $(TRU)/k/key.t8.m16.r100.n24.j5

.PHONY: test-edk
test-edk: $(APP) test-prepare
	$(PAS) | $(APP) -zsvke -i $(TRU)/data.clr           -o $(CUR)/edk/data.clr.enc
	$(PAS) | $(APP) -skvd  -i $(CUR)/edk/data.clr.enc -o $(CUR)/edk/data.clr.enc.clr
	$(DIF) $(CUR)/edk/data.clr.enc.clr $(TRU)/data.clr

.PHONY: clean
clean:
	rm -rf $(APP) $(CUR) $(TRU)/data.clr

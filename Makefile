
OS=$(shell uname -s)
ARCH=$(shell uname -m)

ifeq ($(ARCH), armv6l)
CC = gcc
else
CC = clang
endif
ASAN = 0

###
### CFLAGS
###

CFLAGS  = -O1 -MMD -g
CFLAGS += -Wall
ifneq ($(ARCH), armv6l)
CFLAGS += -Wshadow -Wextra
endif
CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers

CFLAGS += -fno-omit-frame-pointer
CFLAGS += -fstack-protector
ifeq ($(ASAN), 1)
ifneq ($(OS), Darwin)
CFLAGS += -fsanitize=address
endif
endif

ifeq ($(OS), OpenBSD)
CFLAGS += -I/usr/local/include
endif

CFLAGS += -Ipublic -Ilib/public -Icore/ -Iapps/bitc-cli/ -Iext/src/public

ifeq ($(OS), Darwin)
BREW := $(shell brew --prefix)
CFLAGS += -I$(BREW)/include
endif

###
### LDOPTS
###

LDOPTS =
ifneq ($(OS), Darwin)
ifeq ($(ASAN), 1)
LDOPTS += -fsanitize=address
endif
LDOPTS += -rdynamic
endif

ifdef P
CFLAGS += -pg
LDOPTS += -pg
endif


###
### the rest
###

LIBS  = -lpthread -lssl -lcrypto -lm -lncurses -lpanel -lform -lcurl
LIBS += -lleveldb -lsnappy -lstdc++

ifeq ($(OS), OpenBSD)
LIBS += -L/usr/local/lib -lexecinfo
LIBS := $(subst -lsnappy,,$(LIBS))
endif

ifeq ($(OS), Darwin)
LDOPTS += -L$(BREW)/lib
endif

VGRND  = valgrind --log-file=/tmp/valgrind.log --leak-check=full --error-exitcode=255
BLDDIR = bld
BTC_BIN  = bitc
ALLTARGETS = bitc

ifndef V
  QUIET_CC   = @echo ' CC   ' $<;
  QUIET_LINK = @echo ' LINK ' $@;
  QUIET_TEST = >/dev/null 2>&1
endif

BTC_FILES  = core/btc-message.c
BTC_FILES += core/script.c
BTC_FILES += core/peer.c
BTC_FILES += core/peergroup.c
BTC_FILES += core/addrbook.c
BTC_FILES += core/block-store.c
BTC_FILES += core/base58.c
BTC_FILES += core/bloom.c
BTC_FILES += core/key.c
BTC_FILES += core/txdb.c
BTC_FILES += core/wallet.c
BTC_FILES += core/serialize.c
BTC_FILES += core/crypt.c
BTC_FILES += core/rpc.c
BTC_FILES += core/hash.c

BTC_FILES += lib/hashtable/hashtable.c
BTC_FILES += lib/fx/fx.c
BTC_FILES += lib/util/util.c
BTC_FILES += lib/file/file.c
BTC_FILES += lib/poolworker/poolworker.c
BTC_FILES += lib/config/config.c
BTC_FILES += lib/poll/poll.c
BTC_FILES += lib/netasync/netasync.c
BTC_FILES += lib/ip_info/ip_info.c

BTC_FILES += ext/src/cJSON/cJSON.c
BTC_FILES += ext/src/MurmurHash3/MurmurHash3.c

BTC_FILES += apps/bitc-cli/main.c
BTC_FILES += apps/bitc-cli/ncui.c
BTC_FILES += apps/bitc-cli/bitc_ui.c
BTC_FILES += apps/bitc-cli/test.c

BTC_FILES := $(sort $(BTC_FILES))
BTC_OBJ   := $(patsubst %.c,$(BLDDIR)/%.o,$(BTC_FILES))
BTC_DEPS  := $(patsubst %.c,$(BLDDIR)/%.d,$(BTC_FILES))

$(BLDDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -c $< -o $@

bitc: $(BTC_OBJ)
	$(QUIET_LINK)$(CC) $(LDOPTS) -o $(BTC_BIN) $(BTC_OBJ) $(LIBS)

# do not move the following line:
-include $(BTC_DEPS)

inocuoustest:
	$(eval VGRND :=)

test: bitc inocuoustest
	./bitc -t 0

vg-test: bitc inocuoustest
	$(VGRND) ./bitc -t 0

vg-run:
	valgrind --log-file=log --leak-check=full --gen-suppressions=all --suppressions=./valgrind.supp ./bitc

###
###  Common
###

all: $(ALLTARGETS)

lldb: apps/test/lldb.c
	 $(CC) -o ./lldb src/lldb.c -lleveldb

###
### Adversarial parser fuzzer: feeds random/truncated bytes to every
### peer-message parser and checks none of them crash. Run: ./fuzz-parse [iters]
### For a precise report on a crash, rebuild with ASAN=1 and replay:
###   ./fuzz-parse --hex <bytes-from-the-crash-line>
###
FUZZ_OBJ  = $(BLDDIR)/core/btc-message.o $(BLDDIR)/core/serialize.o
FUZZ_OBJ += $(BLDDIR)/core/hash.o $(BLDDIR)/core/base58.o
FUZZ_OBJ += $(BLDDIR)/lib/util/util.o $(BLDDIR)/lib/file/file.o

fuzz-parse: apps/test/fuzz-parse.c $(FUZZ_OBJ)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

lines:
	 find . -name '*.[ch]'|xargs cat|wc -l

clean:
	rm -f $(ALLTARGETS) fuzz-parse *~ gmon*
	rm -rf $(BLDDIR)

tags:
	rm -f tags
	find . -follow \( -name '*.[ch]' \) -a -print | ctags -L -

cscope:
	rm -f cscope*
	find . -name '*.[ch]' -print | xargs cscope -b -q

.PHONY: clean tags cscope


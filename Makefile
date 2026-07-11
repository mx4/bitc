
OS=$(shell uname -s)
ARCH=$(shell uname -m)

ifeq ($(ARCH), armv6l)
CC = gcc
else
CC = clang
endif

###
### Build type: BUILD=debug (default) | release | asan
### ASAN=1 is kept as a backwards-compatible alias for BUILD=asan.
###

BUILD ?= debug
ifeq ($(ASAN), 1)
BUILD := asan
endif

LDOPTS :=

###
### Dependency discovery.
###
### Use pkg-config when available so keg-only / non-standard prefixes
### (Homebrew, multiarch lib dirs, ...) are handled without hardcoded paths.
### leveldb, snappy and ncurses' panel/form companions ship no .pc file, so
### they remain plain -l flags.
###

NCURSES  := $(shell pkg-config --exists ncurses 2>/dev/null && echo ncurses || echo ncursesw)
PKG_MODS := openssl libcurl libcjson $(NCURSES)

ifneq ($(shell command -v pkg-config 2>/dev/null),)
MISSING := $(strip $(foreach m,$(PKG_MODS),\
             $(if $(shell pkg-config --exists $(m) 2>/dev/null && echo y),,$(m))))
ifneq ($(MISSING),)
$(warning pkg-config cannot find: $(MISSING) -- install the matching -dev packages)
endif
DEP_CFLAGS := $(shell pkg-config --cflags $(PKG_MODS) 2>/dev/null)
DEP_LIBS   := $(shell pkg-config --libs   $(PKG_MODS) 2>/dev/null)
else
DEP_LIBS   := -lssl -lcrypto -lcurl -lcjson -lncurses
endif
DEP_LIBS += -lpanel -lform -lleveldb -lsnappy -lstdc++ -lpthread -lm

###
### CFLAGS
###

CFLAGS  = -MMD
CFLAGS += -Wall
ifneq ($(ARCH), armv6l)
CFLAGS += -Wshadow -Wextra
endif
CFLAGS += -Wno-unused-parameter -Wno-sign-compare -Wno-missing-field-initializers

# Optional C standard, e.g. STD=c17 (strict ISO) or STD=gnu17 (with extensions).
ifdef STD
CFLAGS += -std=$(STD)
endif

# STRICT=1: a stricter warning set, treated as errors. Useful in CI / pre-commit.
ifeq ($(STRICT), 1)
CFLAGS += -Wpointer-arith -Wwrite-strings -Wredundant-decls
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition
CFLAGS += -Werror
endif

CFLAGS += -fno-omit-frame-pointer -fstack-protector

ifeq ($(BUILD), release)
CFLAGS += -O2 -DNDEBUG
else ifeq ($(BUILD), asan)
CFLAGS += -O1 -g -fsanitize=address
LDOPTS += -fsanitize=address
else ifeq ($(BUILD), ubsan)
CFLAGS += -O1 -g -fsanitize=undefined -fno-sanitize-recover=undefined
LDOPTS += -fsanitize=undefined
else ifeq ($(BUILD), asan+ubsan)
CFLAGS += -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined
LDOPTS += -fsanitize=address,undefined
else
CFLAGS += -O1 -g
endif

CFLAGS += -Ipublic -Ilib/public -Icore/ -Iapps/bitc-cli/ -Iext/src/public
CFLAGS += $(DEP_CFLAGS)

ifeq ($(OS), OpenBSD)
CFLAGS += -I/usr/local/include
endif

# leveldb/snappy live under the Homebrew prefix on macOS and ship no .pc file.
ifeq ($(OS), Darwin)
BREW := $(shell brew --prefix 2>/dev/null)
ifneq ($(BREW),)
CFLAGS += -I$(BREW)/include
LDOPTS += -L$(BREW)/lib
endif
endif

###
### LDOPTS
###

ifneq ($(OS), Darwin)
LDOPTS += -rdynamic
endif

ifdef P
CFLAGS += -pg
LDOPTS += -pg
endif

###
### the rest
###

LIBS = $(DEP_LIBS)

ifeq ($(OS), OpenBSD)
LIBS += -L/usr/local/lib -lexecinfo
LIBS := $(subst -lsnappy,,$(LIBS))
endif

ifeq ($(OS), Darwin)
LDOPTS += -L$(BREW)/lib
endif

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
BTC_FILES += core/gcs.c
BTC_FILES += core/cfheader-store.c
BTC_FILES += core/ripemd160.c

BTC_FILES += lib/hashtable/hashtable.c
BTC_FILES += lib/fx/fx.c
BTC_FILES += lib/util/util.c
BTC_FILES += lib/file/file.c
BTC_FILES += lib/poolworker/poolworker.c
BTC_FILES += lib/config/config.c
BTC_FILES += lib/poll/poll.c
BTC_FILES += lib/netasync/netasync.c
BTC_FILES += lib/ip_info/ip_info.c

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

test: bitc
	./bitc -t 0

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
FUZZ_OBJ += $(BLDDIR)/core/hash.o $(BLDDIR)/core/ripemd160.o $(BLDDIR)/core/base58.o
FUZZ_OBJ += $(BLDDIR)/lib/util/util.o $(BLDDIR)/lib/file/file.o

fuzz-parse: apps/test/fuzz-parse.c $(FUZZ_OBJ)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

### GCS / SipHash self-test (BIP158 decoder).
TEST_GCS_OBJ  = $(BLDDIR)/core/gcs.o $(BLDDIR)/core/hash.o $(BLDDIR)/core/ripemd160.o
TEST_GCS_OBJ += $(BLDDIR)/lib/util/util.o $(BLDDIR)/lib/file/file.o

test-gcs: apps/test/test-gcs.c $(TEST_GCS_OBJ)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDOPTS) -o $@ $^ $(LIBS)

# Regression gate: build and run the parser fuzzer and GCS tests.
# Override for a deeper run, e.g. `make check FUZZ_ITERS=1000000`.
FUZZ_ITERS ?= 20000
check: fuzz-parse test-gcs
	./fuzz-parse $(FUZZ_ITERS)
	./test-gcs

# compile_commands.json for clangd / editor tooling (no external deps).
compile_commands.json:
	@echo '[' > $@; \
	i=0; n=$(words $(BTC_FILES)); \
	for f in $(BTC_FILES); do \
	  i=$$((i+1)); \
	  printf '  {"directory": "%s", "file": "%s", "command": "%s %s -c %s"}' \
	    "$(CURDIR)" "$$f" "$(CC)" "$(CFLAGS)" "$$f" >> $@; \
	  [ $$i -lt $$n ] && echo ',' >> $@ || echo >> $@; \
	done; \
	echo ']' >> $@; \
	echo "wrote $@ ($(words $(BTC_FILES)) entries)"

lines:
	 find . -name '*.[ch]'|xargs cat|wc -l

clean:
	rm -f $(ALLTARGETS) fuzz-parse fuzz-parse.d test-gcs test-gcs.d compile_commands.json *~ gmon*
	rm -rf fuzz-parse.dSYM test-gcs.dSYM $(BLDDIR)

tags:
	rm -f tags
	find . -follow \( -name '*.[ch]' \) -a -print | ctags -L -

cscope:
	rm -f cscope*
	find . -name '*.[ch]' -print | xargs cscope -b -q

.PHONY: all clean tags cscope check test compile_commands.json


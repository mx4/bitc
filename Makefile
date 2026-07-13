
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

CFLAGS += -Icore/ -Iapps/cli/ $(addprefix -I,$(wildcard lib/*/)) -Iext/src/MurmurHash3/
CFLAGS += $(DEP_CFLAGS)

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

BLDDIR = bld
.DELETE_ON_ERROR:
BTC_BIN  = bitc
ifndef V
  QUIET_CC   = @echo ' CC   ' $<;
  QUIET_LINK = @echo ' LINK ' $@;
  QUIET_TEST = >/dev/null 2>&1
endif

BTC_FILES := $(wildcard core/*.c lib/*/*.c ext/src/MurmurHash3/*.c apps/cli/*.c)
BTC_FILES := $(sort $(BTC_FILES))
BTC_OBJ   := $(patsubst %.c,$(BLDDIR)/%.o,$(BTC_FILES))
BTC_DEPS  := $(patsubst %.c,$(BLDDIR)/%.d,$(BTC_FILES))

$(BLDDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(QUIET_CC)$(CC) $(CFLAGS) -c $< -o $@

bitc: $(BTC_OBJ)
	$(QUIET_LINK)$(CC) $(LDOPTS) -o $(BTC_BIN) $(BTC_OBJ) $(DEP_LIBS)

# do not move the following line:
-include $(BTC_DEPS)

test: bitc
	./bitc -t 0

###
###  Common
###

all: bitc

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
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDOPTS) -o $@ $^ $(DEP_LIBS)

### GCS / SipHash self-test (BIP158 decoder).
TEST_GCS_OBJ  = $(BLDDIR)/core/gcs.o $(BLDDIR)/core/hash.o $(BLDDIR)/core/ripemd160.o
TEST_GCS_OBJ += $(BLDDIR)/lib/util/util.o $(BLDDIR)/lib/file/file.o

test-gcs: apps/test/test-gcs.c $(TEST_GCS_OBJ)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDOPTS) -o $@ $^ $(DEP_LIBS)

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
	rm -f bitc fuzz-parse fuzz-parse.d test-gcs test-gcs.d compile_commands.json *~ gmon*
	rm -rf fuzz-parse.dSYM test-gcs.dSYM $(BLDDIR)

tags:
	rm -f tags
	find . -follow \( -name '*.[ch]' \) -a -print | ctags -L -

cscope:
	rm -f cscope*
	find . -name '*.[ch]' -print | xargs cscope -b -q

.PHONY: all clean tags cscope check test compile_commands.json


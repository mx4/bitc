/*
 * Adversarial parser harness.
 *
 * Feeds random / truncated byte buffers to every peer-message parser and
 * checks that they return an error instead of crashing (panic, OOM-abort, or
 * out-of-bounds). A peer must never be able to take the process down.
 *
 * Reproducible: each iteration's bytes are a pure function of (base seed, i).
 * On a crash the signal handler dumps `iter` and the exact input as hex, and
 *   ./fuzz-parse --hex <hexbytes>
 * replays just that input (run it under ASAN for a precise report).
 *
 * Build: see the fuzz-parse target in the Makefile, or:
 *   clang -Ipublic -Ilib/public -Icore -Iext/src/public -I$(brew --prefix)/include \
 *     apps/test/fuzz-parse.c bld/core/btc-message.o bld/core/serialize.o \
 *     bld/core/hash.o bld/core/base58.o bld/lib/util/util.o bld/lib/file/file.o \
 *     -L$(brew --prefix)/lib -lcrypto -lpthread -o /tmp/fuzz-parse
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "basic_defs.h"
#include "buff.h"
#include "btc-message.h"
#include "bitc-defs.h"
#include "bitc.h"

/* Globals the engine expects; the parsers only read btc->testnet. */
struct BITCApp *btc;
bool bitc_testing = 1;

#define CAP 1024

/* deterministic PRNG so failures are reproducible */
static uint32 rng_state;
static uint32
rng(void)
{
   rng_state = rng_state * 1664525u + 1013904223u;
   return rng_state;
}

/* current input, dumped by the crash handler */
static volatile long g_iter;
static uint8         g_bytes[CAP];
static volatile size_t g_len;

static void
crash_handler(int sig)
{
   char b[64];
   size_t i;
   int n = snprintf(b, sizeof b, "\nCRASH sig=%d iter=%ld len=%zu bytes=",
                    sig, g_iter, g_len);
   write(2, b, n);
   for (i = 0; i < g_len; i++) {
      snprintf(b, sizeof b, "%02x", g_bytes[i]);
      write(2, b, 2);
   }
   write(2, "\n", 1);
   signal(sig, SIG_DFL);
   raise(sig);
}

/* bytes for iteration i are a pure function of (base, i) */
static size_t
gen(uint32 seed, uint8 *bytes)
{
   size_t len, j;
   rng_state = seed ? seed : 1;
   len = rng() % CAP;
   for (j = 0; j < len; j++) {
      bytes[j] = rng();
   }
   return len;
}

static void
fuzz_one(uint8 *bytes, size_t len)
{
   struct buff b;

#define WRAP() buff_init(&b, bytes, len)
   { WRAP(); btc_msg_version v; btcmsg_parse_version(&b, &v); }
   { WRAP(); uint64 nonce; btcmsg_parse_pingpong(BTC_PROTO_VERSION, &b, &nonce); }
   { WRAP(); uint256 *bh = NULL; int nbh = 0;
     if (btcmsg_parse_notfound(&b, &bh, &nbh) == 0) free(bh); }
   { WRAP(); btcmsg_parse_alert(&b); }
   { WRAP(); btc_msg_inv *inv = NULL; int n = 0;
     if (btcmsg_parse_inv(&b, &inv, &n) == 0) free(inv); }
   { WRAP(); btc_block_header *h = NULL; int n = 0;
     if (btcmsg_parse_headers(&b, &h, &n) == 0) free(h); }
   { WRAP(); btc_msg_merkleblock *m = NULL;
     if (btcmsg_parse_merkleblock(&b, &m) == 0) btc_msg_merkleblock_free(m); }
   { WRAP(); btc_msg_block blk; memset(&blk, 0, sizeof blk);
     if (btcmsg_parse_block(&b, &blk) == 0) btc_msg_block_free(&blk); }
   { WRAP(); struct btc_msg_address **a = NULL; size_t na = 0;
     if (btcmsg_parse_addr(BTC_PROTO_VERSION, &b, &a, &na) == 0) {
        for (size_t i = 0; i < na; i++) free(a[i]);
        free(a);
     } }
#undef WRAP
}

static int
hexval(int c)
{
   if (c >= '0' && c <= '9') return c - '0';
   if (c >= 'a' && c <= 'f') return c - 'a' + 10;
   if (c >= 'A' && c <= 'F') return c - 'A' + 10;
   return -1;
}

int
main(int argc, char **argv)
{
   uint32 base = 0x1234567;
   long iters, i;

   Log_Init("/tmp/fuzzharness.log");
   btc = calloc(1, sizeof *btc);
   signal(SIGSEGV, crash_handler);
   signal(SIGBUS,  crash_handler);
   signal(SIGABRT, crash_handler);

   /* replay a single input: ./fuzz-parse --hex deadbeef... */
   if (argc > 2 && strcmp(argv[1], "--hex") == 0) {
      const char *h = argv[2];
      size_t len = 0;
      while (h[0] && h[1] && len < CAP) {
         int hi = hexval(h[0]), lo = hexval(h[1]);
         if (hi < 0 || lo < 0) break;
         g_bytes[len++] = (hi << 4) | lo;
         h += 2;
      }
      g_len = len;
      fprintf(stderr, "replay len=%zu\n", len);
      fuzz_one(g_bytes, len);
      fprintf(stderr, "replay: no crash\n");
      return 0;
   }

   iters = argc > 1 ? atol(argv[1]) : 300000;
   for (i = 0; i < iters; i++) {
      size_t len = gen(base + (uint32)i * 2654435761u, g_bytes);
      g_iter = i;
      g_len = len;
      fuzz_one(g_bytes, len);
   }
   printf("fuzz-parse: %ld iterations, no crash\n", iters);
   return 0;
}

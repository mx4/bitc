#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "basic_defs.h"
#include "util.h"
#include "hashtable.h"
#include "peerstats.h"

#define LGPFX "PSTAT:"

/*
 *------------------------------------------------------------------------
 *
 * File format (versioned, explicit little-endian):
 *
 *   [4 bytes] magic:   0x42 0x50 0x53 0x54  ("BPST")
 *   [1 byte]  version: 1 or 2
 *   [4 bytes] count:   uint32 LE (number of records)
 *
 * v1 records are 36 bytes:
 *   [16 bytes] ip
 *   [8 bytes]  services      uint64 LE
 *   [4 bytes]  latencyUsec   uint32 LE
 *   [4 bytes]  cfilterOk     uint32 LE
 *   [4 bytes]  cfilterFail   uint32 LE
 *
 * v2 records are 40 bytes: the same, plus
 *   [4 bytes]  avgChunkUsec  uint32 LE
 *
 * Unlike cfheader-store.c, this file has no append-order dependency --
 * peerstats_flush() rewrites it wholesale from the in-memory hashtable each
 * time -- so a v1 file is simply read with avgChunkUsec defaulted to 0 and
 * transparently rewritten as v2 on the next flush. No dual-format-writer
 * complexity needed.
 *
 *------------------------------------------------------------------------
 */

#define PSTAT_MAGIC_0    0x42
#define PSTAT_MAGIC_1    0x50
#define PSTAT_MAGIC_2    0x53
#define PSTAT_MAGIC_3    0x54
#define PSTAT_VERSION_1     1
#define PSTAT_VERSION_2     2
#define PSTAT_HEADER_SIZE   9   /* 4 magic + 1 version + 4 count */
#define PSTAT_RECORD_SIZE_1 36  /* 16 ip + 8 services + 4 lat + 4 ok + 4 fail */
#define PSTAT_RECORD_SIZE_2 40  /* v1 + 4 avgChunkUsec */

struct peerstats {
   char             *filename;
   int               fd;
   struct hashtable *hash;   /* ip[16] -> struct peerstats_entry * */
   bool              dirty;
};


static void
write_le32(uint8 *buf, uint32 val)
{
   buf[0] = (uint8)(val);
   buf[1] = (uint8)(val >> 8);
   buf[2] = (uint8)(val >> 16);
   buf[3] = (uint8)(val >> 24);
}

static uint32
read_le32(const uint8 *buf)
{
   return ((uint32)buf[0])       | ((uint32)buf[1] << 8) |
          ((uint32)buf[2] << 16) | ((uint32)buf[3] << 24);
}

static void
write_le64(uint8 *buf, uint64 val)
{
   int i;
   for (i = 0; i < 8; i++) {
      buf[i] = (uint8)(val >> (8 * i));
   }
}

static uint64
read_le64(const uint8 *buf)
{
   uint64 val = 0;
   int i;
   for (i = 0; i < 8; i++) {
      val |= ((uint64)buf[i]) << (8 * i);
   }
   return val;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_init --
 *
 *------------------------------------------------------------------------
 */
int
peerstats_init(const char *filename,
               struct peerstats **ps_out)
{
   struct peerstats *ps;
   uint8 hdr[PSTAT_HEADER_SIZE];
   ssize_t n;
   uint32 count = 0;

   *ps_out = NULL;

   ps = safe_calloc(1, sizeof *ps);
   ps->filename = safe_strdup(filename);
   ps->hash     = hashtable_create();

   ps->fd = open(filename, O_RDWR | O_CREAT, 0600);
   if (ps->fd < 0) {
      log_warn(LGPFX" cannot open '%s': %s\n", filename, strerror(errno));
      free(ps->filename);
      hashtable_destroy(ps->hash);
      free(ps);
      return 1;
   }

   n = read(ps->fd, hdr, sizeof hdr);
   if (n == (ssize_t)sizeof hdr &&
       hdr[0] == PSTAT_MAGIC_0 && hdr[1] == PSTAT_MAGIC_1 &&
       hdr[2] == PSTAT_MAGIC_2 && hdr[3] == PSTAT_MAGIC_3 &&
       (hdr[4] == PSTAT_VERSION_1 || hdr[4] == PSTAT_VERSION_2)) {
      size_t recSize = (hdr[4] == PSTAT_VERSION_2) ?
                       PSTAT_RECORD_SIZE_2 : PSTAT_RECORD_SIZE_1;
      uint32 i;

      count = read_le32(hdr + 5);
      for (i = 0; i < count; i++) {
         uint8 rec[PSTAT_RECORD_SIZE_2];
         struct peerstats_entry *e;

         n = read(ps->fd, rec, recSize);
         if (n != (ssize_t)recSize) {
            log_warn(LGPFX" truncated record %u in '%s'; stopping.\n", i, filename);
            break;
         }
         e = safe_calloc(1, sizeof *e);
         memcpy(e->ip, rec, 16);
         e->services    = read_le64(rec + 16);
         e->latencyUsec = read_le32(rec + 24);
         e->cfilterOk   = read_le32(rec + 28);
         e->cfilterFail = read_le32(rec + 32);
         e->avgChunkUsec = (recSize == PSTAT_RECORD_SIZE_2) ?
                           read_le32(rec + 36) : 0;
         if (!hashtable_insert(ps->hash, e->ip, sizeof e->ip, e)) {
            free(e);   /* duplicate IP in file; keep the first */
         }
      }
   } else if (n != 0) {
      log_warn(LGPFX" bad/truncated header in '%s'; starting fresh.\n", filename);
   }

   log_info(LGPFX" loaded %u peer stats from '%s'.\n",
       hashtable_getnumentries(ps->hash), filename);

   *ps_out = ps;
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_flush_cb --
 *
 *------------------------------------------------------------------------
 */
struct flush_ctx {
   uint8  *buf;
   uint32  idx;
};

static void
peerstats_flush_cb(const void *key,
                   size_t      keyLen,
                   void       *clientData,
                   void       *keyData)
{
   struct flush_ctx *ctx = clientData;
   const struct peerstats_entry *e = keyData;
   uint8 *rec = ctx->buf + PSTAT_HEADER_SIZE + (size_t)ctx->idx * PSTAT_RECORD_SIZE_2;

   memcpy(rec, e->ip, 16);
   write_le64(rec + 16, e->services);
   write_le32(rec + 24, e->latencyUsec);
   write_le32(rec + 28, e->cfilterOk);
   write_le32(rec + 32, e->cfilterFail);
   write_le32(rec + 36, e->avgChunkUsec);
   ctx->idx++;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_flush --
 *
 *------------------------------------------------------------------------
 */
void
peerstats_flush(struct peerstats *ps)
{
   struct flush_ctx ctx;
   uint32 count;
   size_t total;
   ssize_t n;

   if (ps == NULL || !ps->dirty) {
      return;
   }

   count = hashtable_getnumentries(ps->hash);
   total = PSTAT_HEADER_SIZE + (size_t)count * PSTAT_RECORD_SIZE_2;

   ctx.buf = safe_calloc(1, total);
   ctx.buf[0] = PSTAT_MAGIC_0;
   ctx.buf[1] = PSTAT_MAGIC_1;
   ctx.buf[2] = PSTAT_MAGIC_2;
   ctx.buf[3] = PSTAT_MAGIC_3;
   ctx.buf[4] = PSTAT_VERSION_2;
   write_le32(ctx.buf + 5, count);
   ctx.idx = 0;

   hashtable_for_each(ps->hash, peerstats_flush_cb, &ctx);

   if (lseek(ps->fd, 0, SEEK_SET) < 0) {
      log_warn(LGPFX" lseek failed: %s\n", strerror(errno));
      free(ctx.buf);
      return;
   }
   n = write(ps->fd, ctx.buf, total);
   if (n != (ssize_t)total) {
      log_warn(LGPFX" short write: %s\n", strerror(errno));
   } else {
      if (ftruncate(ps->fd, total) != 0) {
         log_warn(LGPFX" ftruncate failed: %s\n", strerror(errno));
      }
      fsync(ps->fd);
      ps->dirty = 0;
   }
   free(ctx.buf);
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_exit --
 *
 *------------------------------------------------------------------------
 */
static void
peerstats_free_entry_cb(const void *key, size_t keyLen, void *clientData)
{
   free(clientData);
}

void
peerstats_exit(struct peerstats *ps)
{
   if (ps == NULL) {
      return;
   }
   peerstats_flush(ps);
   if (ps->fd >= 0) {
      close(ps->fd);
   }
   hashtable_clear_with_callback(ps->hash, peerstats_free_entry_cb);
   hashtable_destroy(ps->hash);
   free(ps->filename);
   free(ps);
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_get_or_create --
 *
 *------------------------------------------------------------------------
 */
static struct peerstats_entry *
peerstats_get_or_create(struct peerstats *ps, const uint8 ip[16])
{
   struct peerstats_entry *e;

   if (hashtable_lookup(ps->hash, ip, 16, (void **)&e)) {
      return e;
   }
   e = safe_calloc(1, sizeof *e);
   memcpy(e->ip, ip, 16);
   hashtable_insert(ps->hash, e->ip, 16, e);
   return e;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_record_handshake --
 *
 *------------------------------------------------------------------------
 */
void
peerstats_record_handshake(struct peerstats *ps, const uint8 ip[16],
                           uint32 latencyUsec, uint64 services)
{
   struct peerstats_entry *e;

   if (ps == NULL) {
      return;
   }
   e = peerstats_get_or_create(ps, ip);
   e->latencyUsec = latencyUsec;
   e->services    = services;
   ps->dirty = 1;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_record_cfilter_ok --
 *
 *      chunkUsec is folded into a simple exponential moving average (3:1
 *      weighting toward the existing average) rather than overwritten, so
 *      one unusually fast or slow chunk doesn't swing the score wildly --
 *      it takes a handful of consistent samples to meaningfully move it,
 *      which is the point: this should reflect how the peer typically
 *      performs, not its single best or worst chunk.
 *
 *------------------------------------------------------------------------
 */
void
peerstats_record_cfilter_ok(struct peerstats *ps, const uint8 ip[16],
                            uint32 chunkUsec)
{
   struct peerstats_entry *e;

   if (ps == NULL) {
      return;
   }
   e = peerstats_get_or_create(ps, ip);
   e->cfilterOk++;
   if (chunkUsec > 0) {
      e->avgChunkUsec = (e->avgChunkUsec == 0) ? chunkUsec :
                        (uint32)(((uint64)e->avgChunkUsec * 3 + chunkUsec) / 4);
   }
   ps->dirty = 1;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_record_cfilter_fail --
 *
 *------------------------------------------------------------------------
 */
void
peerstats_record_cfilter_fail(struct peerstats *ps, const uint8 ip[16])
{
   struct peerstats_entry *e;

   if (ps == NULL) {
      return;
   }
   e = peerstats_get_or_create(ps, ip);
   e->cfilterFail++;
   ps->dirty = 1;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_lookup --
 *
 *------------------------------------------------------------------------
 */
bool
peerstats_lookup(const struct peerstats *ps, const uint8 ip[16],
                 struct peerstats_entry *out)
{
   struct peerstats_entry *e;

   if (ps == NULL || !hashtable_lookup(ps->hash, ip, 16, (void **)&e)) {
      return 0;
   }
   *out = *e;
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_score --
 *
 *------------------------------------------------------------------------
 */
int
peerstats_score(const struct peerstats_entry *e)
{
   if (e->cfilterFail > 0) {
      return -1000 - (int)e->cfilterFail;
   }
   if (e->cfilterOk == 0) {
      return 0;
   }
   if (e->avgChunkUsec == 0) {
      /* Proven ok (e.g. loaded from an older v1 stats file that predates
       * speed tracking) but no timing recorded yet. */
      return 1;
   }
   /*
    * Dominated by speed: a chunk answered in 1s outscores one answered in
    * 13s by ~12000 points, dwarfing the below success-count tiebreak (capped
    * at 50) -- so a peer used 5 times fast beats one used 200 times slow.
    * The large base keeps this positive (and thus still preferred over an
    * unknown peer) even for a proven-but-slow peer.
    */
   return 100000 - (int)(e->avgChunkUsec / 1000) + (int)MIN(e->cfilterOk, 50);
}


/*
 *------------------------------------------------------------------------
 *
 * peerstats_get_best --
 *
 *------------------------------------------------------------------------
 */
struct best_ctx {
   struct peerstats_entry *out;
   int                     maxOut;
   int                     count;
};

static void
peerstats_best_cb(const void *key, size_t keyLen, void *clientData, void *keyData)
{
   struct best_ctx *ctx = clientData;
   const struct peerstats_entry *e = keyData;
   int score = peerstats_score(e);
   int i;
   int insertAt;

   if (score <= 0) {
      return;   /* only proven-good, never-failed peers are "preferred" */
   }

   if (ctx->count < ctx->maxOut) {
      insertAt = ctx->count;
      ctx->count++;
   } else if (peerstats_score(&ctx->out[ctx->maxOut - 1]) < score) {
      insertAt = ctx->maxOut - 1;
   } else {
      return;
   }

   /* Insertion sort: shift lower-scoring entries down to make room. */
   for (i = insertAt; i > 0 && peerstats_score(&ctx->out[i - 1]) < score; i--) {
      ctx->out[i] = ctx->out[i - 1];
   }
   ctx->out[i] = *e;
}

int
peerstats_get_best(const struct peerstats *ps, int maxOut,
                   struct peerstats_entry *out)
{
   struct best_ctx ctx;

   if (ps == NULL || maxOut <= 0) {
      return 0;
   }
   ctx.out = out;
   ctx.maxOut = maxOut;
   ctx.count = 0;

   hashtable_for_each(ps->hash, peerstats_best_cb, &ctx);

   return ctx.count;
}

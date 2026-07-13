#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "basic_defs.h"
#include "util.h"
#include "hash.h"
#include "cfheader-store.h"

#define LGPFX "CFHS:"

/*
 *------------------------------------------------------------------------
 *
 * File format (versioned, explicit little-endian):
 *
 * Version 1 (legacy; always base height 0):
 *   [4 bytes] magic:   0x42 0x54 0x43 0x46  ("BTCF")
 *   [1 byte]  version: 1
 *   [4 bytes] count:   uint32 LE (number of records)
 *
 * Version 2 (adds a base height, so the chain need not start at height 0 --
 * see cfheaderstore_get_base_height):
 *   [4 bytes] magic:      0x42 0x54 0x43 0x46  ("BTCF")
 *   [1 byte]  version:    2
 *   [4 bytes] count:      uint32 LE (number of records)
 *   [4 bytes] baseHeight: int32 LE (height of the first record, or -1 if empty)
 *
 * Then `count` records, each 68 bytes, immediately following the header:
 *   [4 bytes] height:      int32 LE
 *   [32 bytes] filterHeader
 *   [32 bytes] filterHash
 *
 * An existing v1 file is read and appended to as-is (9-byte header, base
 * height 0 implied) -- it is never rewritten in v2 format in place, since
 * that would shift every record's on-disk offset. Only a brand-new (empty)
 * file is created in v2 format, which is what makes a birthday-bounded base
 * height possible.
 *
 *------------------------------------------------------------------------
 */

#define CFHS_MAGIC_0  0x42
#define CFHS_MAGIC_1  0x54
#define CFHS_MAGIC_2  0x43
#define CFHS_MAGIC_3  0x46
#define CFHS_VERSION_1       1
#define CFHS_VERSION_2       2
#define CFHS_HEADER_SIZE_V1  9   /* 4 magic + 1 version + 4 count */
#define CFHS_HEADER_SIZE_V2  13  /* 4 magic + 1 version + 4 count + 4 baseHeight */
#define CFHS_RECORD_SIZE     68  /* 4 height + 32 filterHeader + 32 filterHash */

struct cfheader_entry {
   int     height;
   uint256 filterHeader;
   uint256 filterHash;
};

struct cfheaderstore {
   char                  *filename;
   int                    fd;
   int                    headerSize;  /* CFHS_HEADER_SIZE_V1 or _V2, per the
                                         * on-disk format this file was opened
                                         * with (never changes for its lifetime) */
   int                    baseHeight;  /* height of entries[0], or -1 if empty
                                         * and not yet established (v2 only;
                                         * always 0 once any entry exists, or
                                         * for any v1 file) */
   struct cfheader_entry *entries;
   int                    count;
   int                    capacity;
};


/*
 *------------------------------------------------------------------------
 *
 * cfheader_calc --
 *
 *------------------------------------------------------------------------
 */
void
cfheader_calc(const uint256 *filterHash,
              const uint256 *prevFilterHeader,
              uint256 *out)
{
   uint8 buf[64];
   memcpy(buf, filterHash->data, 32);
   memcpy(buf + 32, prevFilterHeader->data, 32);
   hash256_calc(buf, 64, out);
}


/*
 *------------------------------------------------------------------------
 *
 * Helpers: little-endian read/write for the file header.
 *
 *------------------------------------------------------------------------
 */
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


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_write_header --
 *
 *      Rewrite the file header (magic + version + count [+ baseHeight for
 *      v2]), in the format the file was opened with (cfs->headerSize). The
 *      count (and baseHeight) fields reflect current in-memory state.
 *
 *------------------------------------------------------------------------
 */
static int
cfheaderstore_write_header(struct cfheaderstore *cfs)
{
   uint8 hdr[CFHS_HEADER_SIZE_V2];
   ssize_t n;

   hdr[0] = CFHS_MAGIC_0;
   hdr[1] = CFHS_MAGIC_1;
   hdr[2] = CFHS_MAGIC_2;
   hdr[3] = CFHS_MAGIC_3;
   hdr[4] = (cfs->headerSize == CFHS_HEADER_SIZE_V2) ?
             CFHS_VERSION_2 : CFHS_VERSION_1;
   write_le32(hdr + 5, (uint32)cfs->count);
   if (cfs->headerSize == CFHS_HEADER_SIZE_V2) {
      write_le32(hdr + 9, (uint32)cfs->baseHeight);
   }

   if (lseek(cfs->fd, 0, SEEK_SET) < 0) {
      log_warn(LGPFX" lseek failed: %s\n", strerror(errno));
      return 1;
   }
   n = write(cfs->fd, hdr, cfs->headerSize);
   if (n != (ssize_t)cfs->headerSize) {
      log_warn(LGPFX" short header write: %s\n", strerror(errno));
      return 1;
   }
   fsync(cfs->fd);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_init --
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_init(const char *filename,
                   struct cfheaderstore **cfs_out)
{
   struct cfheaderstore *cfs;
   uint8 hdr[CFHS_HEADER_SIZE_V2];
   ssize_t n;
   int res = 0;
   bool needReinit = 0;

   *cfs_out = NULL;

   cfs = safe_calloc(1, sizeof *cfs);
   cfs->filename = safe_strdup(filename);
   cfs->capacity = 1024;
   cfs->entries  = safe_calloc(cfs->capacity, sizeof *cfs->entries);
   cfs->count    = 0;

   cfs->fd = open(filename, O_RDWR | O_CREAT, 0600);
   if (cfs->fd < 0) {
      log_warn(LGPFX" cannot open '%s': %s\n", filename, strerror(errno));
      res = 1;
      goto fail;
   }

   /*
    * Read the fixed common prefix (magic + version) first, since the rest of
    * the header's layout depends on the version. New files are always
    * created in v2 format (headerSize = 13), which is what lets a birthday-
    * bounded base height be established on the first append; an existing v1
    * file is read and appended to in its original 9-byte-header format, to
    * avoid shifting every already-written record's on-disk offset.
    */
   n = read(cfs->fd, hdr, 5);
   if (n == 0) {
      /* New/empty file. */
      cfs->headerSize = CFHS_HEADER_SIZE_V2;
   } else if (n != 5 ||
              hdr[0] != CFHS_MAGIC_0 || hdr[1] != CFHS_MAGIC_1 ||
              hdr[2] != CFHS_MAGIC_2 || hdr[3] != CFHS_MAGIC_3) {
      log_warn(LGPFX" truncated or bad magic in '%s'; reinitializing.\n",
              filename);
      cfs->headerSize = CFHS_HEADER_SIZE_V2;
      needReinit = 1;
   } else if (hdr[4] == CFHS_VERSION_1) {
      cfs->headerSize = CFHS_HEADER_SIZE_V1;
   } else if (hdr[4] == CFHS_VERSION_2) {
      cfs->headerSize = CFHS_HEADER_SIZE_V2;
   } else {
      log_warn(LGPFX" bad version in '%s'; reinitializing.\n", filename);
      cfs->headerSize = CFHS_HEADER_SIZE_V2;
      needReinit = 1;
   }

   if (n == 0) {
      /* New/empty file: write the header. */
      cfs->baseHeight = -1;
      if (cfheaderstore_write_header(cfs)) {
         res = 1;
         goto fail;
      }
   } else if (needReinit) {
      cfs->count = 0;
      cfs->baseHeight = -1;
      if (cfheaderstore_write_header(cfs)) {
         res = 1;
         goto fail;
      }
   } else {
      /* Read the rest of the header (count, and baseHeight for v2). */
      int restLen = cfs->headerSize - 5;

      n = read(cfs->fd, hdr + 5, restLen);
      if (n != (ssize_t)restLen) {
         log_warn(LGPFX" truncated header in '%s'; reinitializing.\n", filename);
         cfs->headerSize = CFHS_HEADER_SIZE_V2;
         cfs->count = 0;
         cfs->baseHeight = -1;
         if (cfheaderstore_write_header(cfs)) {
            res = 1;
            goto fail;
         }
      } else {
         uint32 count = read_le32(hdr + 5);
         int i;

         cfs->count = 0;
         for (i = 0; i < (int)count; i++) {
            uint8 rec[CFHS_RECORD_SIZE];
            n = read(cfs->fd, rec, sizeof rec);
            if (n != (ssize_t)sizeof rec) {
               log_warn(LGPFX" truncated record %d in '%s'; stopping at %d.\n",
                       i, filename, cfs->count);
               break;
            }
            if (cfs->count >= cfs->capacity) {
               cfs->capacity *= 2;
               cfs->entries = safe_realloc(cfs->entries,
                                           cfs->capacity * sizeof *cfs->entries);
            }
            cfs->entries[cfs->count].height = (int)read_le32(rec);
            memcpy(cfs->entries[cfs->count].filterHeader.data, rec + 4, 32);
            memcpy(cfs->entries[cfs->count].filterHash.data, rec + 36, 32);
            cfs->count++;
         }
         /*
          * Derive baseHeight from the actual loaded data rather than trusting
          * the header field: self-corrects if the header and records ever
          * disagree (e.g. a truncated read above), and covers v1 files
          * (which have no baseHeight field at all -- always 0).
          */
         if (cfs->count > 0) {
            cfs->baseHeight = cfs->entries[0].height;
         } else if (cfs->headerSize == CFHS_HEADER_SIZE_V1) {
            cfs->baseHeight = 0;
         } else {
            cfs->baseHeight = -1;
         }
         /* If we read fewer records than the header claimed, fix the header. */
         if (cfs->count != (int)count) {
            cfheaderstore_write_header(cfs);
         }
      }
   }

   log_info(LGPFX" loaded %d filter headers from '%s' (base height %d).\n",
       cfs->count, filename, cfs->baseHeight);

   *cfs_out = cfs;
   return 0;

fail:
   cfheaderstore_exit(cfs);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_exit --
 *
 *------------------------------------------------------------------------
 */
void
cfheaderstore_exit(struct cfheaderstore *cfs)
{
   if (cfs == NULL) {
      return;
   }
   if (cfs->fd >= 0) {
      close(cfs->fd);
   }
   free(cfs->entries);
   free(cfs->filename);
   memset(cfs, 0, sizeof *cfs);
   free(cfs);
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_get_tip_height --
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_get_tip_height(const struct cfheaderstore *cfs)
{
   if (cfs == NULL || cfs->count == 0) {
      return -1;
   }
   return cfs->entries[cfs->count - 1].height;
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_get_base_height --
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_get_base_height(const struct cfheaderstore *cfs)
{
   if (cfs == NULL || cfs->count == 0) {
      return -1;
   }
   return cfs->baseHeight;
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_append --
 *
 *      Height must be tip+1 once the store has any entries. For the very
 *      first append to an empty v2 store (baseHeight == -1, unestablished),
 *      any height is accepted and becomes the store's base -- this is what
 *      lets a fresh store anchor its chain on a birthday-bounded checkpoint
 *      instead of genesis. An empty v1 store (baseHeight == 0, legacy) still
 *      requires the first append to be exactly height 0, matching its
 *      original semantics.
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_append(struct cfheaderstore *cfs, int height,
                     const uint256 *filterHeader,
                     const uint256 *filterHash)
{
   uint8 rec[CFHS_RECORD_SIZE];
   off_t offset;
   ssize_t n;

   if (cfs == NULL || filterHeader == NULL || filterHash == NULL) {
      return 1;
   }

   if (cfs->count == 0) {
      if (cfs->baseHeight >= 0 && height != cfs->baseHeight) {
         log_warn(LGPFX" first append must be height %d, got %d.\n",
                 cfs->baseHeight, height);
         return 1;
      }
      /* baseHeight == -1: unestablished v2 store; this height becomes it. */
   } else {
      if (height != cfs->entries[cfs->count - 1].height + 1) {
         log_warn(LGPFX" append height %d but expected %d.\n", height,
                 cfs->entries[cfs->count - 1].height + 1);
         return 1;
      }
   }

   /* Grow the array if needed. */
   if (cfs->count >= cfs->capacity) {
      cfs->capacity *= 2;
      cfs->entries = safe_realloc(cfs->entries,
                                  cfs->capacity * sizeof *cfs->entries);
   }

   /* Build the record. */
   write_le32(rec, (uint32)height);
   memcpy(rec + 4, filterHeader->data, 32);
   memcpy(rec + 36, filterHash->data, 32);

   /* Seek past header + existing records and write. */
   offset = cfs->headerSize + (off_t)cfs->count * CFHS_RECORD_SIZE;
   if (lseek(cfs->fd, offset, SEEK_SET) < 0) {
      log_warn(LGPFX" lseek failed: %s\n", strerror(errno));
      return 1;
   }
   n = write(cfs->fd, rec, sizeof rec);
   if (n != (ssize_t)sizeof rec) {
      log_warn(LGPFX" short record write: %s\n", strerror(errno));
      return 1;
   }
   fsync(cfs->fd);

   /* Update in-memory state. */
   if (cfs->count == 0) {
      cfs->baseHeight = height;
   }
   cfs->entries[cfs->count].height        = height;
   cfs->entries[cfs->count].filterHeader  = *filterHeader;
   cfs->entries[cfs->count].filterHash    = *filterHash;
   cfs->count++;

   /* Update the count (and baseHeight, for v2) in the file header. */
   return cfheaderstore_write_header(cfs);
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_get_header --
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_get_header(const struct cfheaderstore *cfs, int height,
                          uint256 *filterHeader)
{
   int idx;

   if (cfs == NULL || filterHeader == NULL || cfs->count == 0) {
      return 1;
   }
   idx = height - cfs->baseHeight;
   if (idx < 0 || idx >= cfs->count) {
      return 1;
   }
   *filterHeader = cfs->entries[idx].filterHeader;
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * cfheaderstore_get_hash --
 *
 *------------------------------------------------------------------------
 */
int
cfheaderstore_get_hash(const struct cfheaderstore *cfs, int height,
                       uint256 *filterHash)
{
   int idx;

   if (cfs == NULL || filterHash == NULL || cfs->count == 0) {
      return 1;
   }
   idx = height - cfs->baseHeight;
   if (idx < 0 || idx >= cfs->count) {
      return 1;
   }
   *filterHash = cfs->entries[idx].filterHash;
   return 0;
}

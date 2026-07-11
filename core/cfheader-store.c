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
 *   [4 bytes] magic:   0x42 0x54 0x43 0x46  ("BTCF")
 *   [1 byte]  version: 1
 *   [4 bytes] count:   uint32 LE (number of records)
 *
 * Then `count` records, each 68 bytes:
 *   [4 bytes] height:      int32 LE
 *   [32 bytes] filterHeader
 *   [32 bytes] filterHash
 *
 *------------------------------------------------------------------------
 */

#define CFHS_MAGIC_0  0x42
#define CFHS_MAGIC_1  0x54
#define CFHS_MAGIC_2  0x43
#define CFHS_MAGIC_3  0x46
#define CFHS_VERSION  1
#define CFHS_HEADER_SIZE 9  /* 4 magic + 1 version + 4 count */
#define CFHS_RECORD_SIZE 68 /* 4 height + 32 filterHeader + 32 filterHash */

struct cfheader_entry {
   int     height;
   uint256 filterHeader;
   uint256 filterHash;
};

struct cfheaderstore {
   char                  *filename;
   int                    fd;
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
 *      Rewrite the file header (magic + version + count). The count field
 *      reflects the current number of records.
 *
 *------------------------------------------------------------------------
 */
static int
cfheaderstore_write_header(struct cfheaderstore *cfs)
{
   uint8 hdr[CFHS_HEADER_SIZE];
   ssize_t n;

   hdr[0] = CFHS_MAGIC_0;
   hdr[1] = CFHS_MAGIC_1;
   hdr[2] = CFHS_MAGIC_2;
   hdr[3] = CFHS_MAGIC_3;
   hdr[4] = CFHS_VERSION;
   write_le32(hdr + 5, (uint32)cfs->count);

   if (lseek(cfs->fd, 0, SEEK_SET) < 0) {
      Warning(LGPFX" lseek failed: %s\n", strerror(errno));
      return 1;
   }
   n = write(cfs->fd, hdr, sizeof hdr);
   if (n != (ssize_t)sizeof hdr) {
      Warning(LGPFX" short header write: %s\n", strerror(errno));
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
   uint8 hdr[CFHS_HEADER_SIZE];
   ssize_t n;
   int res = 0;

   *cfs_out = NULL;

   cfs = safe_calloc(1, sizeof *cfs);
   cfs->filename = safe_strdup(filename);
   cfs->capacity = 1024;
   cfs->entries  = safe_calloc(cfs->capacity, sizeof *cfs->entries);
   cfs->count    = 0;

   cfs->fd = open(filename, O_RDWR | O_CREAT, 0600);
   if (cfs->fd < 0) {
      Warning(LGPFX" cannot open '%s': %s\n", filename, strerror(errno));
      res = 1;
      goto fail;
   }

   /* Read the header. */
   n = read(cfs->fd, hdr, sizeof hdr);
   if (n == 0) {
      /* New/empty file: write the header. */
      if (cfheaderstore_write_header(cfs)) {
         res = 1;
         goto fail;
      }
   } else if (n != (ssize_t)sizeof hdr) {
      Warning(LGPFX" truncated header in '%s'; reinitializing.\n", filename);
      cfs->count = 0;
      if (cfheaderstore_write_header(cfs)) {
         res = 1;
         goto fail;
      }
   } else {
      /* Validate magic and version. */
      if (hdr[0] != CFHS_MAGIC_0 || hdr[1] != CFHS_MAGIC_1 ||
          hdr[2] != CFHS_MAGIC_2 || hdr[3] != CFHS_MAGIC_3 ||
          hdr[4] != CFHS_VERSION) {
         Warning(LGPFX" bad magic/version in '%s'; reinitializing.\n", filename);
         cfs->count = 0;
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
               Warning(LGPFX" truncated record %d in '%s'; stopping at %d.\n",
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
         /* If we read fewer records than the header claimed, fix the header. */
         if (cfs->count != (int)count) {
            cfheaderstore_write_header(cfs);
         }
      }
   }

   Log(LGPFX" loaded %d filter headers from '%s'.\n", cfs->count, filename);

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
 * cfheaderstore_append --
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

   /* Internal invariant: height must be tip+1 (or 0 if empty). */
   if (cfs->count == 0) {
      if (height != 0) {
         Warning(LGPFX" first append must be height 0, got %d.\n", height);
         return 1;
      }
   } else {
      if (height != cfs->entries[cfs->count - 1].height + 1) {
         Warning(LGPFX" append height %d but expected %d.\n", height,
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
   offset = CFHS_HEADER_SIZE + (off_t)cfs->count * CFHS_RECORD_SIZE;
   if (lseek(cfs->fd, offset, SEEK_SET) < 0) {
      Warning(LGPFX" lseek failed: %s\n", strerror(errno));
      return 1;
   }
   n = write(cfs->fd, rec, sizeof rec);
   if (n != (ssize_t)sizeof rec) {
      Warning(LGPFX" short record write: %s\n", strerror(errno));
      return 1;
   }
   fsync(cfs->fd);

   /* Update in-memory state. */
   cfs->entries[cfs->count].height        = height;
   cfs->entries[cfs->count].filterHeader  = *filterHeader;
   cfs->entries[cfs->count].filterHash    = *filterHash;
   cfs->count++;

   /* Update the count in the file header. */
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
   if (cfs == NULL || filterHeader == NULL) {
      return 1;
   }
   if (height < 0 || height >= cfs->count) {
      return 1;
   }
   *filterHeader = cfs->entries[height].filterHeader;
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
   if (cfs == NULL || filterHash == NULL) {
      return 1;
   }
   if (height < 0 || height >= cfs->count) {
      return 1;
   }
   *filterHash = cfs->entries[height].filterHash;
   return 0;
}

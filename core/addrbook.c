#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "addrbook.h"
#include "util.h"
#include "config.h"
#include "bitc-defs.h"
#include "bitc.h"
#include "hashtable.h"
#include "file.h"

#define LGPFX "ADDR:"


struct addrbook {
   struct file_descriptor *desc;
   struct hashtable       *hash_addr;
   char                   *filename;
   int                     unsaved;
};


struct savebook {
   btc_msg_address *addrs;
   int              idx;
};



/*
 *------------------------------------------------------------------------
 *
 * addrbook_add_entry_int --
 *
 *------------------------------------------------------------------------
 */

static bool
addrbook_add_entry_int(struct addrbook *book,
                       struct peer_addr *paddr)
{
   return hashtable_insert(book->hash_addr, paddr->addr.ip,
                           sizeof paddr->addr.ip, paddr);
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_get_count --
 *
 *------------------------------------------------------------------------
 */

uint32
addrbook_get_count(const struct addrbook *book)
{
   return hashtable_getnumentries(book->hash_addr);
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_replace_entry --
 *
 *------------------------------------------------------------------------
 */

void
addrbook_replace_entry(struct addrbook *book,
                       struct peer_addr *paddr)
{
   struct peer_addr *paddr0;
   bool s;

   s = hashtable_lookup(book->hash_addr, paddr->addr.ip,
                        sizeof paddr->addr.ip, (void*)&paddr0);
   ASSERT(s);
   addrbook_remove_entry(book, paddr0);
   free(paddr0);
   s = addrbook_add_entry(book, paddr);
   ASSERT(s);
}

/*
 *------------------------------------------------------------------------
 *
 * addrbook_remove_entry --
 *
 *------------------------------------------------------------------------
 */

void
addrbook_remove_entry(struct addrbook *book,
                      const struct peer_addr *paddr)
{
   bool s;

   s = hashtable_remove(book->hash_addr, paddr->addr.ip,
                        sizeof paddr->addr.ip);
   ASSERT(s);
}


/*
 *-------------------------------------------------------------------------
 *
 * addrbook_get_rand_addr --
 *
 *-------------------------------------------------------------------------
 */

struct peer_addr *
addrbook_get_rand_addr(const struct addrbook *book)
{
   struct peer_addr *addr;
   const uint8 *key;
   size_t keyLen;
   uint32 count;
   uint32 idx;

   count = addrbook_get_count(book);
   if (count == 0) {
      return NULL;
   }

   idx = random() % count;

   addr = NULL;
   key = NULL;
   keyLen = 0;

   hashtable_get_entry_idx(book->hash_addr, idx, (void *)&key,
                           &keyLen, (void**)&addr);

   ASSERT(addr);
   ASSERT(key);
   ASSERT(keyLen == 16);

   return addr;
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_get_path --
 *
 *------------------------------------------------------------------------
 */

static char *
addrbook_get_path(struct config *config)
{
   char path[PATH_MAX];
   char *dir;

   dir = bitc_get_directory();
   snprintf(path, sizeof path, "%s/peers.dat", dir);
   free(dir);

   return config_getstring(config, path, "peers.filename");
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_open --
 *
 *------------------------------------------------------------------------
 */

int
addrbook_open(struct config *config,
              struct addrbook **bookOut)
{
   struct addrbook *book;
   uint64 offset;
   int64 size;
   int res;

   book = safe_malloc(sizeof *book);
   book->hash_addr = hashtable_create();
   book->filename  = addrbook_get_path(config);
   book->unsaved   = 0;

   if (!file_exists(book->filename)) {
      log_warn(LGPFX" creating new addrbook: %s.\n", book->filename);
      res = file_create(book->filename);
      if (res != 0) {
         log_warn(LGPFX" failed to create new addrbook: %s.\n",
                 strerror(res));
         goto exit;
      }
      res = file_chmod(book->filename, 0600);
      if (res != 0) {
         log_warn(LGPFX" failed to chmod 0600 addrbook: %s.\n",
                 strerror(res));
         goto exit;
      }
   }

   res = file_open(book->filename, 0, 0, &book->desc);
   if (res) {
      log_warn(LGPFX" failed to open addrbook '%s' : %s\n",
              book->filename, strerror(res));
      goto exit;
   }

   size = file_getsize(book->desc);
   if (size < 0) {
      return errno;
   }

   if (size > 0) {
      char *s = print_size(size);
      char *name = file_getname(book->filename);

      log_warn(LGPFX" reading file %s -- %s -- %llu addrs.\n",
              name, s, size / sizeof(btc_msg_address));
      free(name);
      free(s);
   }

   offset = 0;
   while (offset < size) {
      btc_msg_address buf[10000];
      size_t numRead;
      size_t numBytes;
      int numAddrs;
      int i;

      numBytes = MIN(size - offset, sizeof buf);

      res = file_pread(book->desc, offset, buf, numBytes, &numRead);
      if (res != 0) {
         break;
      }
      numAddrs = numRead / sizeof(btc_msg_address);
      for (i = 0; i < numAddrs; i++) {
         struct peer_addr *a = safe_calloc(1, sizeof *a);
         bool s;

         memcpy(&a->addr, buf + i, sizeof(btc_msg_address));
         s = addrbook_add_entry_int(book, a);
         ASSERT(s);
      }

      offset += numRead;
   }

   *bookOut = book;
exit:
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_zap --
 *
 *------------------------------------------------------------------------
 */

void
addrbook_zap(struct config *config)
{
   char *filename;

   filename = addrbook_get_path(config);

   if (file_exists(filename)) {
      log_warn(LGPFX" removing addrbook '%s'.\n", filename);
      file_unlink(filename);
   }
   free(filename);
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_save --
 *
 *------------------------------------------------------------------------
 */

static int
addrbook_save(struct addrbook *book)
{
   btc_msg_address *addrs = NULL;
   size_t numWritten;
   size_t len;
   uint32 count;
   int res;

   count = addrbook_get_count(book);
   ASSERT(count > 0);

   hashtable_linearize(book->hash_addr, sizeof(btc_msg_address), (void *)&addrs);
   ASSERT(addrs);
   len = count * sizeof *addrs;

   res = file_truncate(book->desc, 0);
   if (res != 0) {
      log_warn(LGPFX" failed to truncate addrbook: %s\n",
              strerror(res));
   }

   log_info(LGPFX" saving %u addr.\n", count);

   res = file_pwrite(book->desc, 0, addrs, len, &numWritten);
   if (res || numWritten != len) {
      log_warn(LGPFX" Failed to write addrbook: %s\n",
              strerror(res));
   } else {
      book->unsaved = 0;
   }

   free(addrs);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_close --
 *
 *------------------------------------------------------------------------
 */

int
addrbook_close(struct addrbook *book)
{
   if (book == NULL) {
      return 0;
   }
   if (book->unsaved > 0) {
      addrbook_save(book);
   }
   file_close(book->desc);
   hashtable_printstats(book->hash_addr, "addr");
   hashtable_clear_with_free(book->hash_addr);
   hashtable_destroy(book->hash_addr);
   free(book->filename);
   free(book);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * addrbook_add_entry --
 *
 *------------------------------------------------------------------------
 */

bool
addrbook_add_entry(struct addrbook *book,
                   struct peer_addr *paddr)
{
   bool s;

   s = addrbook_add_entry_int(book, paddr);
   if (s == 0) {
      return 0;
   }

   book->unsaved++;
   if (book->unsaved >= 1000) {
      addrbook_save(book);
   }
   return s;
}

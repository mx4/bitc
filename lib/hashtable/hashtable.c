#include <stdlib.h>
#include <string.h>

#include "basic_defs.h"
#include "util.h"
#include "hashtable.h"
#include "MurmurHash3.h"

#define LGPFX "HASH:"

static bool verbose = 0;

#define HASH_DEFAULT_NUM_BUCKETS        256
#define HASH_DEFAULT_FACTOR             4

struct hashtable_linearize_info {
   void         *buf;
   size_t       entry_size;
   size_t       idx;
};

struct hashtable_entry {
   struct hashtable_entry  *next;
   void                    *clientData;
   size_t                   keyLen;
   uint8                    key[];
};


struct hashtable {
   uint32                   numBuckets;
   uint32                   count;
   uint8                    numBits;
   struct hashtable_entry **buckets;
};


/*
 *---------------------------------------------------------------------
 *
 * hashtable_printstats --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_printstats(const struct hashtable *ht,
                     const char *pfx)
{
   uint32 count = hashtable_getnumentries(ht);
   uint32 depth = hashtable_getmaxdepth(ht);
   uint32 empty = hashtable_getemptybuckets(ht);

   if (count == 0) {
      return;
   }

   Log("HASH %s: count=%u maxdepth=%u empty=%u\n",
       pfx, count, depth, empty);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_compute_hash --
 *
 *      http://murmurhash.googlepages.com/
 *
 *---------------------------------------------------------------------
 */

static uint32
hashtable_compute_hash(uint32 numBuckets,
                       uint8 numBits,
                       const void *key,
                       size_t keyLen)
{
   uint32 mask;
   uint32 h;

   h = MurmurHash3(key, keyLen, 0x5678);
   mask = numBuckets - 1;

   while (h > mask) {
      h = (h & mask) ^ (h >> numBits);
   }
   ASSERT(h < numBuckets);
   return h;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_getemptybuckets --
 *
 *---------------------------------------------------------------------
 */

uint32
hashtable_getemptybuckets(const struct hashtable *ht)
{
   uint32 count = 0;
   uint32 i;

   for (i = 0; i < ht->numBuckets; i++) {
      if (ht->buckets[i] == 0) {
         count++;
      }
   }
   return count;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_getmaxdepth --
 *
 *---------------------------------------------------------------------
 */

uint32
hashtable_getmaxdepth(const struct hashtable *ht)
{
   uint32 depth = 0;
   uint32 i;

   for (i = 0; i < ht->numBuckets; i++) {
      const struct hashtable_entry *e = ht->buckets[i];
      uint32 count = 0;

      while (e) {
         e = e->next;
         count++;
      }
      depth = MAX(depth, count);
   }
   return depth;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_getnumentries --
 *
 *---------------------------------------------------------------------
 */

uint32
hashtable_getnumentries(const struct hashtable *ht)
{
   return ht->count;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_get_entry_idx --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_get_entry_idx(const struct hashtable *ht,
                        size_t idx,
                        const void **key,
                        size_t *keyLen,
                        void **clientData)
{
   uint32 count;
   uint32 i;

   if (idx > ht->count) {
      *key = NULL;
      *keyLen = 0;
      *clientData = NULL;
      return;
   }

   count = 0;
   for (i = 0; i < ht->numBuckets; i++) {
      struct hashtable_entry *e = ht->buckets[i];
      while (e) {
         if (count == idx) {
            *key        = e->key;
            *keyLen     = e->keyLen;
            *clientData = e->clientData;
            return;
         }
         count++;
         e = e->next;
      }
   }
   Panic("Should not get here.\n");
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_lookup_entry --
 *
 *---------------------------------------------------------------------
 */

static struct hashtable_entry *
hashtable_lookup_entry(const struct hashtable *ht,
                       uint32 hash,
                       const void *key,
                       size_t keyLen)
{
   struct hashtable_entry *e;

   e = ht->buckets[hash];
   while (e) {
      if (keyLen == e->keyLen && memcmp(key, e->key, keyLen) == 0) {
         return e;
      }
      e = e->next;
   }
   return NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_lookup --
 *
 *---------------------------------------------------------------------
 */

bool
hashtable_lookup(const struct hashtable *ht,
                 const void *key,
                 size_t keyLen,
                 void **clientData)
{
   struct hashtable_entry *e;
   uint32 hash;

   hash = hashtable_compute_hash(ht->numBuckets, ht->numBits, key, keyLen);

   e = hashtable_lookup_entry(ht, hash, key, keyLen);
   if (e && clientData) {
      *clientData = e->clientData;
   }
   return e != NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_check_resize --
 *
 *---------------------------------------------------------------------
 */

static void
hashtable_check_resize(struct hashtable *ht)
{
   struct hashtable_entry **buckets;
   uint32 numBuckets = ht->numBuckets;
   uint8 numBits;
   uint32 i;

   if (ht->count >  HASH_DEFAULT_FACTOR * ht->numBuckets) {
      numBuckets *= HASH_DEFAULT_FACTOR;
   } else if (ht->count < ht->numBuckets / HASH_DEFAULT_FACTOR) {
      numBuckets /= HASH_DEFAULT_FACTOR;
   }
   if (numBuckets <= HASH_DEFAULT_NUM_BUCKETS) {
      return;
   }
   if (numBuckets == ht->numBuckets) {
      return;
   }

   LOG(1, (LGPFX" resizing: %u -> %u buckets.\n", ht->numBuckets, numBuckets));

   buckets = safe_calloc(numBuckets, sizeof *buckets);
   numBits = util_log2(numBuckets);

   for (i = 0; i < ht->numBuckets; i++) {
      struct hashtable_entry *e = ht->buckets[i];
      ht->buckets[i] = NULL;
      while (e) {
         struct hashtable_entry *next;
         uint32 hash;

         next = e->next;
         hash = hashtable_compute_hash(numBuckets, numBits, e->key, e->keyLen);
         e->next = buckets[hash];
         buckets[hash] = e;
         e = next;
      }
   }
   free(ht->buckets);
   ht->numBits = numBits;
   ht->buckets = buckets;
   ht->numBuckets = numBuckets;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_insert --
 *
 *---------------------------------------------------------------------
 */

bool
hashtable_insert(struct hashtable *ht,
                 const void *key,
                 size_t keyLen,
                 void *clientData)
{
   struct hashtable_entry *e;
   uint32 hash;

   hashtable_check_resize(ht);

   hash = hashtable_compute_hash(ht->numBuckets, ht->numBits, key, keyLen);

   e = hashtable_lookup_entry(ht, hash, key, keyLen);
   if (e) {
      return 0;
   }

   e = safe_malloc(sizeof *e + keyLen);
   e->keyLen     = keyLen;
   e->clientData = clientData;
   e->next       = ht->buckets[hash];
   memcpy(e->key, key, keyLen);

   ht->buckets[hash] = e;
   ht->count++;

   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_create --
 *
 *---------------------------------------------------------------------
 */

struct hashtable *
hashtable_create(void)
{
   struct hashtable *ht;

   ht = safe_calloc(1, sizeof *ht);
   ht->numBuckets = HASH_DEFAULT_NUM_BUCKETS;
   ht->numBits    = util_log2(ht->numBuckets);
   ht->buckets    = safe_calloc(ht->numBuckets, sizeof *ht->buckets);

   ASSERT((ht->numBuckets & (ht->numBuckets - 1)) == 0);

   return ht;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_for_each --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_for_each(const struct hashtable *ht,
                   hashtable_for_each_callback callback,
                   void *callbackData)
{
   uint32 i;

   ASSERT(callback);

   for (i = 0; i < ht->numBuckets; i++) {
      struct hashtable_entry *e = ht->buckets[i];
      while (e) {
         struct hashtable_entry *next = e->next;
         callback(e->key, e->keyLen, callbackData, e->clientData);
         e = next;
      }
   }
}



/*
 *---------------------------------------------------------------------
 *
 * hashtable_clear_with_callback --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_clear_with_callback(struct hashtable *ht,
                              hashtable_callback callback)
{
   uint32 i;

   for (i = 0; i < ht->numBuckets; i++) {
      struct hashtable_entry *e = ht->buckets[i];
      ht->buckets[i] = NULL;
      while (e) {
         struct hashtable_entry *next = e->next;
         if (callback) {
            callback(e->key, e->keyLen, e->clientData);
         }
         free(e);
         e = next;
         ht->count--;
      }
   }
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_free_clientdata --
 *
 *---------------------------------------------------------------------
 */

static void
hashtable_free_clientdata(const void *key,
                          size_t keyLen,
                          void *clientData)
{
   free(clientData);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_clear_with_free --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_clear_with_free(struct hashtable *ht)
{
   hashtable_clear_with_callback(ht, hashtable_free_clientdata);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_clear --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_clear(struct hashtable *ht)
{
   hashtable_clear_with_callback(ht, NULL);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_free --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_destroy(struct hashtable *ht)
{
   ASSERT(ht->count == 0);
   hashtable_clear(ht);
   free(ht->buckets);
   free(ht);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_remove --
 *
 *---------------------------------------------------------------------
 */

bool
hashtable_remove(struct hashtable *ht,
                 const void *key,
                 size_t keyLen)
{
   struct hashtable_entry *entry;
   struct hashtable_entry *prev;
   struct hashtable_entry *e;
   uint32 hash;

   hashtable_check_resize(ht);

   hash = hashtable_compute_hash(ht->numBuckets, ht->numBits, key, keyLen);

   entry = hashtable_lookup_entry(ht, hash, key, keyLen);
   if (entry == NULL) {
      return 0;
   }
   e = ht->buckets[hash];
   ASSERT(e);
   prev = NULL;
   while (e) {
      if (e == entry) {
         if (prev) {
            prev->next = e->next;
         } else {
            ht->buckets[hash] = e->next;
         }
         free(e);
         ht->count--;
         return 1;
      }
      prev = e;
      e = e->next;
   }
   Panic("failed to remove entry.\n");
   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_insert_test --
 *
 *---------------------------------------------------------------------
 */

void
hashtable_insert_test(uint32 n,
                      volatile int *stop)
{
   struct hashtable *ht = hashtable_create();
   uint32 i;
   bool s;

   Warning(LGPFX" adding %u entries.\n", n);
   for (i = 0; *stop == 0 && i < n; i++) {
      //uint32 r = random() % (1024 * 1024);
      uint32 r = i;
      s = hashtable_insert(ht, &r, sizeof r, NULL);
      ASSERT(s);
   }
   Warning(LGPFX" stats: numEntries=%u maxDepth=%u emptyBuckets=%u\n",
           hashtable_getnumentries(ht),
           hashtable_getmaxdepth(ht),
           hashtable_getemptybuckets(ht));

   Warning(LGPFX" removing %u entries.\n",
           hashtable_getnumentries(ht));

   for (i = 0; *stop == 0 && i < n; i++) {
      s = hashtable_remove(ht, (uint8 *)&i, sizeof i);
      ASSERT(s);
   }
   hashtable_clear(ht);
   hashtable_destroy(ht);
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_linearize_cb --
 *
 *---------------------------------------------------------------------
 */

static void
hashtable_linearize_cb(const void *key,
                       size_t      keyLen,
                       void       *cbData,
                       void       *keyData)
{
   struct hashtable_linearize_info *info = (struct hashtable_linearize_info*)cbData;

   memcpy((uint8*)info->buf + info->idx * info->entry_size, keyData, info->entry_size);
   info->idx++;
}


/*
 *---------------------------------------------------------------------
 *
 * hashtable_linearize --
 *
 *      NB: we could be smarter here. Instead of full-copying the key-data, we
 *      could just build an array of pointers to those key-data.
 *
 *---------------------------------------------------------------------
 */

void
hashtable_linearize(const struct hashtable *ht,
                    size_t entry_size,
                    void **ptr)
{
   struct hashtable_linearize_info info;
   int n;

   n = hashtable_getnumentries(ht);
   if (n == 0) {
      *ptr = NULL;
      return;
   }

   info.buf = safe_malloc(n * entry_size);
   info.entry_size = entry_size;
   info.idx = 0;

   hashtable_for_each(ht, hashtable_linearize_cb, &info);

   *ptr = info.buf;
}

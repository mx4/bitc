#pragma once

#include "basic_defs.h"


struct hashtable;

typedef void (hashtable_callback)(const void *key, size_t keyLen,
                                  void *clientData);
typedef void (hashtable_for_each_callback)(const void *key, size_t keyLen,
                                           void *cbData, void *keyData);

struct hashtable *hashtable_create(void);

void hashtable_clear(struct hashtable *ht);
void hashtable_clear_with_free(struct hashtable *ht);
void hashtable_clear_with_callback(struct hashtable *ht,
                                   hashtable_callback callback);
void hashtable_destroy(struct hashtable *ht);
void hashtable_insert_test(uint32 n, volatile int *stop);
void hashtable_printstats(const struct hashtable *ht, const char *pfx);

uint32 hashtable_getnumentries(const struct hashtable *ht);
uint32 hashtable_getmaxdepth(const struct hashtable *ht);
uint32 hashtable_getemptybuckets(const struct hashtable *ht);

void hashtable_for_each(const struct hashtable *ht,
                        hashtable_for_each_callback callback,
                        void *clientdata);

bool hashtable_lookup(const struct hashtable *ht,
                      const void *key,
                      size_t keyLen,
                      void **clientData);
bool hashtable_insert(struct hashtable *ht,
                      const void *key,
                      size_t keyLen,
                      void *clientData);
bool hashtable_remove(struct hashtable *ht,
                      const void *key,
                      size_t keyLen);
void hashtable_get_entry_idx(const struct hashtable *ht,
                             size_t idx,
                             const void **key,
                             size_t *keyLen,
                             void **clientData);
void hashtable_linearize(const struct hashtable *ht,
                         size_t entry_size, void **ptr);



#include <stdio.h>
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/rand.h>

#include "key.h"
#include "wallet.h"
#include "buff.h"
#include "hash.h"
#include "util.h"
#include "bitc.h"
#include "serialize.h"
#include "block-store.h"
#include "crypt.h"
#include "hashtable.h"
#include "poolworker.h"
#include "test.h"

#define LGPFX "TEST:"


/*
 *---------------------------------------------------------------------
 *
 * bitc_test_one_tx --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_test_one_tx(struct btc_tx_desc *desc)
{
   struct btc_msg_tx tx;
   uint256 hash;
   struct buff *buf;
   int res;
   int i;

   desc->total_value = 0;
   desc->fee = 0;
   for (i = 0; i < desc->num_addr; i++) {
      desc->total_value += desc->dst[i].value;
      log_info(LGPFX" -- %.8f BTC to %s\n",
          desc->dst[i].value / ONE_BTC, desc->dst[i].addr);
   }

   log_info(LGPFX" sending %.8f BTC total\n",
       desc->total_value / ONE_BTC);

   res = wallet_craft_tx(btc->wallet, desc, &tx);

   ASSERT(btc_msg_tx_value(&tx) >= desc->total_value);

   buf = buff_alloc();
   res = serialize_tx(buf, &tx);
   ASSERT(res == 0);

   hash256_calc(buff_base(buf), buff_curlen(buf), &hash);

   log_info("TX: %s\n", uint256_to_str(&hash));

   ASSERT(res == 0);
   buff_free(buf);

   btc_msg_tx_free(&tx);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_test_tx --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_test_tx(void)
{
   struct btc_tx_desc desc;
   const char *errStr = NULL;
   int res;
   int i;

   res = blockstore_init(btc->config, &btc->blockStore);
   ASSERT(res == 0);
   res = wallet_open(btc->config, NULL, &errStr, &btc->wallet);
   ASSERT(res == 0);

   strcpy(desc.label, "test");

   for (i = 0; i < 4; i++) {
      desc.num_addr     = 1 + i;
      desc.total_value  = 0; /* will be filled out */
      desc.dst[i].value = 1000 * (i + 1);
      strcpy(desc.dst[i].addr, "1GaeWvR4QkFx5A8LzhKzbuCDdUwFedRXwZ");

      bitc_test_one_tx(&desc);
   }

   wallet_close(btc->wallet);
   blockstore_exit(btc->blockStore);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_pool_test --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_pool_test(void)
{
   struct poolworker_state *pw;
   int numIterations = 5;
   int numThreads = 500;
   int i;

   for (i = 0; i < numIterations; i++) {
      printf("Creating %u threads.\n", numThreads);
      pw = poolworker_create(numThreads);
      printf("Destroying %u threads.\n", numThreads);
      poolworker_destroy(pw);
   }
   printf("Done.\n");
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_crypt_test --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_crypt_test(void)
{
   static const char *password = "f00b4r!";
   static const char *cleartext =
      "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
   struct crypt_key k;
   char str[16384];
   uint8 *cipher = NULL;
   size_t clen = 0;
   bool s;
   struct secure_area *sec;
   struct secure_area *dec;
   struct secure_area *pass;
   int64 count = 0;

   pass = secure_alloc(strlen(password) + 1);
   memcpy(pass->buf, password, strlen(password) + 1);

   RAND_bytes(k.salt, sizeof k.salt);

   sec = secure_alloc(strlen(cleartext) + 1);
   memcpy(sec->buf, cleartext, strlen(cleartext) + 1);


   s = crypt_set_key_from_passphrase(pass, &k, &count);
   ASSERT(s);

   printf("num_iterations = %lld\n", (long long)count);

   s = crypt_encrypt(&k, sec, &cipher, &clen);
   ASSERT(s);

   str_snprintf_bytes(str, sizeof str, "encrypted: ", cipher, clen);
   printf("%s (%zu)\n", str, clen);

   s = crypt_decrypt(&k, cipher, clen, &dec);
   ASSERT(s);

   printf("decrypted: '%s' (%zu vs %zu)\n", dec->buf, dec->len, strlen(cleartext) + 1);

   ASSERT(dec->len == strlen(cleartext) + 1);
   ASSERT(strcmp((char*)dec->buf, cleartext) == 0);

   secure_free(pass);
   secure_free(sec);
   secure_free(dec);
   free(cipher);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_hashtable_test --
 *
 *---------------------------------------------------------------------
 */

static void
bitc_hashtable_test(void)
{
   hashtable_insert_test(100000, &btc->stop);
}


/*
 *---------------------------------------------------------------------
 *
 * bitc_test --
 *
 *---------------------------------------------------------------------
 */

int
bitc_test(const char *str)
{
   bool pool;
   bool crypt;
   bool hash;
   bool tx;

   bitc_testing = 1;

   hash  = str && strcmp(str, "hash") == 0;
   tx    = str && strcmp(str, "tx") == 0;
   crypt = str && strcmp(str, "crypt") == 0;
   pool  = str && strcmp(str, "pool") == 0;

   if (crypt == 0 && tx == 0 && hash == 0 && pool == 0) {
      crypt = 1;
      tx = 1;
      pool = 1;
      hash = 1;
   }

   if (hash) {
      bitc_hashtable_test();
   }
   if (tx) {
      bitc_test_tx();
   }
   if (crypt) {
      bitc_crypt_test();
   }
   if (pool) {
      bitc_pool_test();
   }

   return 0;
}

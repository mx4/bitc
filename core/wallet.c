#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/rand.h>
#include <openssl/err.h>

#include "bitc-defs.h"
#include "util.h"
#include "wallet.h"
#include "file.h"
#include "key.h"
#include "base58.h"
#include "config.h"
#include "txdb.h"
#include "hash.h"
#include "bloom.h"
#include "bitc_ui.h"
#include "btc-message.h"
#include "hashtable.h"
#include "crypt.h"
#include "bitc.h"

#define LGPFX "WALLET:"


struct wallet_key {
   struct key  *key;
   time_t       birth;
   char        *desc;
   char        *btc_addr;
   uint8       *pub;
   size_t       pubLen;
   uint160      pub_key;
   uint32       cfg_idx;
   bool         spendable;
};


struct wallet {
   char                   *filename;
   struct txdb            *txdb;
   struct hashtable       *hash_keys;
   uint64                  balance;

   struct secure_area     *pass;
   struct crypt_key       *ckey;
   struct secure_area     *ckey_store;
   struct bloom_filter    *filter;
};


struct wallet_find_data {
   struct wallet_key *wkey;
   uint32             cfg_idx;
};


/*
 *------------------------------------------------------------------------
 *
 * wallet_get_filename --
 *
 *------------------------------------------------------------------------
 */

char *
wallet_get_filename(void)
{
   char str[256];
   char *dir;

   dir = bitc_get_directory();
   snprintf(str, sizeof str, "%s/wallet.cfg", dir);
   free(dir);

   return config_getstring(btc->config, str, "wallet.filename");
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_zap_txdb --
 *
 *------------------------------------------------------------------------
 */

int
wallet_zap_txdb(struct config *config)
{
   return txdb_zap(config);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_has_tx --
 *
 *------------------------------------------------------------------------
 */

bool
wallet_has_tx(struct wallet *wlt,
              const uint256 *txHash)
{
   return txdb_has_tx(wlt->txdb, txHash);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_handle_tx --
 *
 *------------------------------------------------------------------------
 */

int
wallet_handle_tx(struct wallet *wlt,
                 const uint256 *blkHash,
                 const uint8 *buf,
                 size_t len)
{
   bool relevant = 0;
   int res;

   res = txdb_handle_tx(wlt->txdb, blkHash, buf, len, &relevant);

   if (res == 0 && relevant) {
      /*
       * One or more updates were made to the set of known txos and likely
       * affected the balance of the account.
       */
      wlt->balance = txdb_get_balance(wlt->txdb);
   }

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_print_key_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_print_key_cb(const void *key,
                    size_t keyLen,
                    void *cbData,
                    void *keyData)
{
   struct wallet_key *wkey = (struct wallet_key *)keyData;
   char *ts;

   ASSERT(wkey->btc_addr);

   ts = print_time_utc(wkey->birth);
   Log(LGPFX" -- %s -- %s -- %s\n",
       wkey->btc_addr, ts, wkey->desc ? wkey->desc : "");
   free(ts);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_print --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_print(struct wallet *wallet)
{
   hashtable_for_each(wallet->hash_keys, wallet_print_key_cb, NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_verify_hmac --
 *
 *------------------------------------------------------------------------
 */

static bool
wallet_verify_hmac(const struct wallet *wallet,
                   const char          *privStr,
                   uint8              **encPrivKey,
                   size_t              *encLen)
{
   uint8 *hash;
   size_t hash_len;
   uint8 *key;
   size_t key_len;
   uint256 mac;
   size_t len;
   char *macStr;
   char *keyStr;
   bool s;

   len = strlen(privStr);

   if (len < 65) {
      return 0;
   }

   macStr = safe_strdup(privStr);
   keyStr = safe_strdup(privStr);

   // copy the hmac that was appended.
   memcpy(macStr, macStr + len - 64, 64);
   macStr[64] = '\0';

   // stop right before hmac
   ASSERT(keyStr[len - 65] == '-');
   keyStr[len - 65] = '\0';

   str_to_bytes(macStr, &hash, &hash_len);
   str_to_bytes(keyStr, &key,  &key_len);

   ASSERT(hash_len == sizeof mac);

   free(macStr);
   free(keyStr);

   crypt_hmac_sha256(key, key_len, wallet->pass->buf, wallet->pass->len, &mac);

   s = memcmp(mac.data, hash, sizeof mac) == 0;

   free(hash);

   if (s) {
      *encPrivKey = key;
      *encLen = key_len;
   } else {
      Log(LGPFX" %s failed.\n", __FUNCTION__);
      free(key);
   }

   return s;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_alloc_key --
 *
 *------------------------------------------------------------------------
 */

static bool
wallet_alloc_key(struct wallet *wallet,
                 const char    *priv,
                 const char    *pub,
                 const char    *desc,
                 time_t         birth,
                 bool           spendable)
{
   struct wallet_key *wkey;
   struct key *key;
   uint160 pub_key;
   size_t len;
   uint8 *buf;
   bool s;

   ASSERT(priv);

   key = NULL;
   buf = NULL;
   len = 0;
   memset(&pub_key, 0, sizeof pub_key);

   if (btc->wallet_state == WALLET_ENCRYPTED_LOCKED) {
      if (wallet->pass) {
         struct secure_area *sec_b58;
         uint8 *encPrivKey;
         size_t encLen;

         if (!wallet_verify_hmac(wallet, priv, &encPrivKey, &encLen)) {
            return 0;
         }

         s = crypt_decrypt(wallet->ckey, encPrivKey, encLen, &sec_b58);
         free(encPrivKey);
         ASSERT(s);
         /*
          * 'buf' is a sensitive buffer here. It should be backed by
          * a struct secure_area.
          */
         s = b58_privkey_to_bytes((char *)sec_b58->buf, &buf, &len);
         secure_free(sec_b58);
         ASSERT(s);
      } else {
         uint8 *pkey;
         size_t plen;

         str_to_bytes(pub, &pkey, &plen);
         hash160_calc(pkey, plen, &pub_key);
         free(pkey);
      }
   } else {
      s = b58_privkey_to_bytes(priv, &buf, &len);
      ASSERT(s);
   }

   if (buf) {
      key = key_alloc();
      key_set_privkey(key, buf, len);
      memset(buf, 0, len);
      free(buf);
      key_get_pubkey_hash160(key, &pub_key);
   }
   ASSERT(!uint160_iszero(&pub_key));

   wkey = safe_calloc(1, sizeof *wkey);
   wkey->cfg_idx   = hashtable_getnumentries(wallet->hash_keys);
   wkey->btc_addr  = b58_pubkey_from_uint160(&pub_key);
   wkey->desc      = desc ? safe_strdup(desc) : NULL;
   wkey->pub_key   = pub_key;
   wkey->birth     = birth;
   wkey->key       = key;
   wkey->spendable = spendable;

   if (spendable == 0) {
      Log(LGPFX" funds on %s are not spendable.\n", wkey->btc_addr);
   }

   s = hashtable_insert(wallet->hash_keys, &pub_key, sizeof pub_key, wkey);
   ASSERT(s);

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_hmac_string --
 *
 *------------------------------------------------------------------------
 */

static char *
wallet_hmac_string(const uint8 *privkey,
                   size_t       privlen,
                   const struct secure_area *passphrase)
{
   char result[128];
   uint256 hmac;

   ASSERT(privkey);

   crypt_hmac_sha256(privkey, privlen, passphrase->buf, passphrase->len, &hmac);
   str_snprintf_bytes(result, sizeof result, NULL, hmac.data, sizeof hmac);

   return safe_strdup(result);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_encrypt_string --
 *
 *------------------------------------------------------------------------
 */

static char *
wallet_encrypt_string(struct wallet    *wallet,
                      const char       *plaintext,
                      struct crypt_key *ckey)
{
   struct secure_area *sec;
   char cipherStr[1024];
   uint8 *cipher;
   char *hmac;
   char *res;
   size_t clen;
   size_t len;
   bool s;

   ASSERT(plaintext);

   len = strlen(plaintext) + 1;
   sec = secure_alloc(len);
   memcpy(sec->buf, plaintext, len);

   s = crypt_encrypt(ckey, sec, &cipher, &clen);
   ASSERT(s);

   str_snprintf_bytes(cipherStr, sizeof cipherStr, NULL, cipher, clen);
   hmac = wallet_hmac_string(cipher, clen, wallet->pass);
   res = safe_asprintf("%s-%s", cipherStr, hmac);
   free(hmac);

   free(cipher);
   secure_free(sec);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_save_key_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_save_key_cb(const void *key,
                   size_t klen,
                   void *clientData,
                   void *keyData)
{
   struct wallet_key *wkey = (struct wallet_key *)keyData;
   struct config *wcfg = (struct config *)clientData;
   uint8 *privkey;
   uint8 *pubkey;
   size_t privlen;
   size_t publen;
   char *privStr;
   char pubStr[256];

   key_get_privkey(wkey->key, &privkey, &privlen);
   key_get_pubkey(wkey->key,  &pubkey,  &publen);

   privStr = b58_bytes_to_privkey(privkey, privlen);
   str_snprintf_bytes(pubStr, sizeof pubStr, NULL, pubkey, publen);

   config_setint64(wcfg, wkey->birth,    "key%u.birth",  wkey->cfg_idx);
   config_setstring(wcfg, wkey->desc,    "key%u.desc",   wkey->cfg_idx);
   config_setstring(wcfg, pubStr,        "key%u.pubkey", wkey->cfg_idx);
   config_setbool(wcfg, wkey->spendable, "key%u.spendable", wkey->cfg_idx);

   if (btc->wallet->pass) {
      char *enc = wallet_encrypt_string(btc->wallet, privStr, btc->wallet->ckey);
      free(privStr);
      privStr = enc;
   }
   config_setstring(wcfg, privStr, "key%u.privkey", wkey->cfg_idx);

   free(pubkey);
   free(privkey);
   free(privStr);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_save_keys --
 *
 *------------------------------------------------------------------------
 */

static int
wallet_save_keys(struct wallet *wallet)
{
   struct config *cfg;
   int res;
   int n;

   n = hashtable_getnumentries(wallet->hash_keys);

   Log(LGPFX" saving %u key%s in %sencrypted wallet %s.\n",
       n, n > 1 ? "s" : "",
       wallet->pass ? "encrypted" : "NON-",
       wallet->filename);

   cfg = config_create();
   config_setint64(cfg, n, "numKeys");

   if (wallet->pass) {
      char saltStr[80];
      int64 count = 0;
      bool s;

      res = RAND_bytes(wallet->ckey->salt, sizeof wallet->ckey->salt);
      if (res != 1) {
         res = ERR_get_error();
         Log(LGPFX" RAND_bytes failed: %d\n", res);
         goto exit;
      }
      str_snprintf_bytes(saltStr, sizeof saltStr, NULL,
                         wallet->ckey->salt, sizeof wallet->ckey->salt);
      config_setstring(cfg, saltStr, "encryption.salt");
      s = crypt_set_key_from_passphrase(wallet->pass, wallet->ckey, &count);
      ASSERT(s);
      ASSERT(count >= CRYPT_NUM_ITERATIONS_OLD);
      config_setint64(cfg, count, "encryption.numIterations");
   }

   hashtable_for_each(wallet->hash_keys, wallet_save_key_cb, cfg);

   file_rotate(wallet->filename, 1);
   res = file_create(wallet->filename);
   if (res) {
      Log(LGPFX" failed to create file '%s': %s\n",
          wallet->filename, strerror(res));
      goto exit;
   }
   res = file_chmod(wallet->filename, 0600);
   if (res) {
      Log(LGPFX" failed to chmod 0600 wallet.dat: %s\n",
          strerror(res));
      goto exit;
   }
   res = config_write(cfg, wallet->filename);

exit:
   config_free(cfg);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_crypt_init --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_crypt_init(struct wallet *wallet,
                  const char    *saltStr,
                  int64          count)
{
   int64 count0 = count;
   uint8 *salt;
   size_t len;
   bool s;

   if (saltStr == NULL) {
      return;
   }
   if (wallet->pass == NULL) {
      Log(LGPFX" wallet is encrypted. no passphrase given.\n");
      return;
   }

   ASSERT(saltStr);

   str_to_bytes(saltStr, &salt, &len);
   ASSERT(len == sizeof wallet->ckey->salt);
   memcpy(wallet->ckey->salt, salt, len);
   free(salt);

   s = crypt_set_key_from_passphrase(wallet->pass, wallet->ckey, &count0);

   ASSERT(s);
   ASSERT(count == count0);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_load_keys --
 *
 *------------------------------------------------------------------------
 */

static int
wallet_load_keys(struct wallet     *wallet,
                 const char       **errStr,
                 struct config     *cfg,
                 enum wallet_state *wallet_state)
{
   char *saltStr;
   int64 count;
   int n;
   int i;

   n = config_getint64(cfg, 0, "numKeys");
   saltStr = config_getstring(cfg, NULL, "encryption.salt");
   count = config_getint64(cfg, CRYPT_NUM_ITERATIONS_OLD,
                           "encryption.numIterations");

   if (saltStr == NULL) {
      *wallet_state = WALLET_PLAIN;
   } else {
      *wallet_state = WALLET_ENCRYPTED_LOCKED;
   }

   wallet_crypt_init(wallet, saltStr, count);
   free(saltStr);

   Log(LGPFX" %s wallet: %u key%s in file '%s'.\n",
       *wallet_state == WALLET_PLAIN ? "plain" : "encrypted",
       n, n > 1 ? "s" : "", wallet->filename);

   for (i = 0; i < n; i++) {
      time_t birth = config_getint64(cfg, 0,     "key%u.birth", i);
      char   *desc = config_getstring(cfg, NULL, "key%u.desc", i);
      char   *priv = config_getstring(cfg, NULL, "key%u.privkey", i);
      char   *pub  = config_getstring(cfg, NULL, "key%u.pubkey", i);
      bool spendable = config_getbool(cfg, TRUE, "key%u.spendable", i);
      bool s;

      s = wallet_alloc_key(wallet, priv, pub, desc, birth, spendable);

      free(pub);
      free(priv);
      free(desc);

      if (s == 0) {
         Log(LGPFX" failed to load pub_key #%u\n", i);
         *errStr = "failed to alloc key";
         goto exit;
      }
   }
   if (wallet->pass && *wallet_state == WALLET_ENCRYPTED_LOCKED) {
      *wallet_state = WALLET_ENCRYPTED_UNLOCKED;
   }
   return 0;

exit:

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_update_filter_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_update_filter_cb(const void *key,
                        size_t len,
                        void *cbData,
                        void *keyData)
{
   struct bloom_filter *filter = (struct bloom_filter *)cbData;
   struct wallet_key *wkey = (struct wallet_key *)keyData;

   bloom_add(filter, &wkey->pub_key, sizeof wkey->pub_key);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_update_filter --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_update_filter(const struct wallet *wallet,
                     struct bloom_filter *filter)
{
   hashtable_for_each(wallet->hash_keys, wallet_update_filter_cb, filter);
}


/*
 *----------------------------------------------------------------
 *
 * wallet_filter_init --
 *
 *----------------------------------------------------------------
 */

static void
wallet_filter_init(struct wallet *wallet)
{
   ASSERT(wallet->filter == NULL);
   wallet->filter = bloom_create(10, 0.001);

   wallet_update_filter(wallet, wallet->filter);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_lookup_pubkey --
 *
 *      Should really be called _pubkeyhash.
 *
 *------------------------------------------------------------------------
 */

struct key *
wallet_lookup_pubkey(const struct wallet *wallet,
                     const uint160 *pub_key)
{
   struct wallet_key *wkey;
   bool s;

   s = hashtable_lookup(wallet->hash_keys, pub_key, sizeof *pub_key, (void *)&wkey);
   if (s == 0) {
      return NULL;
   }
   ASSERT(wkey->key);
   return wkey->key;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_is_pubkey_spendable --
 *
 *------------------------------------------------------------------------
 */

bool
wallet_is_pubkey_spendable(const struct wallet *wallet,
                           const uint160       *pub_key)
{
   struct wallet_key *wkey;
   bool s;

   s = hashtable_lookup(wallet->hash_keys, pub_key, sizeof *pub_key, (void *)&wkey);
   ASSERT(s);

   return wkey->spendable;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_is_pubkey_hash160_mine --
 *
 *------------------------------------------------------------------------
 */

bool
wallet_is_pubkey_hash160_mine(const struct wallet *wallet,
                              const uint160       *pub_key)
{
   return hashtable_lookup(wallet->hash_keys, pub_key, sizeof *pub_key, NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_export_addrs_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_export_addrs_cb(const void *key,
                       size_t len,
                       void *cbData,
                       void *keyData)
{
   struct wallet_key *wkey = (struct wallet_key*)keyData;
   struct bitcui_addr **addrPtr = (struct bitcui_addr **)cbData;
   struct bitcui_addr *addr = *addrPtr;

   addr->addr = safe_strdup(wkey->btc_addr);
   addr->desc = safe_strdup(wkey->desc);
   addr->idx  = wkey->cfg_idx;

   *addrPtr += 1;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_addr_info_compare --
 *
 *------------------------------------------------------------------------
 */

static int
wallet_addr_info_compare(const void *a0,
                         const void *a1)
{
   struct bitcui_addr *addr0 = (struct bitcui_addr *)a0;
   struct bitcui_addr *addr1 = (struct bitcui_addr *)a1;

   return addr0->idx > addr1->idx;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_export_bitcoin_addrs --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_export_bitcoin_addrs(const struct wallet *wallet,
                            struct bitcui_addr **addrsOut,
                            int *numAddr)
{
   struct bitcui_addr *addrs;

   *numAddr = hashtable_getnumentries(wallet->hash_keys);
   addrs = safe_malloc(*numAddr * sizeof(struct bitcui_addr));

   *addrsOut = addrs;

   hashtable_for_each(wallet->hash_keys, wallet_export_addrs_cb, &addrs);

   qsort(*addrsOut, *numAddr, sizeof *addrs, wallet_addr_info_compare);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_open_file --
 *
 *------------------------------------------------------------------------
 */

static struct wallet *
wallet_open_file(struct config      *config,
                 struct secure_area *pass,
                 const char        **errStr,
                 enum wallet_state  *wallet_state)
{
   struct wallet *wallet;
   struct config *wcfg;
   int res;

   *wallet_state = WALLET_UNKNOWN;

   wallet = safe_calloc(1, sizeof *wallet);
   wallet->filename   = wallet_get_filename();
   wallet->hash_keys  = hashtable_create();
   wallet->pass       = pass;
   wallet->ckey_store = secure_alloc(sizeof *wallet->ckey);
   wallet->ckey       = (struct crypt_key *)wallet->ckey_store->buf;

   if (!file_exists(wallet->filename)) {
      wcfg = config_create();
   } else {
      res = config_load(wallet->filename, &wcfg);
      if (res) {
         *errStr = "failed to read wallet file";
         NOT_TESTED();
         goto exit;
      }
   }

   res = wallet_load_keys(wallet, errStr, wcfg, wallet_state);
   config_free(wcfg);
   if (res) {
      goto exit;
   }

   ASSERT(wallet);

   return wallet;
exit:

   wallet_close(wallet);

   return NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_open --
 *
 *------------------------------------------------------------------------
 */

int
wallet_open(struct config      *config,
            struct secure_area *pass,
            const char        **errStr,
            struct wallet     **walletOut)
{
   struct wallet *wallet;
   int res;

   wallet = wallet_open_file(config, pass, errStr, &btc->wallet_state);
   *walletOut = wallet;
   if (wallet == NULL) {
      res = 1;
      goto exit;
   }

   res = txdb_open(config, errStr, &wallet->txdb);
   if (res) {
      goto exit;
   }

   wallet->balance = txdb_get_balance(wallet->txdb);
   wallet_print(wallet);
   wallet_filter_init(wallet);

   if (btcui->inuse) {
      struct bitcui_addr *addrs;
      int num;

      wallet_export_bitcoin_addrs(wallet, &addrs, &num);
      bitcui_set_addrs_info(num, addrs);
   }

   return res;

exit:

   wallet_close(wallet);
   *walletOut = NULL;

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_get_bloom_filter_info --
 *
 *------------------------------------------------------------------------
 */

void
wallet_get_bloom_filter_info(const struct wallet *wallet,
                             uint8              **filter,
                             uint32              *filterSize,
                             uint32              *numHashFuncs,
                             uint32              *tweak)
{
   bloom_getinfo(wallet->filter, filter, filterSize, numHashFuncs, tweak);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_get_birth_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_get_birth_cb(const void *key,
                    size_t keyLen,
                    void *clientData,
                    void *keyData)
{
   struct wallet_key *wkey = (struct wallet_key *)keyData;
   uint64 *birth = (uint64 *)clientData;

   *birth = MIN(*birth, wkey->birth);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_get_birth --
 *
 *------------------------------------------------------------------------
 */

uint64
wallet_get_birth(const struct wallet *wallet)
{
   uint64 birth = time(NULL) + 100 * 365 * 24 * 60 * 60ULL;

   hashtable_for_each(wallet->hash_keys, wallet_get_birth_cb, &birth);

   return birth - 12 * 60 * 60; // to be on the safe side.
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_free_key_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_free_key_cb(const void *key,
                   size_t keyLen,
                   void *clientData)
{
   struct wallet_key *wkey = (struct wallet_key *)clientData;

   ASSERT(wkey);

   key_free(wkey->key);
   free(wkey->btc_addr);
   free(wkey->desc);
   free(wkey);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_craft_tx --
 *
 *------------------------------------------------------------------------
 */

int
wallet_craft_tx(struct wallet            *wallet,
                const struct btc_tx_desc *desc,
                btc_msg_tx               *tx)
{
   uint64 value = 0;
   int i;

   btc_msg_tx_init(tx);

   Warning(LGPFX" TX: %.8f BTC for '%s' (fee: %.8f BTC -- %.4f%%)\n",
           desc->total_value / ONE_BTC, desc->label, desc->fee / ONE_BTC,
           100.0 * desc->fee / desc->total_value);
   for (i = 0; i < desc->num_addr; i++) {
      value += desc->dst[i].value;
      Warning(LGPFX" TX: %.8f BTC to %s\n",
              desc->dst[i].value / ONE_BTC, desc->dst[i].addr);
   }
   ASSERT(value == desc->total_value);

   if (value + desc->fee > wallet->balance) {
      Warning(LGPFX" insufficient funds: %llu vs %llu (%.8f vs %.8f) fee=%.8f\n",
              value, wallet->balance, value / ONE_BTC,
              wallet->balance / ONE_BTC, desc->fee / ONE_BTC);
      return 1;
   }

   return txdb_craft_tx(wallet->txdb, desc, tx);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_find_key_cb --
 *
 *------------------------------------------------------------------------
 */

static void
wallet_find_key_by_idx_cb(const void *key,
                          size_t      klen,
                          void       *clientData,
                          void       *keyData)
{
   struct wallet_find_data *data = (struct wallet_find_data *)clientData;
   struct wallet_key *wkey = (struct wallet_key *)keyData;

   if (wkey->cfg_idx == data->cfg_idx) {
      data->wkey = wkey;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_find_key_by_idx --
 *
 *------------------------------------------------------------------------
 */

static struct wallet_key*
wallet_find_key_by_idx(struct wallet *wallet,
                       uint32         cfg_idx)
{
   struct wallet_find_data data;

   data.wkey = NULL;
   data.cfg_idx = cfg_idx;

   hashtable_for_each(wallet->hash_keys, wallet_find_key_by_idx_cb, &data);

   return data.wkey;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_get_change_addr --
 *
 *------------------------------------------------------------------------
 */

char *
wallet_get_change_addr(struct wallet *wallet)
{
   struct wallet_key *wkey;

   /*
    * For now, we assume that the address onto which we want to transfer change
    * is the wallet's main/first key. In the future this will likely change,
    * but for now we'll keep this simple.
    */
   wkey = wallet_find_key_by_idx(wallet, 0);

   return wkey->btc_addr;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_add_key --
 *
 *------------------------------------------------------------------------
 */

int
wallet_add_key(struct wallet *wallet,
               const char    *desc,
               char         **btc_addr)
{
   struct key *k;
   uint8 *privkey;
   char *privStr;
   size_t len;

   k = key_generate_new();
   if (k == NULL) {
      return 1;
   }
   key_get_privkey(k, &privkey, &len);
   privStr = b58_bytes_to_privkey(privkey, len);

   if (btc_addr) {
      uint160 pub_key;
      key_get_pubkey_hash160(k, &pub_key);
      *btc_addr = b58_pubkey_from_uint160(&pub_key);
   }

   // XXX: fixme
   wallet_alloc_key(wallet, privStr, NULL, desc, time(NULL), TRUE);

   free(privStr);

   return wallet_save_keys(wallet);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_close --
 *
 *------------------------------------------------------------------------
 */

void
wallet_close(struct wallet *wallet)
{
   if (wallet == NULL) {
      return;
   }
   bloom_free(wallet->filter);
   wallet->filter = NULL;
   txdb_close(wallet->txdb);
   hashtable_clear_with_callback(wallet->hash_keys, wallet_free_key_cb);
   hashtable_destroy(wallet->hash_keys);
   free(wallet->filename);
   secure_free(wallet->ckey_store);
   memset(wallet, 0, sizeof *wallet);
   free(wallet);
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_confirm_tx_in_block --
 *
 *------------------------------------------------------------------------
 */

void
wallet_confirm_tx_in_block(struct wallet *wallet,
                           const btc_msg_merkleblock *blk)
{
   int i;

   for (i = 0; i < blk->matchedTxCount; i++) {
      txdb_confirm_one_tx(wallet->txdb, &blk->blkHash, blk->matchedTxHash + i);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_state_to_str --
 *
 *------------------------------------------------------------------------
 */

static const char *
wallet_state_to_str(void)
{
   switch (btc->wallet_state) {
   case WALLET_PLAIN:                   return "unencrypted";
   case WALLET_ENCRYPTED_LOCKED:        return "encrypted-locked";
   case WALLET_ENCRYPTED_UNLOCKED:      return "encrypted-unlocked";
   case WALLET_UNKNOWN:
   default:                             return "unknown";
   }
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_verify --
 *
 *------------------------------------------------------------------------
 */

bool
wallet_verify(struct secure_area *passphrase,
              enum wallet_state  *wlt_state)
{
   struct wallet *wallet;
   const char *errStr;
   bool res;

   *wlt_state = WALLET_UNKNOWN;

   Log(LGPFX" Verifying wallet encryption state.\n");

   wallet = wallet_open_file(btc->config, passphrase, &errStr, wlt_state);
   res = wallet != NULL;
   if (wallet) {
      wallet_close(wallet);
   } else {
      Log(LGPFX" failed to open wallet: %s\n", errStr);
   }

   Log(LGPFX" wallet state : %s\n", wallet_state_to_str());

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * wallet_encrypt --
 *
 *------------------------------------------------------------------------
 */

int
wallet_encrypt(struct wallet      *wallet,
               struct secure_area *pass)
{

   Log(LGPFX" encrypting wallet.\n");

   if (wallet->pass) {
      Log(LGPFX" wallet already encrypted.\n");
   }

   ASSERT(pass);

   wallet->pass = pass;

   return wallet_save_keys(wallet);
}

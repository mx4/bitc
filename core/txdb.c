#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <leveldb/c.h>

#include "txdb.h"
#include "util.h"
#include "config.h"
#include "hashtable.h"
#include "file.h"
#include "serialize.h"
#include "wallet.h"
#include "bitc.h"
#include "key.h"
#include "base58.h"
#include "script.h"
#include "btc-message.h"
#include "buff.h"
#include "block-store.h"
#include "peergroup.h"
#include "bitc_ui.h"

#define LGPFX "TXDB:"

static int verbose;


/*
 * We serialize one such struct in the DB for each tx of interest:
 *  1. the ones we get from the network,
 *  2. the ones we initiate.
 *
 * For #1:
 *  - label is empty (but can be changed later on),
 *  - blkHash is NOT 0,
 *
 * For #2:
 *  - blkHash is 0,
 *  - label may be set,
 *
 * Once the tx is accepted by the network, we adjust 2 things:
 *  - blkHash is no longer 0.
 *  - expiry is set to 0.
 */

struct tx_ser_data {
   uint256      blkHash;
   uint64       timestamp;
   uint8       *buf;
   uint64       len;
};


struct tx_entry {
   btc_msg_tx   tx;
   uint256      blkHash;
   uint64       timestamp;
   bool         relevant;
};


struct tx_ser_key {
   uint64       seq;
   uint256      txHash;
};


struct txo_entry {
   uint256      txHash;
   uint256      blkHash;
   char        *btc_addr;
   int          outIdx;
   uint64       value;
   bool         spent;
   bool         spendable;
};



struct txdb {
   struct hashtable       *hash_tx;  /* key'd by txHash */
   struct hashtable       *hash_txo;
   uint64                  tx_seq;

   char                   *path;
   leveldb_t              *db;
   leveldb_options_t      *db_opts;
   leveldb_readoptions_t  *rd_opts;
   leveldb_writeoptions_t *wr_opts;
};

static struct txdb *theTxdb;

static int
txdb_remember_tx(struct txdb   *txdb,
                 bool           alreadySaved,
                 mtime_t        timestamp,
                 const uint8   *buf,
                 size_t         len,
                 const uint256 *txHash,
                 const uint256 *blkHash,
                 bool          *relevant);


/*
 *------------------------------------------------------------------------
 *
 * txdb_save_tx_label --
 *
 *      Save tx label in the config file. That way if we resync the app and zap
 *      all relevant tx, we still keep the labels of the tx we initiated
 *      around.
 *
 *------------------------------------------------------------------------
 */

static void
txdb_save_tx_label(const struct btc_tx_desc *tx_desc,
                   const char               *hashStr)
{
   if (tx_desc->label[0] != '\0') {
      config_setstring(btc->txLabelsCfg, tx_desc->label, "tx.%s.label", hashStr);
   }
   config_save(btc->txLabelsCfg);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_print_coins --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_print_coins(const struct txdb *txdb,
                 bool onlyUnspent)
{
   struct txo_entry *txo_array = NULL;
   int i;
   int n;

   n = hashtable_getnumentries(txdb->hash_txo);
   if (n == 0) {
      log_info(LGPFX" %s: no coins found\n", __func__);
      return;
   }

   hashtable_linearize(txdb->hash_txo, sizeof *txo_array, (void **)&txo_array);
   ASSERT(txo_array);
   log_info(LGPFX" %s: %d coins available:\n", __func__, n);

   for (i = 0; i < n; i++) {
      struct txo_entry *txo_ent = txo_array + i;

      if (onlyUnspent && txo_ent->spent) {
         continue;
      }

      log_info(LGPFX" txo%03d: %s sp=%u id=%3u v=%" PRIu64 "\n",
          i, txo_ent->btc_addr, txo_ent->spent, txo_ent->outIdx, txo_ent->value);
   }
   free(txo_array);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_free_tx_entry --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_free_tx_entry(struct tx_entry *txe)
{
   btc_msg_tx_free(&txe->tx);
   free(txe);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_hashtable_free_tx_entry --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_hashtable_free_tx_entry(const void *key,
                             size_t      keyLen,
                             void       *clientData)
{
   struct tx_entry *txe = clientData;

   txdb_free_tx_entry(txe);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_hashtable_free_txo_entry --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_hashtable_free_txo_entry(const void *key,
                              size_t      keyLen,
                              void       *clientData)
{
   struct txo_entry *txo = clientData;

   free(txo->btc_addr);
   free(txo);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_tx_credit --
 *
 *------------------------------------------------------------------------
 */

static uint64
txdb_get_tx_credit(const btc_msg_tx *tx)
{
   uint64 credit;
   int i;

   credit = 0;
   for (i = 0; i < tx->out_count; i++) {
      const btc_msg_tx_out *txo = tx->tx_out + i;
      uint160 addr;

      if (script_parse_pubkey_hash(txo->scriptPubKey, txo->scriptLength, &addr)
         || !wallet_is_pubkey_hash160_mine(btc->wallet, &addr)) {
         continue;
      }
      credit += txo->value;
   }
   return credit;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_lookup_txo --
 *
 *------------------------------------------------------------------------
 */

static struct txo_entry*
txdb_lookup_txo(const uint256 *txHash,
                uint32         outIdx)
{
   struct txo_entry *txo_entry;
   char key[32 + 4]; // txHash + txo_idx
   bool s;

   /*
    * Look to see if the txi refers to one of our coins (a known txo).
    */
   memcpy(key,  txHash,   sizeof(uint256));
   memcpy(key + 32, &outIdx, sizeof(uint32));

   s = hashtable_lookup(theTxdb->hash_txo, key, sizeof key, (void **)&txo_entry);
   if (s == 0) {
      return NULL;
   }
   return txo_entry;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_tx_debit --
 *
 *------------------------------------------------------------------------
 */

static uint64
txdb_get_tx_debit(const btc_msg_tx *tx)
{
   uint64 debit;
   int i;

   debit = 0;
   for (i = 0; i < tx->in_count; i++) {
      const btc_msg_tx_in *txi = tx->tx_in + i;
      struct txo_entry *txo_entry;

      txo_entry = txdb_lookup_txo(&txi->prevTxHash, txi->prevTxOutIdx);
      if (txo_entry == NULL) {
         continue;
      }

      ASSERT(txo_entry);

      debit += txo_entry->value;
   }
   return debit;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_serialize_tx_key --
 *
 *------------------------------------------------------------------------
 */

static struct buff *
txdb_serialize_tx_key(uint64 tx_seq,
                      const char *hashStr)
{
   struct buff *buf;
   char str[256];

   ASSERT(hashStr);

   buf = buff_alloc();

   snprintf(str, sizeof str, "/tx/%010" PRIu64 "/%s", tx_seq, hashStr);
   serialize_bytes(buf, str, strlen(str) + 1); /* include terminal '\0' */

   log_info(LGPFX" adding %s seq=%" PRIu64 " : '%s'\n", hashStr, tx_seq, str);

   return buf;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_deserialize_tx_key --
 *
 *------------------------------------------------------------------------
 */

static struct tx_ser_key *
txdb_deserialize_tx_key(const void *key,
                        size_t klen)
{
   struct tx_ser_key *tx;
   char hashStr[80];
   bool s;
   int n;

   ASSERT(key);

   tx = safe_calloc(1, sizeof *tx);

   n = sscanf(key, "/tx/%010" SCNu64 "/%s", &tx->seq, hashStr);
   ASSERT(n == 2);
   s = uint256_from_str(hashStr, &tx->txHash);
   ASSERT(s);

   return tx;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_deserialize_tx_data --
 *
 *------------------------------------------------------------------------
 */

static struct tx_ser_data *
txdb_deserialize_tx_data(const void *val,
                         size_t vlen)
{
   struct tx_ser_data *tx;
   struct buff buf;

   ASSERT(val);

   buff_init(&buf, (void *)val, vlen);

   tx = safe_malloc(sizeof *tx);

   deserialize_uint256(&buf, &tx->blkHash);
   deserialize_uint64(&buf,  &tx->timestamp);
   deserialize_varint(&buf,  &tx->len);

   tx->buf = safe_calloc(1, tx->len + 1);
   deserialize_bytes(&buf, tx->buf, tx->len);

   ASSERT(buff_space_left(&buf) == 0);

   return tx;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_serialize_tx_data --
 *
 *------------------------------------------------------------------------
 */

static struct buff *
txdb_serialize_tx_data(const struct tx_ser_data *tx)
{
   struct buff *buf;

   ASSERT(tx);

   buf = buff_alloc();

   serialize_uint256(buf, &tx->blkHash);
   serialize_uint64(buf,   tx->timestamp);
   serialize_varint(buf,   tx->len);
   serialize_bytes(buf,    tx->buf, tx->len);

   return buf;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_tx_entry --
 *
 *------------------------------------------------------------------------
 */

static struct tx_entry *
txdb_get_tx_entry(const struct txdb *txdb,
                  const uint256     *hash)
{
   struct tx_entry *txe;
   bool s;

   ASSERT(hash);
   ASSERT(txdb);

s = hashtable_lookup(txdb->hash_tx, hash, sizeof *hash, (void **)&txe);
    if (s == 0) {
       return NULL;
   }

   return txe;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_has_tx --
 *
 *------------------------------------------------------------------------
 */

bool
txdb_has_tx(const struct txdb *txdb,
            const uint256     *hash)
{
   ASSERT(hash);
   ASSERT(txdb);

   return txdb_get_tx_entry(txdb, hash) != NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_db_path --
 *
 *------------------------------------------------------------------------
 */

static char *
txdb_get_db_path(struct config *config)
{
   char txdbPath[PATH_MAX];
   char *dir;

   dir = bitc_get_directory();
   snprintf(txdbPath, sizeof txdbPath, "%s/txdb", dir);
   free(dir);

   return config_getstring(config, txdbPath, "txdb.path");
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_zap --
 *
 *------------------------------------------------------------------------
 */

int
txdb_zap(struct config *config)
{
   leveldb_options_t *options;
   char *err = NULL;
   char *path;
   int res;

   path = txdb_get_db_path(config);

   res = file_exists(path);
   if (res == 0) {
      goto exit;
   }

   log_warn(LGPFX" destroying txdb @ '%s'\n", path);

   options = leveldb_options_create();
   leveldb_options_set_info_log(options, NULL);
   leveldb_destroy_db(options, path, &err);
   leveldb_options_destroy(options);
   if (err) {
      log_warn(LGPFX" failed to destroy DB %s: %s\n", path, err);
      free(err);
      res = 1;
   }

exit:
   free(path);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_process_tx_entry --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_process_tx_entry(struct txdb      *txdb,
                      const uint256    *txHash,
                      const uint256    *blkHash,
                      const btc_msg_tx *tx,
                      bool             *relevant)
{
   struct txo_entry *txo_entry;
   uint32 i;
   bool s;

   ASSERT(txdb);
   ASSERT(*relevant == 0);

   log_info(LGPFX" processing  %s\n", uint256_to_str(txHash));

   /*
    * Look at all the tx referred to by the inputs. If any of these match
    * a txo for the wallet keys, we have a debit.
    */
   for (i = 0; i < tx->in_count; i++) {
      const btc_msg_tx_in *txi = tx->tx_in + i;
      /*
       * Look to see if the txi refers to one of our coins (a known txo). If
       * so, we need to mark it as spent.
       */
      txo_entry = txdb_lookup_txo(&txi->prevTxHash, txi->prevTxOutIdx);
      if (txo_entry == NULL) {
         continue;
      }

      ASSERT(txo_entry->spent == 0);
      txo_entry->spent = 1;
      *relevant = 1;
   }

   /*
    * Analyze all the txo to see if any credit our addresses.
    */
   for (i = 0; i < tx->out_count; i++) {
      char key[32 + 4]; // txHash + txo_idx
      const btc_msg_tx_out *txo = tx->tx_out + i;
      uint160 pub_key;

      if (script_parse_pubkey_hash(txo->scriptPubKey, txo->scriptLength, &pub_key)
          || !wallet_is_pubkey_hash160_mine(btc->wallet, &pub_key)) {
         continue;
      }
      *relevant = 1;

      memcpy(key,  txHash, sizeof(uint256));
      memcpy(key + 32, &i, sizeof(uint32));

      txo_entry = safe_malloc(sizeof *txo_entry);
      txo_entry->spent     = 0;
      txo_entry->value     = txo->value;
      txo_entry->btc_addr  = b58_pubkey_from_uint160(&pub_key);
      txo_entry->outIdx    = i;
      txo_entry->spendable = wallet_is_pubkey_spendable(btc->wallet, &pub_key);
      memcpy(&txo_entry->txHash, txHash,  sizeof *txHash);
      if (blkHash) {
         memcpy(&txo_entry->blkHash, blkHash, sizeof *blkHash);
      } else {
         memset(&txo_entry->blkHash, 0, sizeof txo_entry->blkHash);
      }

      s = hashtable_insert(txdb->hash_txo, key, sizeof key, txo_entry);
      ASSERT(s);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_balance_cb --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_get_balance_cb(const void *key,
                    size_t      klen,
                    void       *clientData,
                    void       *keyData)
{
   struct txo_entry *txo_entry = keyData;
   uint64 *balance = (uint64 *)clientData;

   if (txo_entry->spent == 0) {
      *balance += txo_entry->value;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_balance --
 *
 *------------------------------------------------------------------------
 */

uint64
txdb_get_balance(struct txdb *txdb)
{
   uint64 balance = 0;

   /*
    * This is not quite correct. We should only aggregate transactions that are
    * either 1) pending or 2) whose encompassing block is part of the 'best
    * chain'.
    *
    * XXX: Right now, we misreport the balance of wallets that have tx that
    * made it into orphaned blocks.
    */

   hashtable_for_each(txdb->hash_txo, txdb_get_balance_cb, &balance);

   log_info(LGPFX" BALANCE =  %" PRIu64 " -- %.8f BTC\n",
       balance / 10, balance / ONE_BTC);

   return balance;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_remove_from_hashtable --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_remove_from_hashtable(struct txdb      *txdb,
                           const uint256    *txHash)
{
   struct tx_entry *txe;
   bool s;

   txe = txdb_get_tx_entry(txdb, txHash);
   if (txe == NULL || txe->relevant == 1) {
      return;
   }

txdb_free_tx_entry(txe);

   s = hashtable_remove(txdb->hash_tx, txHash, sizeof *txHash);
   log_warn(LGPFX" %s removed from hash_tx: %d (count=%u)\n",
            uint256_to_str(txHash), s, hashtable_getnumentries(txdb->hash_tx));
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_add_to_hashtable --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_add_to_hashtable(struct txdb      *txdb,
                      const void       *buf,
                      size_t            len,
                      const uint256    *txHash,
                      const uint256    *blkHash,
                      uint64            timestamp,
                      struct tx_entry **txePtr)
{
   struct tx_entry *txe;
   struct buff b;
   int res;
   bool s;

   buff_init(&b, (char *)buf, len);

   txe = safe_malloc(sizeof *txe);
   if (blkHash) {
      memcpy(&txe->blkHash, blkHash, sizeof *blkHash);
   } else {
      memset(&txe->blkHash, 0, sizeof txe->blkHash);
   }
   txe->relevant = 0; /* for now */
   txe->timestamp = timestamp; // only really useful for 'relevant' ones.

   res = deserialize_tx(&b, &txe->tx);
   ASSERT(res == 0);

   s = hashtable_insert(txdb->hash_tx, txHash, sizeof *txHash, txe);
   ASSERT(s);

   *txePtr = txe;

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_open_db --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_open_db(struct txdb *txdb)
{
   char *err = NULL;

   txdb->db_opts = leveldb_options_create();
   leveldb_options_set_create_if_missing(txdb->db_opts, 1);
   txdb->db = leveldb_open(txdb->db_opts, txdb->path, &err);
   if (err) {
      log_warn(LGPFX" failed to open db '%s' : %s\n", txdb->path, err);
      printf("btc failed to open the leveldb database at '%s' : %s\n",
             txdb->path, err);
      printf("Could there be another instance of btc running?\n");
      free(err);
      return 1;
   }

   txdb->rd_opts = leveldb_readoptions_create();
   leveldb_readoptions_set_verify_checksums(txdb->rd_opts, 1);
   leveldb_readoptions_set_fill_cache(txdb->rd_opts, 0);

   txdb->wr_opts = leveldb_writeoptions_create();
   leveldb_writeoptions_set_sync(txdb->wr_opts, 1);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_load_tx --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_load_tx(struct txdb *txdb,
             const char  *key,
             size_t       klen,
             const char  *val,
             size_t       vlen)
{
   struct tx_ser_data *txd;
   struct tx_ser_key *txk;
   bool relevant = 0;
   uint256 txHash;
   bool confirmed;
   int res = 0;

   ASSERT(strncmp(key, "/tx/", 4) == 0);

   txk = txdb_deserialize_tx_key(key, klen);
   txd = txdb_deserialize_tx_data(val, vlen);

   ASSERT(txdb->tx_seq == txk->seq);
   txdb->tx_seq++;

   confirmed = !uint256_iszero(&txd->blkHash);

   hash256_calc(txd->buf, txd->len, &txHash);
   ASSERT(uint256_issame(&txHash, &txk->txHash));
   LOG(1, (LGPFX" loading %ctx %s\n", confirmed ? 'c' : 'u', uint256_to_str(&txHash)));

   res = txdb_remember_tx(txdb, 1 /* not on disk, just hashtable */,
                          txd->timestamp, txd->buf, txd->len,
                          &txk->txHash, &txd->blkHash, &relevant);

   /*
    * If the transaction is still unconfirmed, add to relay set.
    */
   if (!confirmed) {
      struct buff buf;
      int numSec;

      numSec = time(NULL) - txd->timestamp;

      if (numSec > 0) {
         int hours = numSec / (60 * 60);
         int min  = (numSec % (60 * 60)) / 60;

log_info(LGPFX" unconfirmed tx %s was sent %d hours %d min ago.\n",
              uint256_to_str(&txHash), hours, min);
      }

      buff_init(&buf, txd->buf, txd->len);

      log_info(LGPFX" adding tx %s to relay-set\n", uint256_to_str(&txHash));
      peergroup_new_tx_broadcast(btc->peerGroup, &buf,
                                 txd->timestamp + 2 * 60 * 60,
                                 &txHash);
   } else {
      log_info(LGPFX" tx in block %s\n", uint256_to_str(&txd->blkHash));
   }

   free(txd->buf);
   free(txd);
   free(txk);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_open --
 *
 *------------------------------------------------------------------------
 */

int
txdb_open(struct config *config,
          const char   **errStr,
          struct txdb  **out)
{
   leveldb_iterator_t* iter;
   struct txdb *txdb;
   int res;

   txdb = safe_calloc(1, sizeof *txdb);
   txdb->hash_txo = hashtable_create(); /* index all interesting txos */
   txdb->hash_tx  = hashtable_create(); /* all TX brought to our attention */
   txdb->path     = txdb_get_db_path(config);
   txdb->tx_seq   = 0;

   theTxdb = txdb;

   if (!file_exists(txdb->path)) {
      log_info(LGPFX" txdb DB '%s' does not exist. Creating..\n", txdb->path);
   }

   res = txdb_open_db(txdb);
   if (res) {
      *errStr = "failed to open tx DB";
      goto error;
   }

   res = file_chmod(txdb->path, 0700);
   if (res) {
      log_info(LGPFX" Failed to chmod txdb to 0700: %s\n", strerror(res));
      goto error;
   }

   *out = txdb;

   iter = leveldb_create_iterator(txdb->db, txdb->rd_opts);
   leveldb_iter_seek_to_first(iter);

   while (leveldb_iter_valid(iter) && btc->stop == 0) {
      const char *key;
      const char *val;
      size_t klen;
      size_t vlen;

      key = leveldb_iter_key(iter, &klen);
      val = leveldb_iter_value(iter, &vlen);

      log_info(LGPFX" found entry \"%s\" klen=%zu vlen=%zu\n", key, klen, vlen);

      if (klen > 4 && strncmp(key, "/tx/", 4) == 0) {
         res = txdb_load_tx(txdb, key, klen, val, vlen);
         ASSERT(res == 0);
      }

      leveldb_iter_next(iter);
   }
   leveldb_iter_destroy(iter);

   txdb_export_tx_info(txdb);
   txdb_print_coins(txdb, 1);

exit:
   return res;

error:
   txdb_close(txdb);
   theTxdb = NULL;
   *out = NULL;
   goto exit;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_save_tx --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_save_tx(struct txdb   *txdb,
             const uint256 *blkHash,
             const uint256 *txHash,
             mtime_t        timestamp,
             const uint8   *buf,
             size_t         len)
{
   struct tx_ser_data txdata;
   struct buff *bufd;
   struct buff *bufk;
   char *err;

   err = NULL;
   memset(&txdata, 0, sizeof txdata);

   if (blkHash) {
      memcpy(&txdata.blkHash, blkHash, sizeof *blkHash);
   }

   txdata.buf       = (uint8 *)buf;
   txdata.len       = len;
   txdata.timestamp = timestamp;

   bufk = txdb_serialize_tx_key(txdb->tx_seq, uint256_to_str(txHash));
   bufd = txdb_serialize_tx_data(&txdata);

   leveldb_put(txdb->db, txdb->wr_opts,
               buff_base(bufk), buff_curlen(bufk),
               buff_base(bufd), buff_curlen(bufd),
               &err);

   buff_free(bufk);
   buff_free(bufd);

   if (err) {
      log_warn(LGPFX" failed to save tx %s: %s\n", uint256_to_str(txHash), err);
      free(err);
   }

   return err != NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_confirm_one_tx --
 *
 *      Lookup the serialized entry for this transaction and set 'blkHash'.
 *
 *------------------------------------------------------------------------
 */

void
txdb_confirm_one_tx(struct txdb   *txdb,
                    const uint256 *blkHash,
                    const uint256 *txHash)
{
   leveldb_iterator_t *iter;
   struct tx_entry *txe;
   char bkHashStr[80];
   char txHashStr[80];

   ASSERT(!uint256_iszero(blkHash));
   ASSERT(!uint256_iszero(txHash));

   txe = txdb_get_tx_entry(txdb, txHash);
   if (txe == NULL) {
      return;
   }

   if (txe->relevant == 0) {
      txdb_remove_from_hashtable(txdb, txHash);
      return;
   }

   if (!uint256_iszero(&txe->blkHash)) {
      /*
       * It's possible for the ASSERT below to fire if a tx is confirmed in
       * a block that is later orphaned. The tx should then be relayed again
       * until it finds its way in a new block.
       */
      ASSERT(uint256_issame(&txe->blkHash, blkHash));
      return;
   }

   peergroup_stop_broadcast_tx(btc->peerGroup, txHash);
   memcpy(&txe->blkHash, blkHash, sizeof *blkHash);

   uint256_snprintf_reverse(bkHashStr, sizeof bkHashStr, blkHash);
   uint256_snprintf_reverse(txHashStr, sizeof txHashStr, txHash);
   log_warn(LGPFX" %s confirmed in %s\n", txHashStr, bkHashStr);


   iter = leveldb_create_iterator(txdb->db, txdb->rd_opts);
   leveldb_iter_seek_to_first(iter);

   while (leveldb_iter_valid(iter)) {
      struct tx_ser_key *txkey;
      struct tx_ser_data *txdata;
      struct buff *buf;
      const char *key;
      const char *val;
      size_t klen;
      size_t vlen;
      char *err = NULL;

      key = leveldb_iter_key(iter, &klen);
      txkey = txdb_deserialize_tx_key(key, klen);

      if (txkey == NULL || uint256_issame(txHash, &txkey->txHash) == 0) {
         free(txkey);
         leveldb_iter_next(iter);
         continue;
      }


      val = leveldb_iter_value(iter, &vlen);
      txdata = txdb_deserialize_tx_data(val, vlen);
      ASSERT(uint256_iszero(&txdata->blkHash));
      ASSERT(txdata->timestamp != 0);
      memcpy(&txdata->blkHash, blkHash, sizeof *blkHash);

      buf = txdb_serialize_tx_data(txdata);

      leveldb_put(txdb->db, txdb->wr_opts, key, klen,
                  buff_base(buf), buff_curlen(buf), &err);
      buff_free(buf);
      if (err) {
         log_warn(LGPFX" failed to write tx entry: %s\n", err);
      }

      txdb_export_tx_info(txdb);

      free(txkey);
      free(txdata->buf);
      free(txdata);
      break;
   }
   leveldb_iter_destroy(iter);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_remember_tx --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_remember_tx(struct txdb   *txdb,
                 bool           alreadySaved,
                 mtime_t        ts,
                 const uint8   *buf,
                 size_t         len,
                 const uint256 *txHash,
                 const uint256 *blkHash,
                 bool          *relevant)
{
   struct tx_entry *txe;
   int res;

   ASSERT(txHash);
   ASSERT(relevant);

   *relevant = 0;

   /*
    * We always store the tx in the memory pool, that way we know quickly
    * whether we've already seen it.
    */
   res = txdb_add_to_hashtable(txdb, buf, len, txHash, blkHash, ts, &txe);
   if (res) {
      return res;
   }

   txdb_process_tx_entry(txdb, txHash, blkHash, &txe->tx, &txe->relevant);
   if (txe->relevant == 0) {
      log_warn(LGPFX" tx %s not relevant (%u)\n",
              uint256_to_str(txHash), hashtable_getnumentries(txdb->hash_tx));
      return 0;
   }

   if (alreadySaved) {
      return 0;
   }

   /*
    * OK -- this transaction is relevant to our wallet.
    */
   *relevant = 1;
   log_warn(LGPFX" tx %s ok (%u)\n", uint256_to_str(txHash), hashtable_getnumentries(txdb->hash_tx));

   res = txdb_save_tx(txdb, blkHash, txHash, ts, buf, len);
   if (res == 0) {
      txdb->tx_seq++;
   }

   txdb_export_tx_info(txdb);
   if (bitc_state_ready()) {
      int64 value = txdb_get_tx_credit(&txe->tx) - txdb_get_tx_debit(&txe->tx);

      bitcui_set_status("New payment %s: %.8f BTC",
                       value > 0 ? "received" : "made",
                       1.0 * value / ONE_BTC);
   }

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_handle_tx --
 *
 *------------------------------------------------------------------------
 */

int
txdb_handle_tx(struct txdb   *txdb,
               const uint256 *blkHash,
               const uint8   *buf,
               size_t         len,
               bool          *relevant)
{
   uint256 txHash;
   mtime_t ts = 0;
   bool txKnown;

   *relevant = 0;
   hash256_calc(buf, len, &txHash);

   txKnown = txdb_has_tx(txdb, &txHash);

   if (!uint256_iszero(blkHash)) {
      txdb_confirm_one_tx(txdb, blkHash, &txHash);
   }

   if (txKnown) {
      return 0;
   }

   if (uint256_iszero(blkHash)) {
      ts = time(NULL);
   } else {
      ts = blockstore_get_block_timestamp(btc->blockStore, blkHash);
   }

   return txdb_remember_tx(txdb, 0 /* save to disk */, ts, buf, len,
                           &txHash, blkHash, relevant);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_set_txo --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_set_txo(btc_msg_tx *tx,
             int         idx,
             const char *btc_addr,
             uint64      value)
{
   struct btc_msg_tx_out *txo;
   uint160 pubkey;

   b58_pubkey_to_uint160(btc_addr, &pubkey);
   log_bytes(LGPFX" hash-addr:", &pubkey, sizeof pubkey);

   ASSERT(idx < tx->out_count);
   txo = tx->tx_out + idx;
   txo->value = value;

   script_txo_generate(&pubkey, &txo->scriptPubKey, &txo->scriptLength);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_prepare_txout --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_prepare_txout(const struct btc_tx_desc *tx_desc,
                   btc_msg_tx               *tx)
{
   int i;

   /*
    * Fill-out part of the txo: value, addr.  We allocate (outCount+1), in case
    * we need to pay ourselves some change.
    */
   tx->out_count = tx_desc->num_addr;
   ASSERT(tx->tx_out == NULL);
   /*
    * Allocate enough room for the eventual change.
    */
   tx->tx_out = safe_calloc(tx->out_count + 1, sizeof *tx->tx_out);

   for (i = 0; i < tx_desc->num_addr; i++) {
      txdb_set_txo(tx, i, tx_desc->dst[i].addr, tx_desc->dst[i].value);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_sign_tx_inputs --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_sign_tx_inputs(struct txdb *txdb,
                    btc_msg_tx  *tx)
{
   int i;

   for (i = 0; i < tx->in_count; i++) {
      struct btc_msg_tx_in *txi = tx->tx_in + i;
      struct btc_msg_tx_out *txoFrom;
      struct tx_entry *txe;
      int res;
      bool s;

s = hashtable_lookup(txdb->hash_tx, &txi->prevTxHash,
                            sizeof txi->prevTxHash, (void **)&txe);
      ASSERT(s);

      ASSERT(txi->prevTxOutIdx < txe->tx.out_count);
      txoFrom = txe->tx.tx_out + txi->prevTxOutIdx;

      log_warn(LGPFX" -- signing input #%u\n", i);

      res = script_sign(btc->wallet, txoFrom, tx, i, SIGHASH_ALL);
      ASSERT(res == 0);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_txo_entry_compare_cb --
 *
 *------------------------------------------------------------------------
 */

static int
txdb_txo_entry_compare_cb(const void *e0,
                          const void *e1)
{
   struct txo_entry *txo0 = (struct txo_entry *)e0;
   struct txo_entry *txo1 = (struct txo_entry *)e1;
   time_t t0;
   time_t t1;

   t0 = blockstore_get_block_timestamp(btc->blockStore, &txo0->blkHash);
   t1 = blockstore_get_block_timestamp(btc->blockStore, &txo1->blkHash);

   /*
    * If 2 txos are from the same tx, sort by outIdx.
    */
   if (t0 == t1) {
      if (txo0->outIdx == txo1->outIdx) {
         return 0;
      }
      return txo0->outIdx > txo1->outIdx ? 1 : -1;
   }

   return t0 > t1 ? 1 : -1;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_get_coins_sorted --
 *
 *------------------------------------------------------------------------
 */

static struct txo_entry *
txdb_get_coins_sorted(struct txdb *txdb)
{
   struct txo_entry *ptr = NULL;
   int n;

   hashtable_linearize(txdb->hash_txo, sizeof(struct txo_entry), (void **)&ptr);
   ASSERT(ptr);

   n = hashtable_getnumentries(txdb->hash_txo);

   qsort(ptr, n, sizeof *ptr, txdb_txo_entry_compare_cb);

   return ptr;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_select_coins --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_select_coins(struct txdb              *txdb,
                  const struct btc_tx_desc *desc,
                  btc_msg_tx               *tx,
                  uint64                   *change)
{
   struct txo_entry *txo_array;
   uint64 value;
   int txo_num;
   int i;

   i = 0;
   value = 0;
   tx->in_count = 0;
   txo_array = txdb_get_coins_sorted(txdb);
   txo_num = hashtable_getnumentries(txdb->hash_txo);

   /*
    * txo_array is sorted in chronological order, so we'll be consuming old
    * coins first.
    */
   log_info(LGPFX" select_coins: total_value=%" PRIu64 " fee=%" PRIu64 "\n",
       desc->total_value, desc->fee);

   while (value < (desc->total_value + desc->fee) && i < txo_num) {
      struct txo_entry *txo_ent = &txo_array[i++];

      if (txo_ent->spent == 1 ||
          txo_ent->spendable == 0) {
         continue;
      }
      if (uint256_iszero(&txo_ent->blkHash)) {
         continue;
      }

      log_info(LGPFX" using txo for %s id=%3u of %s\n",
          txo_ent->btc_addr, txo_ent->outIdx, uint256_to_str(&txo_ent->txHash));
      value += txo_ent->value;
      memcpy(&tx->tx_in[tx->in_count].prevTxHash, &txo_ent->txHash, sizeof txo_ent->txHash);
      tx->tx_in[tx->in_count].prevTxOutIdx = txo_ent->outIdx;
      tx->tx_in[tx->in_count].sequence = UINT_MAX;
      tx->in_count++;
   }

   ASSERT(value >= desc->total_value);
   *change = value - desc->total_value - desc->fee;
   log_info(LGPFX" change=%" PRIu64 "\n", *change);
   free(txo_array);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_craft_tx --
 *
 *------------------------------------------------------------------------
 */

int
txdb_craft_tx(struct txdb              *txdb,
              const struct btc_tx_desc *tx_desc,
              btc_msg_tx               *tx)
{
   struct buff *buf;
   uint256 txHash;
   uint64 change;
   uint32 numCoins;
   bool relevant;
   mtime_t ts;
   int res;

   res = 0;
   relevant = 0;
   tx->version = 1;
   txdb_prepare_txout(tx_desc, tx);

   /*
    * In order to properly size 'tx->txIn', we need to determine how many coins
    * we're going to use. Right now, let's just vastly overestimate.
    */
   numCoins = hashtable_getnumentries(txdb->hash_txo);
   tx->tx_in = safe_calloc(numCoins, sizeof *tx->tx_in);

   txdb_print_coins(txdb, 1);
   txdb_select_coins(txdb, tx_desc, tx, &change);

   /*
    * Change! XXX: fix me.
    */
   if (change > 0) {
      const char *btc_change;

      btc_change = wallet_get_change_addr(btc->wallet);
      tx->out_count++;
      txdb_set_txo(tx, tx->out_count - 1, btc_change, change);
      log_warn(LGPFX" change: %" PRIu64 " -- %.8f BTC\n", change, change / ONE_BTC);
   }

   txdb_sign_tx_inputs(txdb, tx);

   /*
    * Now that the tx is ready, serialize it and check that it's not too big.
    */
   btcmsg_print_tx(tx);

   buf = buff_alloc();
   serialize_tx(buf, tx);
   if (buff_curlen(buf) > BTC_TX_MAX_SIZE) {
      log_warn(LGPFX" tx too large: %zu\n", buff_curlen(buf));
      res = 1;
      goto exit;
   }

   hash256_calc(buff_base(buf), buff_curlen(buf), &txHash);

   log_warn(LGPFX" %s (%zu bytes)\n", uint256_to_str(&txHash), buff_curlen(buf));
   log_bytes(LGPFX" TX: ", buff_base(buf), buff_curlen(buf));

   if (bitc_testing) {
      log_warn("TESTING! Not saving/relaying tx.\n");
      goto exit;
   }

   ts = time(NULL);

   res = txdb_remember_tx(txdb, 0 /* save to disk */, ts,
                          buff_base(buf), buff_curlen(buf),
                          &txHash, NULL, &relevant);

   txdb_save_tx_label(tx_desc, uint256_to_str(&txHash));
   txdb_export_tx_info(txdb);

   res = peergroup_new_tx_broadcast(btc->peerGroup, buf,
                                    ts + 2 * 60 * 60, &txHash);
   if (res) {
      log_warn(LGPFX" failed to transmit tx: %d\n", res);
      bitcui_set_status("got errors while broadcasting tx");
   }
exit:
   buff_free(buf);
   /*
    * XXX: We should mark the coins used by this tx as "reserved", so that we
    * do not attempt to use conflicting coins in subsequent TXs.
    */
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_close --
 *
 *------------------------------------------------------------------------
 */

void
txdb_close(struct txdb *txdb)
{
   if (txdb == NULL) {
      return;
   }

   if (txdb->db) {
      leveldb_close(txdb->db);
   }
   leveldb_options_destroy(txdb->db_opts);
   leveldb_readoptions_destroy(txdb->rd_opts);
   leveldb_writeoptions_destroy(txdb->wr_opts);

   hashtable_clear_with_callback(txdb->hash_txo, txdb_hashtable_free_txo_entry);
   hashtable_destroy(txdb->hash_txo);

   hashtable_clear_with_callback(txdb->hash_tx, txdb_hashtable_free_tx_entry);
   hashtable_destroy(txdb->hash_tx);

   free(txdb->path);
   memset(txdb, 0, sizeof *txdb);
   free(txdb);
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_export_tx_cb --
 *
 *------------------------------------------------------------------------
 */

static void
txdb_export_tx_cb(const void *key,
                  size_t keyLen,
                  void *cbData,
                  void *keyData)
{
   struct bitcui_tx **txiPtr = (struct bitcui_tx **)cbData;
   struct tx_entry *txe = keyData;
   struct bitcui_tx *txi = *txiPtr;
   char hashStr[80];

   if (txe->relevant == 0) {
      return;
   }

   /*
    * We need to weed out transactions that made it in an orphan block but were
    * not integrated later on in the main chain.
    */

   txi->src  = NULL;
   txi->dst  = NULL;
   txi->desc = NULL;

   ASSERT(keyLen == sizeof(uint256));
   memcpy(&txi->txHash, key, keyLen);
   txi->value  = txdb_get_tx_credit(&txe->tx);
   txi->value -= txdb_get_tx_debit(&txe->tx);

   txi->blockHeight = -1;
   if (!uint256_iszero(&txe->blkHash)) {
      txi->blockHeight = blockstore_get_block_height(btc->blockStore,
                                                     &txe->blkHash);
   }

   uint256_snprintf_reverse(hashStr, sizeof hashStr, (uint256*)key);
   txi->desc = config_getstring(btc->txLabelsCfg, NULL, "tx.%s.label", hashStr) ;
   /*
    * This is a workaround for a bug caused by truncated hashStr.
    */
   if (txi->desc == NULL) {
      hashStr[63] = '\0';
      txi->desc = config_getstring(btc->txLabelsCfg, NULL, "tx.%s.label", hashStr) ;
   }

   txi->timestamp = txe->timestamp;
   *txiPtr += 1;
}


/*
 *--------------------------------------------------------------
 *
 * txdb_bitcui_tx_entry_compare_cb --
 *
 *      Provides full ordering between tx.
 *
 *--------------------------------------------------------------
 */

static int
txdb_bitcui_tx_entry_compare_cb(const void *t0,
                               const void *t1)
{
   const struct bitcui_tx *tx0 = t0;
   const struct bitcui_tx *tx1 = t1;

   if (tx0->blockHeight == tx1->blockHeight) {
      if (memcmp(&tx0->txHash, &tx1->txHash, sizeof(uint256)) == 0) {
         return 0;
      }
      return memcmp(&tx0->txHash, &tx1->txHash, sizeof(uint256)) > 0 ? 1 : -1;
   }

   return tx0->blockHeight > tx1->blockHeight ? 1 : -1;
}


/*
 *------------------------------------------------------------------------
 *
 * txdb_export_tx_info --
 *
 *------------------------------------------------------------------------
 */

void
txdb_export_tx_info(struct txdb *txdb)
{
   struct bitcui_tx *tx_info;
   struct bitcui_tx *ti;
   int tx_num;

   if (btcui->inuse == 0) {
      return;
   }

   /*
    * We may have in hash_tx some entries that are not relevant to our wallet
    * but whose presence is still useful for performance reasons. It's possible
    * we allocate too much memory for tx_info but that's fine for now.
    */
   tx_num  = hashtable_getnumentries(txdb->hash_tx);
   tx_info = safe_calloc(tx_num, sizeof *tx_info);
   ti = tx_info;

   hashtable_for_each(txdb->hash_tx, txdb_export_tx_cb, &ti);
   ASSERT(ti <= tx_info + tx_num);
   tx_num = ti - tx_info;

   qsort(tx_info, tx_num, sizeof *tx_info, txdb_bitcui_tx_entry_compare_cb);
   bitcui_set_tx_info(tx_num, tx_info);
}

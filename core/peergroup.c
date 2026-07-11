#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "peergroup.h"
#include "circlist.h"
#include "netasync.h"
#include "poll.h"
#include "addrbook.h"
#include "util.h"
#include "peer.h"
#include "btc-message.h"
#include "bitc_ui.h"
#include "block-store.h"
#include "wallet.h"
#include "bitc.h"
#include "hashtable.h"
#include "buff.h"

#define LGPFX   "PEERG:"


struct tx_broadcast {
   struct buff *buf;     /* tx serialized */
   time_t       expiry;
};


/*
 * DNS seeds, kept in sync with Bitcoin Core's chainparams.cpp. These return A
 * records for reachable full nodes to bootstrap the address book.
 */
static const char *peer_seeds_main[] = {
   "seed.bitcoin.sipa.be",
   "dnsseed.bluematt.me",
   "dnsseed.bitcoin.dashjr.org",
   "seed.bitcoinstats.com",
   "seed.bitcoin.jonasschnelli.ch",
   "seed.btc.petertodd.net",
   "seed.bitcoin.sprovoost.nl",
   "dnsseed.emzy.de",
   "seed.bitcoin.wiz.biz",
};

static const char *peer_seeds_testnet[] = {
   "testnet-seed.bitcoin.jonasschnelli.ch",
   "seed.tbtc.petertodd.net",
   "seed.testnet.bitcoin.sprovoost.nl",
   "testnet-seed.bluematt.me",
};

static struct {
   uint32 sent;
   uint32 received;
} cmdStats[BTC_MSG_MAX];


/*
 *------------------------------------------------------------------------
 *
 * peergroup_free_tx_broadcast_entry --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_free_tx_broadcast_entry(struct tx_broadcast *txb)
{
   buff_free(txb->buf);
   free(txb);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_free_tx_broadcast_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_free_tx_broadcast_cb(const void *key,
                               size_t keylen,
                               void *clientData)
{
   struct tx_broadcast *txb = (struct tx_broadcast *)clientData;

   peergroup_free_tx_broadcast_entry(txb);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_stop_broadcast_tx --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_stop_broadcast_tx(struct peergroup *pg,
                            const uint256 *hash)
{
   struct tx_broadcast *txb = NULL;
   char hashStr[80];
   bool s;

   s = hashtable_lookup(pg->hash_broadcast, hash, sizeof *hash, (void*)&txb);
   if (s == 0) {
      return;
   }

   uint256_snprintf_reverse(hashStr, sizeof hashStr, hash);
   Warning(LGPFX" stop relaying tx %s\n", hashStr);

   ASSERT(txb);

   peergroup_free_tx_broadcast_entry(txb);

   hashtable_remove(pg->hash_broadcast, hash, sizeof *hash);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_lookup_broadcast_tx --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_lookup_broadcast_tx(struct peergroup *pg,
                              const uint256 *hash,
                              struct buff **bufOut)
{
   struct tx_broadcast *txb;
   bool s;

   *bufOut = NULL;

   s = hashtable_lookup(pg->hash_broadcast, hash, sizeof *hash, (void*)&txb);
   if (s == 0) {
      return 0;
   }

   *bufOut = buff_dup(txb->buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_set_lastblk --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_set_lastblk(struct peergroup *pg,
                      const uint256 *hash)
{
   char prev[80];
   char next[80];

   ASSERT(!uint256_iszero(hash));
   if (uint256_issame(hash, &pg->lastBlk) == 1) {
      return;
   }

   uint256_snprintf_reverse(prev, sizeof prev, &pg->lastBlk);
   uint256_snprintf_reverse(next, sizeof next, hash);

   pg->configNeedWrite = 1;
   memcpy(&pg->lastBlk, hash, sizeof *hash);

   Log(LGPFX" was %s\n", prev);
   Log(LGPFX" now %s\n", next);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_get_lastblk --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_get_lastblk(const struct peergroup *pg,
                      uint256 *hash)
{
   ASSERT(pg);

   memcpy(hash, &pg->lastBlk, sizeof *hash);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_count_connected --
 *
 *------------------------------------------------------------------------
 */

static uint32
peergroup_count_connected(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct circlist_item *li;
   int n;

   n = 0;
   CIRCLIST_SCAN(li, pg->peer_list) {
      int res = peer_getinfo(li, NULL);
      if (res == 0) {
         n++;
      }
   }
   return n;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_update_info --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_update_info(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct circlist_item *li;
   struct bitcui_peer *pinfo;
   int n;

   if (btcui->inuse == 0) {
      return;
   }

   pinfo = safe_calloc(pg->active, sizeof *pinfo);

   n = 0;
   CIRCLIST_SCAN(li, pg->peer_list) {
      int res;
      ASSERT(n < pg->active);
      res = peer_getinfo(li, pinfo + n);
      if (res == 0) {
         n++;
         ASSERT(n <= pg->active);
      }
   }

   bitcui_set_peer_info(pg->active, n, addrbook_get_count(btc->book), pinfo);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_add_peer --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_add_peer(struct peer_addr *paddr)
{
   static int last;

   btc->peerGroup->active++;
   if ((btc->peerGroup->active % 250) == 0 &&
       btc->peerGroup->active != last) {
      last = btc->peerGroup->active;
      Warning(LGPFX" peers: %u\n", btc->peerGroup->active);
   }

   peer_add(paddr, btc->peerGroup->peerSequence);

   peergroup_update_info();
   btc->peerGroup->peerSequence++;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_download_progress --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_download_progress(void)
{
   struct peergroup *peerGroup = btc->peerGroup;
   bitcui_set_catchup_info(peerGroup->numHdrFetched, peerGroup->numHdrToFetch,
                          peerGroup->numFetched,    peerGroup->numToFetch);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_on_ready --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_on_ready(void)
{
   struct circlist_item *li;

   Log(LGPFX" peergroup ready.\n");
   bitcui_set_status("online.");

   CIRCLIST_SCAN(li, btc->peerGroup->peer_list) {
      peer_on_ready_li(li);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_download_complete --
 *
 *      BITC_STATE_UPDATE_TXDB -> BITC_STATE_EXITING
 *                            -> BITC_STATE_READY
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_download_complete(void)
{
   if (btc->state != BITC_STATE_UPDATE_TXDB) {
      return;
   }
   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   if (btc->peerGroup->numFetched > 0) {
      Warning(LGPFX" %d filtered blocks downloaded. refresh complete.\n",
              btc->peerGroup->numFetched);
   } else {
      Warning(LGPFX" headers and filtered blocks up to date.\n");
   }
   peergroup_download_progress();

   if (btc->updateAndExit) {
      bitc_req_stop();
   } else {
      Log(LGPFX" %s -- BITC_STATE_READY.\n", __FUNCTION__);
      btc->state = BITC_STATE_READY;
      peergroup_on_ready();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_add_block_finalize --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_add_block_finalize(struct blockstore *bs,
                             bool headerOnly)

{
   uint256 best_hash;

   blockstore_write_headers(bs);
   blockstore_get_best_hash(bs, &best_hash);
   if (headerOnly == 0) {
      peergroup_set_lastblk(btc->peerGroup, &best_hash);
   }
   if (bitc_state_ready() || bitc_state_updating_txdb() ||
       (blockstore_get_height(bs) % 2000) == 0) {
      bitcui_set_last_block_info(&best_hash, blockstore_get_height(bs),
                                 blockstore_get_timestamp(btc->blockStore));
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_process_filtered_block --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_process_filtered_block(struct peer *peer,
                                 const btc_msg_merkleblock *blk)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint256 lastTxdb;
   bool orphan;
   bool s;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB ||
          btc->state == BITC_STATE_READY);

   peergroup_get_lastblk(pg, &lastTxdb);
   ASSERT(!uint256_iszero(&lastTxdb));

   if (btc->state == BITC_STATE_UPDATE_TXDB &&
       blockstore_is_next(bs, &lastTxdb, &blk->blkHash)) {
      pg->numFetched++;
      peergroup_set_lastblk(pg, &blk->blkHash);
      if ((pg->numFetched % 5000) == 0) {
         Warning(LGPFX" fetched %6d blocks out of %d\n",
                 pg->numFetched, pg->numToFetch);
      }
   }

   s = blockstore_add_header(bs, &blk->header, &blk->blkHash, &orphan);
   if (orphan) {
      char hashStr[80];
      uint256_snprintf_reverse(hashStr, sizeof hashStr, &blk->blkHash);
      bitcui_set_status("Block %s orphaned", hashStr);
   }
   if (s) {
      peergroup_add_block_finalize(bs, FALSE /* full block */);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_download_headers --
 *
 *      BITC_STATE_STARTING -> BITC_STATE_UPDATE_HEADERS
 *
 *------------------------------------------------------------------------
 */

int
peergroup_download_headers(struct peer *peer,
                           int peerStartingHeight)
{
   struct blockstore *bs = btc->blockStore;

   ASSERT(btc->state == BITC_STATE_STARTING ||
          btc->state == BITC_STATE_UPDATE_HEADERS);

   /*
    * Only one peer downloads headers at a time. The first peer to reach here
    * becomes the download peer; others stay connected but idle. If the download
    * peer disconnects, peer_destroy() clears this and the next peer to connect
    * (refill adds one when 'active' drops) takes over.
    */
   if (btc->peerGroup->downloadPeer == NULL) {
      btc->peerGroup->downloadPeer = peer;
   } else if (btc->peerGroup->downloadPeer != peer) {
      return 0;
   }

   if (peerStartingHeight > btc->peerGroup->heightTarget) {
      if (btc->peerGroup->numHdrToFetch == 0) {
         btc->peerGroup->numHdrToFetch = peerStartingHeight - blockstore_get_height(bs);
      } else {
         btc->peerGroup->numHdrToFetch += peerStartingHeight - btc->peerGroup->heightTarget;
      }
      btc->peerGroup->heightTarget = peerStartingHeight;
   }

   peergroup_download_progress();

   if (btc->state == BITC_STATE_STARTING) {
      Log(LGPFX" %s -- BITC_STATE_UPDATE_HEADERS.\n", __FUNCTION__);
      btc->state = BITC_STATE_UPDATE_HEADERS;
      bitcui_set_status("online, fetching headers..");
      if (btc->peerGroup->numHdrToFetch > 0) {
         time_t last_ts = blockstore_get_timestamp(bs);
         mtime_t lag    = (time(NULL) - last_ts) * 1000 * 1000;
         char *lagStr   = print_latency(lag);

         Warning(LGPFX" downloading %d header%s -- %s late\n",
                 btc->peerGroup->numHdrToFetch,
                 btc->peerGroup->numHdrToFetch > 1 ? "s" : "",
                 lagStr);
         free(lagStr);
      }
   }
   return peer_send_getheaders(peer);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_download_filtered_blocks --
 *
 *      BITC_STATE_UPDATE_HEADERS -> BITC_STATE_UPDATE_TXDB
 *
 *------------------------------------------------------------------------
 */

int
peergroup_download_filtered_blocks(struct peer *peer)
{
   struct blockstore *bs = btc->blockStore;
   uint256 walletHash;
   uint256 lastHashStore;
   uint256 startHash;
   uint256 *nextHash;
   uint64 birth;
   bool first;
   int res = 0;
   int n;

   if (btc->state != BITC_STATE_UPDATE_HEADERS &&
       btc->state != BITC_STATE_UPDATE_TXDB) {
       return 0;
    }
   ASSERT(btc->state == BITC_STATE_UPDATE_HEADERS ||
          btc->state == BITC_STATE_UPDATE_TXDB);

   first = btc->state == BITC_STATE_UPDATE_HEADERS;

   if (first && btc->peerGroup->numHdrToFetch > 0) {
      mtime_t lat = time_get() - btc->peerGroup->firstConnectTS;
      char *s = print_latency(lat);
      Warning(LGPFX" %d header%s downloaded in %s\n",
              btc->peerGroup->numHdrToFetch,
              btc->peerGroup->numHdrToFetch > 1 ? "s" : "", s);
      free(s);
   }
   Log(LGPFX" %s -- BITC_STATE_UPDATE_TXDB.\n", __FUNCTION__);
   btc->state = BITC_STATE_UPDATE_TXDB;
   bitcui_set_status("online, fetching tx..");

   /*
    * - Get hash of the wallet birth.
    * - Get the hash of the last block processed.
    */
   birth = wallet_get_birth(btc->wallet);
   blockstore_get_hash_from_birth(bs, birth, &walletHash);
   peergroup_get_lastblk(btc->peerGroup, &lastHashStore);

   /*
    * Get the youngest of the two.
    */
   blockstore_get_highest(bs, &walletHash, &lastHashStore, &startHash);

   if (first) {
      char hashStr[80];
      peergroup_set_lastblk(btc->peerGroup, &startHash);

      btc->peerGroup->numToFetch = blockstore_get_height(bs)
         - blockstore_get_block_height(bs, &startHash);
      uint256_snprintf_reverse(hashStr, sizeof hashStr, &startHash);
      Log(LGPFX" downloading starting at %s\n", hashStr);
   }

   Log(LGPFX" downloading %d filtered block%s..\n",
       btc->peerGroup->numToFetch,
       btc->peerGroup->numToFetch > 1 ? "s" : "");
   blockstore_get_next_hashes(bs, &startHash, &nextHash, &n);

   peergroup_download_progress();

   if (n >= 1) {
      btc->peerGroup->lastFilteredBlockReq = nextHash[n - 1];

      res = peer_send_getdata(peer, INV_TYPE_MSG_FILTERED_BLOCK,
                              nextHash, n);
      ASSERT(res == 0);
   } else {
      peergroup_download_complete();
   }
   free(nextHash);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_download_filtered_blocks_continue --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_download_filtered_blocks_continue(struct peer *peer)
{
   uint256 best_hash;
   uint256 lastTxdb;
   int res = 0;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   peergroup_download_progress();
   blockstore_get_best_hash(btc->blockStore, &best_hash);
   peergroup_get_lastblk(btc->peerGroup, &lastTxdb);

   if (uint256_issame(&lastTxdb, &best_hash)) {
      peergroup_download_complete();
   } else if (uint256_issame(&lastTxdb, &btc->peerGroup->lastFilteredBlockReq)) {
      uint256 *nextHash;
      int n;

      blockstore_get_next_hashes(btc->blockStore, &lastTxdb, &nextHash, &n);

      Log(LGPFX" %s: querying %d blocks: %u processed out of %d\n",
          peer_name(peer), n, btc->peerGroup->numFetched, btc->peerGroup->numToFetch);

      ASSERT(n > 0);
      btc->peerGroup->lastFilteredBlockReq = nextHash[n - 1];

      res = peer_send_getdata(peer, INV_TYPE_MSG_FILTERED_BLOCK, nextHash, n);
      free(nextHash);
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_queue_peerlist --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_queue_peerlist(struct circlist_item *li)
{
   circlist_queue_item(&btc->peerGroup->peer_list, li);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_dequeue_peerlist --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_dequeue_peerlist(const struct circlist_item *li)
{
   /*
    * It's possible we get here on an error path from peer_add if we fail to
    * connect synchronously.
    */
   if (li->next && li->prev) {
      circlist_delete_item(&btc->peerGroup->peer_list, li);
   }
   btc->peerGroup->active--;

   if (btc->state != BITC_STATE_EXITING) {
      peergroup_update_info();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_send_stats_inc --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_send_stats_inc(enum btc_msg_type type)
{
   ASSERT(type < BTC_MSG_MAX);
   cmdStats[type].sent++;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_recv_stats_inc --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_recv_stats_inc(enum btc_msg_type type)
{
   ASSERT(type < BTC_MSG_MAX);
   cmdStats[type].received++;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_print_stats --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_print_stats(struct peergroup *peerGroup)
{
   enum btc_msg_type i;

   Log(LGPFX" active=%u maxActive=%u\n",
       peerGroup->active, peerGroup->maxActive);

   for (i = 0; i < BTC_MSG_MAX; i++) {
      if (cmdStats[i].received != 0 || cmdStats[i].sent != 0) {
         Log(LGPFX" %11s: %6u  / %5u\n",
             btcmsg_type_to_str(i), cmdStats[i].received, cmdStats[i].sent);
      }
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_refill --
 *
 *-------------------------------------------------------------------------
 */

void
peergroup_refill(bool init)
{
   struct peergroup *pg = btc->peerGroup;
   uint32 numTried = 0;
   uint32 numAddrs;
   uint32 max;

   /*
    * In connect-only mode we never draw peers from the address book; the sole
    * peer is added exactly once by peergroup_seed() at startup. Re-seeding here
    * would spawn duplicate connections while the first is still pending (and
    * get us rate-limited by the peer), so do nothing.
    */
   if (btc->connectHost) {
      return;
   }

   numAddrs = addrbook_get_count(btc->book);

   if (numAddrs <= 2 * pg->active) {
      return;
   }

   max = pg->maxActive;
   if (init) {
      max = MAX(max, pg->minActiveInit);
   }

   while (numTried < 2000 && pg->active < max) {
      struct peer_addr *paddr;

      numTried++;
      paddr = addrbook_get_rand_addr(btc->book);
      if (paddr == NULL) {
         NOT_TESTED();
         return;
      }

      if (paddr->triedalready) {
         continue;
      }
      if ((paddr->addr.services & BTC_SERVICE_NODE_NETWORK) == 0) {
         continue;
      }

      if (paddr->connected) {
         /* we may have better luck next time */
         continue;
      }
      peergroup_add_peer(paddr);
   }
   peergroup_update_info();
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_notify_destroy --
 *
 *-------------------------------------------------------------------------
 */

void
peergroup_notify_destroy(void)
{
   if (bitc_exiting()) {
      return;
   }

   peergroup_refill(FALSE);
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_check_liveness --
 *
 *-------------------------------------------------------------------------
 */

static void
peergroup_check_liveness(void)
{
   struct circlist_item *next;
   struct circlist_item *li;
   mtime_t now = time_get();

   CIRCLIST_SCAN_SAFE(li, next, btc->peerGroup->peer_list) {
      peer_check_liveness(li, now);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_periodic_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
peergroup_periodic_cb(void *clientData)
{
   if (bitc_exiting()) {
      return;
   }
   peergroup_refill(FALSE);
   peergroup_check_liveness();
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_init --
 *
 *-------------------------------------------------------------------------
 */

void
peergroup_init(struct config *config,
               uint32 maxPeers,
               uint32 minPeersInit,
               mtime_t periodUsec)
{
   struct peergroup *pg;
   char *hashStr;

   Log(LGPFX" maxPeers=%u period=%.1f msec\n",
       maxPeers, periodUsec / 1000.0);

   pg = safe_calloc(1, sizeof *btc->peerGroup);
   pg->peer_list     = NULL;
   pg->active        = 0;
   pg->startTS       = time_get();
   pg->maxActive     = maxPeers;
   pg->minActiveInit = minPeersInit;

   memset(pg->lastBlk.data, 0, sizeof(uint256));
   pg->hash_broadcast = hashtable_create();

   hashStr = config_getstring(config, NULL, "peergroup.lastblk");
   if (hashStr) {
      bool s = uint256_from_str(hashStr, &pg->lastBlk);
      Log(LGPFX" loading lastBlk: %s\n", hashStr);
      if (s == 0) {
         Warning(LGPFX" failed to parse lastBlk: %s\n", hashStr);
      }
      free(hashStr);
   }

   btc->peerGroup = pg;
   peergroup_update_info();

   poll_callback_time(btc->poll, periodUsec, 1 /* permanent */,
                      peergroup_periodic_cb, NULL);
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_add_peer_from_str --
 *
 *-------------------------------------------------------------------------
 */

static void
peergroup_add_peer_from_str(struct poll_loop *poll,
                            const char *hostname,
                            uint16 port)
{
   struct sockaddr_in sockaddr = { 0 };
   struct peer_addr *paddr;
   int res;
   bool s;

   Log(LGPFX" seeding %s\n", hostname);
   res = netasync_resolve(hostname, port, &sockaddr);
   if (res != 0) {
      return;
   }

   ASSERT_ON_COMPILE(sizeof(sockaddr.sin_addr) == 4);

   paddr = safe_calloc(1, sizeof *paddr);
   memcpy(paddr->addr.ip + 12, &sockaddr.sin_addr, sizeof(sockaddr.sin_addr));
   paddr->addr.ip[10] = 0xff;
   paddr->addr.ip[11] = 0xff;
   paddr->addr.port   = htons(port);
   paddr->addr.time   = 0; // will be initialized quickly if connection ok.
   paddr->addr.services = 1;

   s = addrbook_add_entry(btc->book, paddr);
   if (s == 0) {
      addrbook_replace_entry(btc->book, paddr);
   }

   peergroup_add_peer(paddr);
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_seed --
 *
 *-------------------------------------------------------------------------
 */

void
peergroup_seed(void)
{
   const char **seeds;
   uint16 port;
   int i;
   int n;

   port = btc->testnet ? BTC_PORT_TESTNET : BTC_PORT_MAIN;

   /*
    * -C/--connect: talk only to an explicit, comma-separated list of peers and
    * skip DNS seeds and the (possibly stale/polluted) address book entirely.
    * Each entry is "host" or "host:port"; without a port the network default
    * is used. Handy for iterating against known-good nodes without recompiling.
    */
   if (btc->connectHost) {
      char *list = safe_strdup(btc->connectHost);
      char *saveptr = NULL;
      char *tok;

      Log(LGPFX" connect-only mode: %s\n", btc->connectHost);
      for (tok = strtok_r(list, ",", &saveptr); tok != NULL;
           tok = strtok_r(NULL, ",", &saveptr)) {
         uint16 hostport = port;
         char *colon = strrchr(tok, ':');

         if (colon) {
            *colon = '\0';
            hostport = atoi(colon + 1);
         }
         if (tok[0] != '\0') {
            peergroup_add_peer_from_str(btc->poll, tok, hostport);
         }
      }
      free(list);
      return;
   }

   n = config_getint64(btc->config, 0, "numstaticpeers");
   for (i = 0; i < n; i++) {
      char *addr = config_getstring(btc->config, NULL, "peer%u.address", i);
      if (addr == NULL) {
         break;
      }
      Log(LGPFX" adding static peer '%s'\n", addr);
      peergroup_add_peer_from_str(btc->poll, addr, port);
      free(addr);
   }

   /*
    * Always pull in the DNS seeds. The previous "skip if the book already has
    * >= 200 entries" shortcut meant that once the address book filled up with
    * junk (e.g. a monitoring-node cluster), it could never recover because the
    * diverse seed peers were never re-added.
    */
   if (btc->testnet) {
      n = ARRAYSIZE(peer_seeds_testnet);
      seeds = peer_seeds_testnet;
   } else {
      n = ARRAYSIZE(peer_seeds_main);
      seeds = peer_seeds_main;
   }

   for (i = 0; i < n; i++) {
      peergroup_add_peer_from_str(btc->poll, seeds[i], port);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_save_lastblk --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_save_lastblk(struct config *config,
                       const uint256 *hash)
{
   char hashStr[80];

   uint256_snprintf_reverse(hashStr, sizeof hashStr, hash);
   if (!uint256_iszero(hash)) {
      Log(LGPFX" saving lastBlk: %s\n", hashStr);
   }

   config_setstring(config, hashStr, "peergroup.lastblk");
   config_save(config);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_zap --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_zap(struct config *config)
{
   uint256 zero;

   memset(&zero, 0, sizeof zero);

   peergroup_save_lastblk(config, &zero);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_destroy --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_destroy_peers(void)
{
   while (!circlist_empty(btc->peerGroup->peer_list)) {
      peer_destroy(btc->peerGroup->peer_list, 0 /* success */);
   }

   ASSERT(btc->peerGroup->active == 0);
   ASSERT(btc->peerGroup->peer_list == NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_exit --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_exit(struct peergroup *pg)
{
   bool s;

   if (pg == NULL) {
      return;
   }
   ASSERT(btc->poll);

   s = poll_callback_time_remove(btc->poll, 1, peergroup_periodic_cb, NULL);
   ASSERT_NOT_TESTED(s);

   if (btc->updateAndExit && btc->stop == 1) {
      mtime_t delay = time_get() - pg->startTS;
      char *str = print_latency(delay);
      Warning("Synchronized block-store in %s.\n", str);
      free(str);
   }

   if (pg->configNeedWrite) {
      peergroup_save_lastblk(btc->config, &pg->lastBlk);
   }

   hashtable_clear_with_callback(pg->hash_broadcast, peergroup_free_tx_broadcast_cb);
   hashtable_destroy(pg->hash_broadcast);
   peergroup_print_stats(pg);
   peergroup_destroy_peers();
   free(btc->peerGroup);
   btc->peerGroup = NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_handshake_ok --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_handle_handshake_ok(struct peer *peer,
                              int peerStartingHeight)
{
   struct peergroup *pg = btc->peerGroup;

   if (peergroup_count_connected() > pg->maxActive) {
      return 1;
   }

   peergroup_update_info();

   if (pg->firstConnectTS == 0) {
      pg->firstConnectTS = time_get();
   }

   /*
    * We've now established & validated a connection with the peer.
    * We need to decide what to do next based on the state.
    */

   if (btc->state == BITC_STATE_STARTING ||
       btc->state == BITC_STATE_UPDATE_HEADERS) {
      return peergroup_download_headers(peer, peerStartingHeight);
   } else if (btc->state == BITC_STATE_UPDATE_TXDB) {
      return peergroup_download_filtered_blocks(peer);
   } else if (btc->state == BITC_STATE_READY) {
      return peer_on_ready(peer);
   } else {
      ASSERT(btc->state == BITC_STATE_EXITING);
      return 0;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_headers --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_handle_headers(struct peer            *peer,
                         int                     peerStartingHeight,
                         const btc_block_header *headers,
                         int                     n)
{
   struct blockstore *bs = btc->blockStore;
   int numOrphans = 0;
   int numAdded = 0;
   int height;
   int i;

   /*
    * Ignore headers from any peer other than the designated download peer, so
    * we never process two header streams into the shared block store at once.
    */
   if (btc->peerGroup->downloadPeer != NULL &&
       btc->peerGroup->downloadPeer != peer) {
      return 0;
   }

   for (i = 0; i < n; i++) {
      const btc_block_header *hdr = headers + i;
      char hashStr[80];
      uint256 hash;
      bool orphan;
      bool s;

      hash256_calc(hdr, sizeof *hdr, &hash);
      uint256_snprintf_reverse(hashStr, sizeof hashStr, &hash);

      s = blockstore_add_header(bs, hdr, &hash, &orphan);
      if (orphan) {
         numOrphans++;
         bitcui_set_status("Block %s orphaned (count = %d)", hashStr, numOrphans);
      }
      if (s) {
         numAdded++;
         btc->peerGroup->numHdrFetched++;
         if (btc->peerGroup->numHdrFetched % 100000 == 0) {
            Warning(LGPFX" fetched %6d headers out of %d\n",
                    btc->peerGroup->numHdrFetched, btc->peerGroup->numHdrToFetch);
         }
         peergroup_add_block_finalize(bs, TRUE /* header ony */);
      }
   }

   peergroup_download_progress();
   height = blockstore_get_height(bs);

   /*
    * Keep the progress target sensible even when peers under-report their
    * best height in the 'version' handshake (some nodes advertise 0).
    */
   if (height > btc->peerGroup->heightTarget) {
      btc->peerGroup->heightTarget = height;
   }

   /*
    * Headers-first sync: a 'headers' message carries up to 2000 entries, so as
    * long as the peer handed us new headers there are likely more to fetch.
    * We must NOT rely on the peer's advertised startingHeight to decide when to
    * stop -- many nodes report 0 -- and instead keep asking until a response
    * adds nothing new (empty batch == we reached the tip).
    */
   if (numAdded > 0 && btc->state == BITC_STATE_UPDATE_HEADERS) {
      return peer_send_getheaders(peer);
   }

   return peergroup_download_filtered_blocks(peer);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_broadcast_inv --
 *
 *------------------------------------------------------------------------
 */

static int
peergroup_broadcast_inv(struct peergroup *pg,
                        struct buff *bufInv)
{
   struct circlist_item *next;
   struct circlist_item *li;
   int res = 0;

   CIRCLIST_SCAN_SAFE(li, next, pg->peer_list) {
      res = peer_send_inv(li, bufInv);
      if (res) {
         Warning(LGPFX" %s: failed to send inv: %s (%d)\n",
                 peer_name_li(li), strerror(res), res);
      }
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_add_tx_broadcast_hash --
 *
 *------------------------------------------------------------------------
 */

static void
peergroup_add_tx_broadcast_hash(struct peergroup  *pg,
                                const struct buff *buf,
                                mtime_t            expiry,
                                const uint256     *hash)
{
   struct tx_broadcast *txb;
   bool s;

   txb = safe_malloc(sizeof *txb);
   txb->buf    = buff_dup(buf);
   txb->expiry = expiry;

   s = hashtable_insert(pg->hash_broadcast, hash, sizeof *hash, txb);
   if (s == 0) {
      buff_free(txb->buf);
      free(txb);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_tx_broadcast --
 *
 *------------------------------------------------------------------------
 */

static int
peergroup_tx_broadcast(struct peergroup *pg,
                       const uint256 *hash)
{
   struct buff *bufInv;
   int res;

   res = btcmsg_craft_inv(&bufInv, INV_TYPE_MSG_TX, hash, 1);
   ASSERT(res == 0);

   res = peergroup_broadcast_inv(pg, bufInv);
   buff_free(bufInv);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_new_tx_broadcast --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_new_tx_broadcast(struct peergroup  *pg,
                           const struct buff *buf,
                           mtime_t            expiry,
                           const uint256     *hash)
{
   if (pg == NULL) {
      return 0;
   }
   ASSERT(pg);
   ASSERT(hash);

   peergroup_add_tx_broadcast_hash(pg, buf, expiry, hash);

   return peergroup_tx_broadcast(pg, hash);
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_addr --
 *
 *------------------------------------------------------------------------
 */

void
peergroup_handle_addr(struct peer      *peer,
                      btc_msg_address **addrs,
                      size_t            numAddrs)
{
   bool update = 0;
   size_t i;

   for (i = 0; i < numAddrs; i++) {
      struct peer_addr *a;
      bool s;

      a = safe_calloc(1, sizeof *a);
      memcpy(&a->addr, addrs[i], sizeof a->addr);
      s = addrbook_add_entry(btc->book, a);
      if (s == 0) {
         free(a);
      } else {
         update = 1;
      }
      free(addrs[i]);
   }
   free(addrs);

   if (update) {
      peergroup_update_info();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_merkleblock --
 *
 *------------------------------------------------------------------------
 */

int
peergroup_handle_merkleblock(struct peer *peer,
                             const btc_msg_merkleblock *blk)
{
   ASSERT(btc->state == BITC_STATE_READY ||
          btc->state == BITC_STATE_UPDATE_TXDB);

   peergroup_process_filtered_block(peer, blk);
   wallet_confirm_tx_in_block(btc->wallet, blk);

   if (btc->state == BITC_STATE_READY) {
      return 0;
   }

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   return peergroup_download_filtered_blocks_continue(peer);
}

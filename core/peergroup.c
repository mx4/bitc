#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
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
#include "serialize.h"
#include "gcs.h"
#include "cfheader-store.h"
#include "peerstats.h"

#define LGPFX   "PEERG:"

/*
 * peergroup_periodic_cb runs every 15s (see peergroup_init's periodUsec in
 * main.c), so for the header-sync stall detector the detection latency is
 * bounded by that period, not by this threshold; it is set below the tick
 * period so a genuine stall is always caught on the very next tick. For
 * pending-block-fetch retries (peergroup_check_pending_blocks), it is simply
 * the maximum time to wait for a getdata(MSG_BLOCK) response before trying a
 * different peer.
 */
#define SYNC_STALL_USEC (10 * 1000 * 1000)  /* 10 seconds */

/*
 * Max cfilters per getcfilters request (BIP157 limit); also the chunk size
 * for the parallel cfilter scan. Defined here (rather than next to its main
 * user, peergroup_assign_chunk) because CF_CHUNK_INDEX and
 * peergroup_handle_cfilter, both much earlier in the file, need it too.
 */
#define CFILTER_BATCH 1000

/*
 * BIP157 fixes the getcfcheckpt interval at 1000 blocks (a spec constant,
 * not configurable) -- kept as a separate name from CFILTER_BATCH even
 * though both happen to be 1000, since they mean different things: one is
 * our chosen chunk size, the other is the wire protocol's checkpoint
 * spacing.
 */
#define BIP157_CHECKPOINT_INTERVAL 1000

/* Which cfSeg[] entry covers a given absolute block height. */
#define CF_CHUNK_INDEX(_pg, _height) (((_height) - (_pg)->cfScanFloor) / CFILTER_BATCH)

/* Cap on concurrently in-flight cfilter chunks, so a large -n doesn't fan out
 * an unbounded number of simultaneous getcfilters streams. */
#define MAX_INFLIGHT_CHUNKS 64

/* Forward declarations. */
static void peergroup_schedule_cfilters(void);
static void peergroup_assign_next_chunk_to(struct peer *peer);
static void peergroup_advance_lastblk(void);
static void peergroup_maybe_complete(void);
static int peergroup_request_cfheaders(struct peer *peer);
static int peergroup_verify_cfcheckpts(struct peer *peer);
static void peergroup_add_pending_block(const uint256 *hash, struct peer *from);
static void peergroup_remove_pending_block(const uint256 *hash);
static void peergroup_save_lastblk(struct config *config, const uint256 *hash);


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
   struct tx_broadcast *txb = clientData;

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

s = hashtable_lookup(pg->hash_broadcast, hash, sizeof *hash, (void **)&txb);
    if (s == 0) {
       return;
   }

   uint256_snprintf_reverse(hashStr, sizeof hashStr, hash);
   log_warn(LGPFX" stop relaying tx %s\n", hashStr);

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

s = hashtable_lookup(pg->hash_broadcast, hash, sizeof *hash, (void **)&txb);
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

   log_info(LGPFX" was %s\n", prev);
   log_info(LGPFX" now %s\n", next);
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
      log_warn(LGPFX" peers: %u\n", btc->peerGroup->active);
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
   struct peergroup *pg = btc->peerGroup;
   static mtime_t lastUIUpdateTS;
   mtime_t now = time_get();

   /* Any call here means the sync just made forward progress. */
   pg->lastProgressTS = now;

   /*
    * bitcui_set_catchup_info() below funnels through the UI's request queue
    * (bitcui_req_enqueue), which is mutex-shared with the render thread. The
    * BIP157 cfilter path calls this function once per verified FILTER --
    * hundreds/sec during a scan -- and a `sample` profile showed that lock
    * wait alone was the single largest consumer of poll-thread CPU. A
    * progress bar visibly updating 10x/sec is indistinguishable from one
    * updating on every filter, so throttle the actual UI push; the cheap
    * lastProgressTS stall-detection timestamp above is still updated on
    * every call, unthrottled.
    */
   if (now - lastUIUpdateTS < 100 * 1000 /* 100ms */) {
      return;
   }
   lastUIUpdateTS = now;

   /*
    * In the BIP157 path, report cfilter scan progress (how many cfilters
    * have been verified) instead of the legacy numFetched/numToFetch
    * (which count matched blocks, not filters scanned).
    */
   if (pg->cfTipHeight >= 0) {
      bitcui_set_catchup_info(pg->numHdrFetched, pg->numHdrToFetch,
                             pg->cfVerified, pg->cfTipHeight);
   } else {
      bitcui_set_catchup_info(pg->numHdrFetched, pg->numHdrToFetch,
                             pg->numFetched,    pg->numToFetch);
   }
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

   log_info(LGPFX" peergroup ready.\n");
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
      log_warn(LGPFX" %d filtered blocks downloaded. refresh complete.\n",
              btc->peerGroup->numFetched);
   } else {
      log_warn(LGPFX" headers and filtered blocks up to date.\n");
   }
   peergroup_download_progress();

   if (btc->updateAndExit) {
      bitc_req_stop();
   } else {
      log_info(LGPFX" %s -- BITC_STATE_READY.\n", __func__);
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
 * peergroup_handle_cfilter --
 *
 *      BIP157: receive a compact filter, GCS-match it against the wallet's
 *      scriptPubKeys, and request the full block if it matches.
 *
 *------------------------------------------------------------------------
 */
int
peergroup_handle_cfilter(struct peer *peer, const btc_msg_cfilter *cf)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint8 **scripts;
   size_t *scriptLens;
   size_t numScripts;
   uint256 blockHash;
   int blockHeight;
   struct cf_segment *seg = NULL;
   bool mine;
   bool match;
   int res;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB ||
          btc->state == BITC_STATE_READY);

   /*
    * Look up the block height for this filter's block hash.
    */
   blockHash = cf->blockHash;
   blockHeight = blockstore_get_block_height(bs, &blockHash);
   if (blockHeight < 0) {
      log_warn(LGPFX" BIP157: cfilter for unknown block hash; skipping.\n");
      return 0;
   }

   /*
    * Verify the filter against the stored filter header chain.
    * filterHash = hash256(filterData); this must match the stored hash at
    * this height, and filterHeader = hash256(filterHash || prevFilterHeader)
    * must match the stored header. This is what makes BIP157 trust-minimized.
    * This check is independent of which peer/chunk this filter is
    * associated with -- verification is keyed purely by height -- so it is
    * always performed, even for a filter that arrives after its chunk was
    * reassigned to someone else (see 'mine' below).
    */
   if (pg->cfStore) {
      uint256 storedHash;
      uint256 computedHash;

      res = cfheaderstore_get_hash(pg->cfStore, blockHeight, &storedHash);
      if (res) {
         log_warn(LGPFX" BIP157: no stored filter hash at height %d; skipping.\n",
                 blockHeight);
         return 0;
      }
      hash256_calc(cf->filterData, cf->numBytes, &computedHash);
      if (uint256_issame(&computedHash, &storedHash) == 0) {
         log_warn(LGPFX" BIP157: cfilter hash mismatch at height %d! "
                 "Peer may be serving fake filters.\n", blockHeight);
         return 1;
      }
      /*
       * No per-filter success log here: at a few hundred filters/sec this
       * line alone (plus LogPrintf's fflush()) was a measurable share of the
       * single poll thread's CPU. Chunk-level "assigned"/"complete" already
       * report coarser progress; a mismatch above still logs immediately.
       */
   }

   pg->cfVerified++;
   peergroup_download_progress();

   /*
    * Locate the chunk covering this height and confirm this peer is still
    * the one it was assigned to (chunks are fixed-size and cfSeg is indexed
    * directly by height, so this is O(1), not a search). A cfilter arriving
    * from any other peer -- a late reply after the chunk was reassigned on
    * disconnect/stall (peergroup_requeue_peer_chunks /
    * peergroup_check_pending_chunks), a duplicate, or an unsolicited send --
    * has already been cryptographically verified above, so it is harmless to
    * have received, but must NOT affect chunk bookkeeping: double-decrementing
    * 'remaining' would mark the chunk done early and let the resume watermark
    * skip past heights nobody actually scanned.
    */
   mine = 0;
   if (pg->cfSeg != NULL) {
      int idx = CF_CHUNK_INDEX(pg, blockHeight);
      if (idx >= 0 && idx < pg->cfSegCount) {
         seg = &pg->cfSeg[idx];
         mine = (seg->assignedPeer == peer && !seg->done);
      }
   }

   if (mine) {
      seg->remaining--;
      seg->progressTS = time_get();
      if (seg->remaining <= 0) {
         seg->done = 1;
         log_info(LGPFX" BIP157: cfilter chunk [%d..%d] complete.\n",
             seg->startHeight, seg->endHeight);
         peerstats_record_cfilter_ok(pg->peerStats, peer_get_ip(peer),
                                     (uint32)(seg->progressTS - seg->assignedTS));
         while (pg->cfDoneContig < pg->cfSegCount &&
                pg->cfSeg[pg->cfDoneContig].done) {
            pg->cfDoneContig++;
         }
         /*
          * Persist progress: advance the resume pointer as far as is safe
          * (every height up to the contiguous watermark has been verified,
          * and no matched-but-unprocessed block is being skipped over). See
          * peergroup_advance_lastblk. Without this, an interrupted run would
          * restart from scratch.
          */
         peergroup_advance_lastblk();
         /* Keep this peer busy: hand it the next unclaimed chunk, if any. */
         peergroup_assign_next_chunk_to(peer);
      }
   }

   /*
    * --stop-after-height: once the scan passes the given height, stop
    * requesting new cfilters. But defer the actual stop until any matched
    * full blocks still in flight have been received and processed, so we
    * don't miss the very transaction we were scanning for.
    */
   if (btc->stopAfterHeight > 0 && blockHeight >= btc->stopAfterHeight) {
      if (!btc->peerGroup->cfStopRequested) {
         log_warn(LGPFX" BIP157: reached stop-after-height %d; "
                 "draining %d pending block(s).\n",
                 btc->stopAfterHeight, btc->peerGroup->cfBlocksPending);
         btc->peerGroup->cfStopRequested = 1;
      }
      if (btc->peerGroup->cfBlocksPending == 0) {
         peergroup_download_complete();
         bitc_req_stop();
      }
      return 0;
   }

   /*
    * GCS-match the filter against the wallet's scriptPubKeys. The returned
    * arrays are cached inside the wallet and owned by it (rebuilt only when
    * a key is added) -- do not free them here; see wallet_get_filter_scripts.
    */
   wallet_get_filter_scripts(btc->wallet, &scripts, &scriptLens, &numScripts);
   if (numScripts == 0) {
      match = 0;
   } else {
      match = gcs_filter_match_any(cf->filterData, cf->numBytes,
                                   &blockHash,
                                   (const uint8 * const *)scripts,
                                   scriptLens, numScripts);
   }

   if (match) {
      log_info(LGPFX" BIP157: cfilter match at height %d; requesting full block.\n",
          blockHeight);
      pg->numFetched++;
      peergroup_add_pending_block(&blockHash, peer);
      res = peer_send_getdata(peer, INV_TYPE_MSG_BLOCK, &blockHash, 1);
      if (res) {
         return res;
      }
   }

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_add_pending_block --
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_add_pending_block(const uint256 *hash, struct peer *from)
{
   struct peergroup *pg = btc->peerGroup;

   if (pg->cfBlocksPending >= pg->cfPendingCap) {
      pg->cfPendingCap = pg->cfPendingCap ? pg->cfPendingCap * 2 : 8;
      pg->cfPending = safe_realloc(pg->cfPending,
                                   pg->cfPendingCap * sizeof *pg->cfPending);
   }
   pg->cfPending[pg->cfBlocksPending].hash          = *hash;
   pg->cfPending[pg->cfBlocksPending].height        =
      blockstore_get_block_height(btc->blockStore, hash);
   pg->cfPending[pg->cfBlocksPending].requestedFrom = from;
   pg->cfPending[pg->cfBlocksPending].requestTS     = time_get();
   pg->cfBlocksPending++;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_maybe_complete --
 *
 *      Shared completion check for the parallel cfilter scan: every chunk
 *      verified, no matched block still in flight, and the resume pointer
 *      has caught up to the current chain tip.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_maybe_complete(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct blockstore *bs = btc->blockStore;
   uint256 best_hash;
   uint256 lastTxdb;

   if (btc->state != BITC_STATE_UPDATE_TXDB) {
      return;
   }
   if (pg->cfDoneContig < pg->cfSegCount || pg->cfBlocksPending != 0) {
      return;
   }
   blockstore_get_best_hash(bs, &best_hash);
   peergroup_get_lastblk(pg, &lastTxdb);
   if (uint256_issame(&lastTxdb, &best_hash)) {
      peergroup_download_complete();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_advance_lastblk --
 *
 *      Advance the crash-safe resume pointer (peergroup.lastblk) as far as
 *      is currently safe. Chunks can complete out of order, so the furthest
 *      point we may claim as "verified" is the contiguous watermark
 *      (cfDoneContig chunks from the scan floor, with no gap) -- NOT simply
 *      the highest chunk that happens to be done. That watermark is further
 *      clamped to just below the lowest still-in-flight matched-block fetch
 *      (cfPending), so a crash can never lose a transaction whose block was
 *      matched but not yet processed into the wallet. This makes the
 *      parallel scan's resume point strictly safer than the old serial
 *      scan's, which advanced lastBlk on every verified cfilter regardless
 *      of pending matched blocks.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_advance_lastblk(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct blockstore *bs = btc->blockStore;
   uint256 curLastBlk;
   uint256 hash;
   int contigHeight;
   int minPending;
   int safeHeight;
   int curHeight;
   int i;

   if (pg->cfDoneContig == 0) {
      return;
   }

   contigHeight = pg->cfSeg[pg->cfDoneContig - 1].endHeight;

   minPending = INT_MAX;
   for (i = 0; i < pg->cfBlocksPending; i++) {
      if (pg->cfPending[i].height < minPending) {
         minPending = pg->cfPending[i].height;
      }
   }

   safeHeight = MIN(contigHeight, minPending - 1);
   if (safeHeight < pg->cfScanFloor) {
      return;
   }

   peergroup_get_lastblk(pg, &curLastBlk);
   curHeight = blockstore_get_block_height(bs, &curLastBlk);
   if (safeHeight <= curHeight) {
      return;   /* no forward progress */
   }

   if (!blockstore_get_block_at_height(bs, safeHeight, &hash, NULL)) {
      log_warn(LGPFX" BIP157: cannot get block hash at height %d for resume pointer.\n",
              safeHeight);
      return;
   }
   peergroup_set_lastblk(pg, &hash);
   peergroup_maybe_complete();
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_assign_chunk --
 *
 *      Send getcfilters for one scan chunk to 'peer' and mark it assigned.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_assign_chunk(struct peer *peer, struct cf_segment *seg)
{
   struct blockstore *bs = btc->blockStore;
   uint256 stopHash;
   int res;

   res = blockstore_get_block_at_height(bs, seg->endHeight, &stopHash, NULL);
   if (!res) {
      log_warn(LGPFX" BIP157: cannot get block hash at height %d for cfilter chunk.\n",
              seg->endHeight);
      return;
   }

   res = peer_send_getcfilters(peer, BTC_CFILTER_TYPE_BASIC,
                               seg->startHeight, &stopHash);
   if (res) {
      log_warn(LGPFX" BIP157: failed to send getcfilters [%d..%d] to %s.\n",
              seg->startHeight, seg->endHeight, peer_name(peer));
      return;
   }

   seg->assignedPeer = peer;
   seg->avoidPeer    = NULL;
   seg->remaining    = seg->endHeight - seg->startHeight + 1;
   seg->progressTS   = time_get();
   seg->assignedTS   = seg->progressTS;

   log_info(LGPFX" BIP157: assigned cfilter chunk [%d..%d] to %s.\n",
       seg->startHeight, seg->endHeight, peer_name(peer));
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_assign_next_chunk_to --
 *
 *      Give 'peer' the next unclaimed chunk (never assigned, or requeued
 *      after a disconnect/stall), if any remain. Called when a peer's
 *      current chunk finishes, to keep it continuously busy without
 *      round-tripping through the full scheduler. Skips a chunk whose
 *      avoidPeer is this same peer (see struct cf_segment) so a peer that
 *      just stalled on a chunk isn't immediately handed the same chunk back.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_assign_next_chunk_to(struct peer *peer)
{
   struct peergroup *pg = btc->peerGroup;
   int i;

   for (i = 0; i < pg->cfSegCount; i++) {
      struct cf_segment *seg = &pg->cfSeg[i];
      if (seg->assignedPeer == NULL && !seg->done && seg->avoidPeer != peer) {
         peergroup_assign_chunk(peer, seg);
         return;
      }
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_schedule_cfilters --
 *
 *      Fan out unclaimed cfilter chunks to every idle, connected,
 *      NODE_COMPACT_FILTERS-capable peer, up to MAX_INFLIGHT_CHUNKS chunks
 *      in flight at once. This is what makes the cfilter scan parallel:
 *      instead of one peer streaming the whole [floor, tip] range
 *      sequentially, every filter-capable peer streams a different chunk
 *      concurrently. Safe to call any time (new peer joining, periodic tick,
 *      after a requeue); peers that already own a live chunk, or chunks that
 *      are already claimed or done, are simply skipped.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_schedule_cfilters(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct circlist_item *li;
   int inflight;
   int i;

   if (pg->cfSeg == NULL) {
      return;
   }

   inflight = 0;
   for (i = 0; i < pg->cfSegCount; i++) {
      if (pg->cfSeg[i].assignedPeer != NULL && !pg->cfSeg[i].done) {
         inflight++;
      }
   }

   CIRCLIST_SCAN(li, pg->peer_list) {
      struct peer *p;
      bool busy;

      if (inflight >= MAX_INFLIGHT_CHUNKS) {
         break;
      }
      if (!peer_is_connected(li) ||
          !(peer_get_services(li) & BTC_SERVICE_NODE_COMPACT_FILTERS)) {
         continue;
      }
      p = peer_from_li(li);

      busy = 0;
      for (i = 0; i < pg->cfSegCount; i++) {
         if (pg->cfSeg[i].assignedPeer == p && !pg->cfSeg[i].done) {
            busy = 1;
            break;
         }
      }
      if (busy) {
         continue;
      }

      for (i = 0; i < pg->cfSegCount; i++) {
         struct cf_segment *seg = &pg->cfSeg[i];
         if (seg->assignedPeer == NULL && !seg->done && seg->avoidPeer != p) {
            peergroup_assign_chunk(p, seg);
            inflight++;
            break;
         }
      }
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_check_pending_chunks --
 *
 *      Periodic check: a chunk whose assigned peer is connected but has made
 *      no progress on it for SYNC_STALL_USEC (unlike a hard disconnect,
 *      which peergroup_requeue_peer_chunks handles immediately) is requeued
 *      for another peer. Already-received heights within the chunk re-verify
 *      idempotently when the reassigned peer streams it again.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_check_pending_chunks(void)
{
   struct peergroup *pg = btc->peerGroup;
   mtime_t now = time_get();
   bool anyRequeued = 0;
   int i;

   if (pg->cfSeg == NULL) {
      return;
   }

   for (i = 0; i < pg->cfSegCount; i++) {
      struct cf_segment *seg = &pg->cfSeg[i];

      if (seg->done || seg->assignedPeer == NULL) {
         continue;
      }
      if (now < seg->progressTS || now - seg->progressTS < SYNC_STALL_USEC) {
         continue;
      }
      log_warn(LGPFX" BIP157: cfilter chunk [%d..%d] stalled on %s; requeuing.\n",
              seg->startHeight, seg->endHeight, peer_name(seg->assignedPeer));
      /*
       * Unlike a disconnect (peergroup_requeue_peer_chunks), which can happen
       * for reasons that say nothing about the peer's quality (we hit
       * -n and evicted it, we're exiting, ...), a peer going quiet for
       * SYNC_STALL_USEC while it holds a chunk is a genuine peer-caused
       * signal: it accepted the request and then stopped answering.
       */
      peerstats_record_cfilter_fail(pg->peerStats, peer_get_ip(seg->assignedPeer));
      /*
       * Remember who just failed this chunk so the scheduler below (and any
       * later assign_next_chunk_to call) doesn't immediately hand it right
       * back to the same still-connected, still-"idle" peer -- which would
       * otherwise re-stall on the same chunk every SYNC_STALL_USEC forever,
       * making zero progress on it while also blocking that peer from being
       * tried on a different, possibly-fine chunk.
       */
      seg->avoidPeer    = seg->assignedPeer;
      seg->assignedPeer = NULL;
      seg->remaining    = seg->endHeight - seg->startHeight + 1;
      anyRequeued = 1;
   }

   if (anyRequeued) {
      peergroup_schedule_cfilters();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_requeue_peer_chunks --
 *
 *      Called from peer_destroy() for every disconnecting peer. Any cfilter
 *      scan chunk this peer owned is requeued (not lost) so the scheduler
 *      hands it to another connected filter peer, instead of that height
 *      range going permanently unscanned.
 *
 *      Deliberately does NOT record a peerstats cfilter failure here: unlike
 *      a stall (peergroup_check_pending_chunks), a disconnect can happen for
 *      reasons that say nothing about this peer's quality -- we hit -n and
 *      evicted it, the process is exiting, a transient network blip -- and
 *      penalizing it would wrongly demote an otherwise-good peer out of the
 *      preferred set.
 *
 *------------------------------------------------------------------------
 */
void
peergroup_requeue_peer_chunks(struct peer *peer)
{
   struct peergroup *pg = btc->peerGroup;
   bool anyRequeued = 0;
   int i;

   if (pg == NULL || pg->cfSeg == NULL) {
      return;
   }

   for (i = 0; i < pg->cfSegCount; i++) {
      struct cf_segment *seg = &pg->cfSeg[i];

      if (seg->assignedPeer == peer && !seg->done) {
         log_warn(LGPFX" BIP157: requeuing cfilter chunk [%d..%d] "
                 "(peer %s gone).\n",
                 seg->startHeight, seg->endHeight, peer_name(peer));
         seg->avoidPeer    = peer;
         seg->assignedPeer = NULL;
         seg->remaining    = seg->endHeight - seg->startHeight + 1;
         anyRequeued = 1;
      }
   }

   if (anyRequeued) {
      peergroup_schedule_cfilters();
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_remove_pending_block --
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_remove_pending_block(const uint256 *hash)
{
   struct peergroup *pg = btc->peerGroup;
   int i;

   for (i = 0; i < pg->cfBlocksPending; i++) {
      if (uint256_issame(&pg->cfPending[i].hash, hash)) {
         pg->cfPending[i] = pg->cfPending[pg->cfBlocksPending - 1];
         pg->cfBlocksPending--;
         return;
      }
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_check_pending_blocks --
 *
 *      Periodic check: any matched-block getdata still outstanding after
 *      SYNC_STALL_USEC is retried against a different connected peer. Many
 *      NODE_NETWORK_LIMITED peers neither serve nor send 'notfound' for an
 *      old block they no longer hold, so a timeout is the only reliable
 *      signal here (unlike a real protocol-level notfound response, which
 *      is handled separately in peer_handle_notfound).
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_check_pending_blocks(void)
{
   struct peergroup *pg = btc->peerGroup;
   mtime_t now = time_get();
   uint256 expiredHash[64];
   struct peer *expiredFrom[64];
   int numExpired = 0;
   int i;

   /*
    * Read-only scan: collect entries that expired *before* this call (all
    * requestTS values here were set on a prior call/request, strictly
    * earlier than 'now'), without mutating pg->cfPending. Entries added by
    * a retry are only ever added after this scan completes, so there is no
    * risk of computing 'now - freshlyAddedTS' and underflowing the unsigned
    * mtime_t subtraction (which previously caused an immediate, unbounded
    * retry storm against the same couple of peers).
    */
   for (i = 0; i < pg->cfBlocksPending && numExpired < (int)ARRAYSIZE(expiredHash); i++) {
      struct cf_pending_block *p = &pg->cfPending[i];

      if (now < p->requestTS || now - p->requestTS < SYNC_STALL_USEC) {
         continue;
      }
      expiredHash[numExpired] = p->hash;
      expiredFrom[numExpired] = p->requestedFrom;
      numExpired++;
   }

   /*
    * Second pass: now that the scan is done, remove and retry each expired
    * entry. peergroup_retry_block_fetch may append new pending entries, but
    * that can no longer interfere since we're iterating our own snapshot,
    * not pg->cfPending directly.
    */
   for (i = 0; i < numExpired; i++) {
      char hashStr[80];

      uint256_snprintf_reverse(hashStr, sizeof hashStr, &expiredHash[i]);
      log_warn(LGPFX" BIP157: getdata(MSG_BLOCK) for %s timed out; "
              "retrying against another peer.\n", hashStr);

      peergroup_remove_pending_block(&expiredHash[i]);
      peergroup_retry_block_fetch(expiredFrom[i], &expiredHash[i], 1);
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

static int
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
      log_info(LGPFX" %s -- BITC_STATE_UPDATE_HEADERS.\n", __func__);
      btc->state = BITC_STATE_UPDATE_HEADERS;
      bitcui_set_status("online, fetching headers..");
      if (btc->peerGroup->numHdrToFetch > 0) {
         time_t last_ts = blockstore_get_timestamp(bs);
         mtime_t lag    = (time(NULL) - last_ts) * 1000 * 1000;
         char *lagStr   = print_latency(lag);

         log_warn(LGPFX" downloading %d header%s -- %s late\n",
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
 *      BIP157 path: request compact block filters (getcfilters) starting
 *      from the wallet birth height. Each received cfilter is GCS-matched
 *      against the wallet's scriptPubKeys; matching blocks are fetched via
 *      getdata(MSG_BLOCK).
 *
 *      BIP157 compact-filter sync is the default and only path.
 *
 *------------------------------------------------------------------------
 */

static int
peergroup_download_filtered_blocks(struct peer *peer)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint256 walletHash;
   uint256 lastHashStore;
   uint256 startHash;
   uint64 birth;
   bool first;

   if (btc->state != BITC_STATE_UPDATE_HEADERS &&
       btc->state != BITC_STATE_UPDATE_TXDB) {
       return 0;
    }
   ASSERT(btc->state == BITC_STATE_UPDATE_HEADERS ||
          btc->state == BITC_STATE_UPDATE_TXDB);

   /*
    * cfcheckpt verification and cfheader sync remain single-driver, exactly
    * like header sync below: the cfheader hash chain has a genuine
    * sequential dependency (each batch commits to the previous one), so
    * letting every peer race it forward would corrupt cfhdrStartHeight.
    * Once cfheader sync is done, the (much larger) cfilter scan is handed
    * off to peergroup_schedule_cfilters, which fans out to every connected
    * filter-capable peer -- see the 'else' branch below.
    */
   if (pg->downloadPeer == NULL) {
      pg->downloadPeer = peer;
   } else if (pg->downloadPeer != peer) {
      if (btc->state == BITC_STATE_UPDATE_TXDB && pg->cfcheckptVerified &&
          pg->cfhdrStartHeight > pg->cfhdrTipHeight) {
         /*
          * cfheader sync is complete: this peer (and any other idle,
          * filter-capable peer) can join the parallel cfilter scan instead
          * of sitting out the whole thing.
          */
         peergroup_schedule_cfilters();
      }
      return 0;
   }

   first = btc->state == BITC_STATE_UPDATE_HEADERS;

   if (first && pg->numHdrToFetch > 0) {
      mtime_t lat = time_get() - pg->firstConnectTS;
      char *s = print_latency(lat);
      log_warn(LGPFX" %d header%s downloaded in %s\n",
              pg->numHdrToFetch,
              pg->numHdrToFetch > 1 ? "s" : "", s);
      free(s);
   }

   /*
    * --sync-and-exit: header sync is done, so quit now instead of moving on to
    * transaction download. Handy for benchmarking `time ./bitc -d ...`.
    */
   if (first && btc->syncAndExit) {
      log_warn(LGPFX" header sync complete; exiting (--sync-and-exit).\n");
      bitc_req_stop();
      return 0;
   }

   log_info(LGPFX" %s -- BITC_STATE_UPDATE_TXDB.\n", __func__);
   btc->state = BITC_STATE_UPDATE_TXDB;
   bitcui_set_status("online, fetching tx..");

   /*
    * - Get hash of the wallet birth.
    * - Get the hash of the last block processed.
    *
    * Normally we start from the younger of the two (so we don't re-scan
    * blocks we've already processed). But with --stop-after-height, always
    * start from the wallet birth so we re-scan from the beginning for testing.
    */
   birth = wallet_get_birth(btc->wallet);
   blockstore_get_hash_from_birth(bs, birth, &walletHash);
   if (btc->stopAfterHeight > 0) {
      lastHashStore = walletHash;
   } else {
      peergroup_get_lastblk(pg, &lastHashStore);
   }

   /*
    * Get the youngest of the two.
    */
   blockstore_get_highest(bs, &walletHash, &lastHashStore, &startHash);

   if (first) {
      char hashStr[80];
      int startHeight;
      int tipHeight;

      peergroup_set_lastblk(pg, &startHash);

      pg->numToFetch = blockstore_get_height(bs)
         - blockstore_get_block_height(bs, &startHash);
      uint256_snprintf_reverse(hashStr, sizeof hashStr, &startHash);
      log_info(LGPFX" downloading starting at %s\n", hashStr);

      /*
       * BIP157: initialize the parallel cfilter scan. The range
       * [startHeight, tipHeight] is fixed for this pass and carved up front
       * into cfSegCount fixed-size chunks (see struct cf_segment), so
       * multiple peers can each claim and stream a different chunk
       * concurrently (peergroup_schedule_cfilters), instead of one peer
       * streaming the whole range sequentially.
       */
      startHeight = blockstore_get_block_height(bs, &startHash);
      tipHeight   = blockstore_get_height(bs);

      pg->cfScanFloor  = startHeight;
      pg->cfTipHeight  = tipHeight;
      pg->cfVerified   = startHeight;
      pg->cfDoneContig = 0;

      free(pg->cfSeg);
      pg->cfSeg      = NULL;
      pg->cfSegCount = 0;

      if (tipHeight >= startHeight) {
         int nChunks = (tipHeight - startHeight) / CFILTER_BATCH + 1;
         int i;

         pg->cfSeg = safe_calloc(nChunks, sizeof *pg->cfSeg);
         pg->cfSegCount = nChunks;
         for (i = 0; i < nChunks; i++) {
            int chunkStart = startHeight + i * CFILTER_BATCH;
            int chunkEnd   = MIN(chunkStart + CFILTER_BATCH - 1, tipHeight);

            pg->cfSeg[i].startHeight  = chunkStart;
            pg->cfSeg[i].endHeight    = chunkEnd;
            pg->cfSeg[i].remaining    = chunkEnd - chunkStart + 1;
            pg->cfSeg[i].assignedPeer = NULL;
            pg->cfSeg[i].done         = 0;
            pg->cfSeg[i].progressTS   = 0;
         }
      }

      /*
       * Initialize cfheader sync: start from the tip of the stored
       * cfheader chain (or 0 if empty), up to the block tip.
       */
      {
         int cfTip = -1;
         if (pg->cfStore) {
            cfTip = cfheaderstore_get_tip_height(pg->cfStore);
         }
         pg->cfhdrStartHeight = cfTip + 1;  /* -1 + 1 = 0 if empty */
         pg->cfhdrTipHeight   = tipHeight;

         /*
          * Set prevFilterHeader for the first batch: either the tip of
          * the stored chain, or the zero hash if starting from scratch.
          */
         if (cfTip >= 0 && pg->cfStore) {
            cfheaderstore_get_header(pg->cfStore, cfTip,
                                     &pg->cfhdrPrevHeader);
         } else {
            uint256_zero_out(&pg->cfhdrPrevHeader);
         }
      }

      log_info(LGPFX" BIP157: cfheader sync from height %d to %d, "
          "cfilter scan from %d to %d (%d chunk%s)\n",
          pg->cfhdrStartHeight, pg->cfhdrTipHeight,
          pg->cfScanFloor, pg->cfTipHeight, pg->cfSegCount,
          pg->cfSegCount == 1 ? "" : "s");
   }

   peergroup_download_progress();

   /*
    * BIP157 path: first verify cfcheckpts across peers, then sync cfheaders,
    * then fan out cfilter chunks to every filter-capable peer.
    */
   if (!pg->cfcheckptVerified) {
      return peergroup_verify_cfcheckpts(peer);
   }
   if (pg->cfhdrStartHeight <= pg->cfhdrTipHeight) {
      /* cfheaders not yet synced to tip. */
      return peergroup_request_cfheaders(peer);
   }
   peergroup_schedule_cfilters();
   return 0;
}


#define CFHEADER_BATCH 2000  /* max cfheaders per getcfheaders request */

/*
 *------------------------------------------------------------------------
 *
 * peergroup_verify_cfcheckpts --
 *
 *      Send getcfcheckpt to all connected NODE_COMPACT_FILTERS peers.
 *      The first response becomes the expected set; subsequent responses
 *      must agree. This is the eclipse/lying-peer defense: a single peer
 *      cannot trick us into accepting a fake filter header chain.
 *
 *------------------------------------------------------------------------
 */
static int
peergroup_verify_cfcheckpts(struct peer *peer)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint256 tipHash;
   int nSent = 0;
   struct circlist_item *li;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   /*
    * Get the block tip hash to use as stopHash for the checkpoint request.
    */
   blockstore_get_best_hash(bs, &tipHash);

   /*
    * Send getcfcheckpt to every connected peer that supports compact filters.
    */
   CIRCLIST_SCAN(li, pg->peer_list) {
      if (peer_is_connected(li) &&
          (peer_get_services(li) & BTC_SERVICE_NODE_COMPACT_FILTERS)) {
         int res = peer_send_getcfcheckpt(peer_from_li(li),
                                         BTC_CFILTER_TYPE_BASIC, &tipHash);
         if (res == 0) {
            nSent++;
         }
      }
   }

   pg->cfcheckptPeers    = nSent;
   pg->cfcheckptAgreed   = 0;
   pg->cfcheckptVerified = 0;
   pg->cfhdrSyncStarted  = 0;
   free(pg->cfcheckptExpected);
   pg->cfcheckptExpected = NULL;
   pg->cfcheckptCount    = 0;

   if (nSent == 0) {
      log_warn(LGPFX" BIP157: no NODE_COMPACT_FILTERS peers for checkpoint "
              "verification; proceeding with single-peer sync.\n");
      pg->cfcheckptVerified = 1;
      return peergroup_request_cfheaders(peer);
   }

   log_info(LGPFX" BIP157: sent getcfcheckpt to %d peer%s; waiting for responses.\n",
       nSent, nSent > 1 ? "s" : "");
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_cfcheckpt --
 *
 *      BIP157: receive a checkpoint response. The first response becomes the
 *      expected set; subsequent responses must agree. Once at least one peer
 *      agrees (or we only have one filter peer), proceed to cfheader sync.
 *
 *------------------------------------------------------------------------
 */
/*
 *------------------------------------------------------------------------
 *
 * peergroup_maybe_birthday_bound_cfheaders --
 *
 *      If the cfheader store is completely empty, anchor cfheader sync on a
 *      cross-validated getcfcheckpt checkpoint near the cfilter scan's start
 *      height instead of genesis: the cfilter scan only ever reads the
 *      cfheader store at heights >= cfScanFloor
 *      (cfheaderstore_get_hash, in peergroup_handle_cfilter), so a wallet
 *      with a recent birth can skip syncing (and verifying) cfheaders for
 *      the entire unused range below it. No-op if the store already has
 *      entries (an in-progress or previously-completed sync must continue
 *      contiguously from its own tip -- see cfheaderstore_append), or if no
 *      checkpoints are available to anchor on (falls back to the existing
 *      genesis-start behavior, just without the optimization).
 *
 *      Safe even if the checkpoint index math below were ever off: a wrong
 *      cfhdrPrevHeader simply fails peergroup_handle_cfheaders's mismatch
 *      check against the real chain (peers report their own honest
 *      prevFilterHeader), which safely disconnects the peer rather than
 *      accepting a wrong chain.
 *
 *------------------------------------------------------------------------
 */
static void
peergroup_maybe_birthday_bound_cfheaders(void)
{
   struct peergroup *pg = btc->peerGroup;
   int cfTip;
   int anchorHeight;
   int idx;

   cfTip = pg->cfStore ? cfheaderstore_get_tip_height(pg->cfStore) : -1;
   if (cfTip >= 0) {
      return;
   }
   if (pg->cfcheckptExpected == NULL || pg->cfcheckptCount == 0) {
      return;
   }

   anchorHeight = (pg->cfScanFloor / BIP157_CHECKPOINT_INTERVAL) *
                  BIP157_CHECKPOINT_INTERVAL;
   if (anchorHeight <= 0) {
      return;   /* nothing to skip; genesis start is already optimal */
   }

   /*
    * cfcheckptExpected[i] is the filter header at height (i+1)*1000 - 1.
    * We want the checkpoint at anchorHeight - 1 as the prevFilterHeader for
    * a batch starting at anchorHeight, i.e. index (anchorHeight/1000 - 1).
    */
   idx = anchorHeight / BIP157_CHECKPOINT_INTERVAL - 1;
   if (idx < 0 || idx >= pg->cfcheckptCount) {
      return;   /* out of range; stay safe and start from genesis */
   }

   pg->cfhdrStartHeight = anchorHeight;
   pg->cfhdrPrevHeader  = pg->cfcheckptExpected[idx];

   log_info(LGPFX" BIP157: birthday-bounding cfheader sync to start at "
       "height %d (checkpoint %d), skipping %d unused header%s.\n",
       anchorHeight, idx, anchorHeight, anchorHeight == 1 ? "" : "s");
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_cfcheckpt_maybe_complete --
 *
 *      Shared completion check for cfcheckpt verification: once we've heard
 *      from every peer we sent getcfcheckpt to (or that count has been
 *      revised down because some disconnected before responding -- see
 *      peergroup_notify_peer_gone), and at least one agreed, proceed to
 *      cfheader sync using 'driver' (which must be a currently connected,
 *      already-responded peer).
 *
 *------------------------------------------------------------------------
 */
static int
peergroup_cfcheckpt_maybe_complete(struct peer *driver)
{
   struct peergroup *pg = btc->peerGroup;

   if (pg->cfcheckptVerified) {
      return 0;
   }
   if (pg->cfcheckptAgreed >= 1 && pg->cfcheckptAgreed >= pg->cfcheckptPeers) {
      pg->cfcheckptVerified = 1;
      peergroup_maybe_birthday_bound_cfheaders();
      log_info(LGPFX" BIP157: cfcheckpt verified by %d peer%s; starting cfheader sync.\n",
          pg->cfcheckptAgreed, pg->cfcheckptAgreed > 1 ? "s" : "");
      return peergroup_request_cfheaders(driver);
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_notify_peer_gone --
 *
 *      Called from peer_destroy() for every disconnecting peer. If we are
 *      still waiting on cfcheckpt responses and this peer was one we sent
 *      getcfcheckpt to but never heard back from, a permanently unmet
 *      target (cfcheckptAgreed can never reach the original cfcheckptPeers)
 *      would wedge the sync forever. We can't tell precisely which pending
 *      peers this one was, so conservatively lower the target by one: this
 *      may occasionally let verification proceed with fewer confirmations
 *      than originally intended, which is a correct and safe trade-off
 *      against hanging indefinitely.
 *
 *------------------------------------------------------------------------
 */
void
peergroup_notify_peer_gone(struct peer *peer)
{
   struct peergroup *pg = btc->peerGroup;
   struct circlist_item *li;

   if (pg == NULL) {
      return;
   }

   /*
    * Case 1: mid cfcheckpt verification, waiting on a response from this
    * peer that can no longer arrive. Revise the target down instead of
    * hanging forever on an unmet count.
    */
   if (!pg->cfcheckptVerified && pg->cfcheckptPeers > 0 &&
       pg->cfcheckptAgreed < pg->cfcheckptPeers) {
      pg->cfcheckptPeers--;
      log_warn(LGPFX" BIP157: %s gone while awaiting cfcheckpt; "
              "lowering target to %d.\n", peer_name(peer), pg->cfcheckptPeers);

      if (pg->cfcheckptAgreed >= 1) {
         /* Use any other connected peer as the driver for the next step. */
         CIRCLIST_SCAN(li, pg->peer_list) {
            struct peer *cand = peer_from_li(li);
            if (cand != peer && peer_is_connected(li)) {
               peergroup_cfcheckpt_maybe_complete(cand);
               break;
            }
         }
      }
   }

   /*
    * Case 2: this peer owned one or more in-flight cfilter scan chunks.
    * Unlike the old single-driver model, the parallel scan has no single
    * "batch driver" to resume -- any chunk this peer held is simply
    * requeued for another connected filter peer (see
    * peergroup_requeue_peer_chunks, called from peer_destroy).
    */
}


int
peergroup_handle_cfcheckpt(struct peer *peer, const btc_msg_cfcheckpt *cfc)
{
   struct peergroup *pg = btc->peerGroup;
   bool agree = 1;
   int i;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   log_info(LGPFX" BIP157: cfcheckpt from %s: %llu headers.\n",
       peer_name(peer), (unsigned long long)cfc->numHeaders);

   if (pg->cfcheckptExpected == NULL) {
      /*
       * First response: store as the expected set.
       */
      pg->cfcheckptCount = (int)cfc->numHeaders;
      pg->cfcheckptExpected = safe_calloc(cfc->numHeaders,
                                          sizeof *pg->cfcheckptExpected);
      for (i = 0; i < (int)cfc->numHeaders; i++) {
         pg->cfcheckptExpected[i] = cfc->filterHeaders[i];
      }
      pg->cfcheckptAgreed++;
      log_info(LGPFX" BIP157: first cfcheckpt stored (%d checkpoints).\n",
          pg->cfcheckptCount);
   } else {
      /*
       * Subsequent response: compare against the expected set.
       */
      if ((int)cfc->numHeaders != pg->cfcheckptCount) {
         log_warn(LGPFX" BIP157: cfcheckpt count mismatch: %llu vs %d.\n",
                 (unsigned long long)cfc->numHeaders, pg->cfcheckptCount);
         agree = 0;
      } else {
         for (i = 0; i < (int)cfc->numHeaders; i++) {
            if (uint256_issame(&cfc->filterHeaders[i],
                               &pg->cfcheckptExpected[i]) == 0) {
               log_warn(LGPFX" BIP157: cfcheckpt mismatch at index %d.\n", i);
               agree = 0;
               break;
            }
         }
      }

      if (agree) {
         pg->cfcheckptAgreed++;
         log_info(LGPFX" BIP157: cfcheckpt agrees (%d/%d peers agree).\n",
             pg->cfcheckptAgreed, pg->cfcheckptPeers);
      } else {
         log_warn(LGPFX" BIP157: cfcheckpt DISAGREES; dropping peer %s.\n",
                 peer_name(peer));
         return 1;
      }
   }

   return peergroup_cfcheckpt_maybe_complete(peer);
}

/*
 *------------------------------------------------------------------------
 *
 * peergroup_request_cfheaders --
 *
 *      Send a getcfheaders request for the next batch of block heights.
 *      The peer responds with prevFilterHeader + an array of filter hashes.
 *
 *------------------------------------------------------------------------
 */
static int
peergroup_request_cfheaders(struct peer *peer)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint256 stopHash;
   int batchEnd;
   int res;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   /*
    * Guard against duplicate calls: only send getcfheaders once per batch.
    * The response handler clears this flag after processing.
    */
   if (pg->cfhdrSyncStarted) {
      return 0;
   }
   pg->cfhdrSyncStarted = 1;

   if (pg->cfhdrStartHeight > pg->cfhdrTipHeight) {
      /* All cfheaders requested; move on to the parallel cfilter scan. */
      log_info(LGPFX" BIP157: cfheaders synced to height %d; starting cfilter scan.\n",
          pg->cfhdrTipHeight);
      peergroup_schedule_cfilters();
      return 0;
   }

   batchEnd = MIN(pg->cfhdrStartHeight + CFHEADER_BATCH - 1, pg->cfhdrTipHeight);

   /*
    * Get the block hash at batchEnd to use as stopHash.
    */
   res = blockstore_get_block_at_height(bs, batchEnd, &stopHash, NULL);
   if (!res) {
      log_warn(LGPFX" BIP157: cannot get block hash at height %d for cfheaders.\n",
              batchEnd);
      return 1;
   }

   res = peer_send_getcfheaders(peer, BTC_CFILTER_TYPE_BASIC,
                                pg->cfhdrStartHeight, &stopHash);
   if (res) {
      return res;
   }

   log_info(LGPFX" BIP157: requested cfheaders for heights %d..%d\n",
       pg->cfhdrStartHeight, batchEnd);

   pg->lastFilteredBlockReq = stopHash;

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_cfheaders --
 *
 *      BIP157: receive a batch of filter headers. Verify that each filter
 *      hash chains onto the stored cfheader chain, then persist.
 *
 *------------------------------------------------------------------------
 */
int
peergroup_handle_cfheaders(struct peer *peer, const btc_msg_cfheaders *cfh)
{
   struct peergroup *pg = btc->peerGroup;
   uint256 prevHeader;
   uint256 expectedPrev;
   uint64 i;
   int startHeight;
   int res;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB);

   /*
    * The cfheaders message gives us prevFilterHeader and an array of
    * filterHashes. We compute filterHeader for each as:
    *   filterHeader = hash256( filterHash || prevFilterHeader )
    * and chain them: each prev becomes the previous header.
    */

   /*
    * Verify prevFilterHeader matches what we expect.
    * On the first batch (empty cfheader store), accept the peer's
    * prevFilterHeader as the anchor — we have nothing to compare against.
    * The cfcheckpt cross-check (done earlier) is what establishes trust.
    */
   expectedPrev = pg->cfhdrPrevHeader;
   if (uint256_iszero(&expectedPrev)) {
      /* First batch: accept the peer's prevFilterHeader. */
      log_info(LGPFX" BIP157: accepting initial prevFilterHeader from peer.\n");
   } else if (uint256_issame(&cfh->prevFilterHeader, &expectedPrev) == 0) {
      log_warn(LGPFX" BIP157: cfheaders prevFilterHeader mismatch; dropping peer.\n");
      return 1;
   }

   /*
    * Determine the start height for this batch. It's the first height
    * after the current cfheader tip (or 0 if empty).
    */
   if (pg->cfStore) {
      startHeight = cfheaderstore_get_tip_height(pg->cfStore) + 1;
   } else {
      startHeight = 0;
   }

   prevHeader = cfh->prevFilterHeader;

   /*
    * Verify and persist each filter header in the batch.
    */
   for (i = 0; i < cfh->numHeaders; i++) {
      uint256 filterHeader;
      uint256 filterHash;

      filterHash = cfh->filterHashes[i];
      cfheader_calc(&filterHash, &prevHeader, &filterHeader);

      /*
       * Persist the filter header and its hash. The store verifies
       * height continuity (must be tip+1).
       */
      res = cfheaderstore_append(pg->cfStore, startHeight + (int)i,
                                 &filterHeader, &filterHash);
      if (res) {
         log_warn(LGPFX" BIP157: cfheaderstore_append failed at height %d.\n",
                 startHeight + (int)i);
         return res;
      }

      prevHeader = filterHeader;
   }

   /*
    * Update the prev header for the next batch.
    */
   pg->cfhdrPrevHeader = prevHeader;
   pg->cfhdrStartHeight = startHeight + (int)cfh->numHeaders;
   pg->cfhdrSyncStarted = 0;  /* allow next batch request */

   log_info(LGPFX" BIP157: stored %llu cfheaders (heights %d..%d).\n",
       (unsigned long long)cfh->numHeaders,
       startHeight, startHeight + (int)cfh->numHeaders - 1);

   /*
    * Request the next batch, or move on to cfilters.
    */
   if (pg->cfhdrStartHeight <= pg->cfhdrTipHeight) {
      return peergroup_request_cfheaders(peer);
   }

   log_info(LGPFX" BIP157: cfheader sync complete to height %d.\n",
       pg->cfhdrTipHeight);
   peergroup_schedule_cfilters();
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_handle_block --
 *
 *      BIP157: process a full block received because its cfilter matched.
 *      Advance the lastblk pointer and feed transactions to the wallet.
 *
 *------------------------------------------------------------------------
 */
int
peergroup_handle_block(struct peer *peer, const btc_msg_block *blk)
{
   struct blockstore *bs = btc->blockStore;
   struct peergroup *pg = btc->peerGroup;
   uint256 blockHash;
   int blockHeight;
   int res = 0;
   uint64 i;

   ASSERT(btc->state == BITC_STATE_UPDATE_TXDB ||
          btc->state == BITC_STATE_READY);

   /* Compute the block hash from the header. */
   hash256_calc(&blk->header, sizeof blk->header, &blockHash);
   blockHeight = blockstore_get_block_height(bs, &blockHash);

   log_info(LGPFX" BIP157: received matched block at height %d, %llu txs\n",
       blockHeight, (unsigned long long)blk->txCount);

   /*
    * Feed each transaction to the wallet for credit/debit detection.
    * We serialize each parsed tx back to raw bytes (the format
    * wallet_handle_tx / txdb_handle_tx expects), then hand it off.
    */
   for (i = 0; i < blk->txCount; i++) {
      struct buff *txBuf;
      const uint8 *raw;
      size_t rawLen;

      txBuf = buff_alloc();
      res = serialize_tx(txBuf, &blk->tx[i]);
      if (res) {
         log_warn(LGPFX" BIP157: failed to serialize tx %llu in block %d.\n",
                (unsigned long long)i, blockHeight);
         buff_free(txBuf);
         continue;
      }
      raw = buff_base(txBuf);
      rawLen = buff_curlen(txBuf);
      res = wallet_handle_tx(btc->wallet, &blockHash, raw, rawLen);
      if (res) {
         log_warn(LGPFX" BIP157: wallet_handle_tx failed for tx %llu in block %d.\n",
                (unsigned long long)i, blockHeight);
      }
      buff_free(txBuf);
   }

   /*
    * This block was fetched because its cfilter matched. Removing it from
    * the pending set may unblock the resume watermark (peergroup_pending_
    * blocks gates how far peergroup_advance_lastblk may advance -- see
    * there), so recompute it now. If --stop-after-height was requested and
    * this was the last in-flight block, stop now (the tx we were scanning
    * for has been processed).
    */
   peergroup_remove_pending_block(&blockHash);
   peergroup_advance_lastblk();
   if (pg->cfStopRequested && pg->cfBlocksPending == 0) {
      log_warn(LGPFX" BIP157: matched blocks drained; stopping.\n");
      peergroup_download_complete();
      bitc_req_stop();
      return 0;
   }

   peergroup_maybe_complete();

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peergroup_retry_block_fetch --
 *
 *      A peer replied 'notfound' for a getdata(MSG_BLOCK) we sent after a
 *      cfilter match (typically a NODE_NETWORK_LIMITED peer that has pruned
 *      the old block). Retry each hash against a different connected peer,
 *      preferring one that is not NODE_NETWORK_LIMITED. If no other peer is
 *      available, the fetch stays pending; a later refill/reconnect may
 *      supply one.
 *
 *------------------------------------------------------------------------
 */
void
peergroup_retry_block_fetch(struct peer *failedPeer,
                           const uint256 *hashes,
                           int numHashes)
{
   struct peergroup *pg = btc->peerGroup;
   struct circlist_item *li;
   struct peer *best = NULL;
   bool bestIsLimited = 1;
   int i;

   CIRCLIST_SCAN(li, pg->peer_list) {
      struct peer *cand = peer_from_li(li);
      uint64 svc;

      if (cand == failedPeer || !peer_is_connected(li)) {
         continue;
      }
      svc = peer_get_services(li);
      if ((svc & BTC_SERVICE_NODE_NETWORK) == 0) {
         continue;
      }

      if (best == NULL) {
         best = cand;
         bestIsLimited = (svc & BTC_SERVICE_NODE_NETWORK_LIMITED) != 0;
         continue;
      }
      if (bestIsLimited && (svc & BTC_SERVICE_NODE_NETWORK_LIMITED) == 0) {
         best = cand;
         bestIsLimited = 0;
      }
   }

   if (best == NULL) {
      log_warn(LGPFX" BIP157: no alternate peer to retry %d block fetch(es); "
              "will remain pending.\n", numHashes);
      return;
   }

   for (i = 0; i < numHashes; i++) {
      char hashStr[80];
      int res;

      uint256_snprintf_reverse(hashStr, sizeof hashStr, &hashes[i]);
      log_info(LGPFX" BIP157: retrying block %s via %s.\n",
          hashStr, peer_name(best));

      res = peer_send_getdata(best, INV_TYPE_MSG_BLOCK, &hashes[i], 1);
      if (res == 0) {
         peergroup_add_pending_block(&hashes[i], best);
      } else {
         log_warn(LGPFX" BIP157: retry getdata failed for %s: %d.\n",
                 hashStr, res);
      }
   }
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

   log_info(LGPFX" active=%u maxActive=%u\n",
       peerGroup->active, peerGroup->maxActive);

   for (i = 0; i < BTC_MSG_MAX; i++) {
      if (cmdStats[i].received != 0 || cmdStats[i].sent != 0) {
         log_info(LGPFX" %11s: %6u  / %5u\n",
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

   /*
    * Before falling back to picking uniformly at random from the ~10k-entry,
    * largely-unverified address book, try our short list of addresses
    * proven -- across this run and past ones -- to actually serve compact
    * filters correctly with no recorded failure (see core/peerstats.c).
    * This is what makes a repeat run reliably find the same handful of good
    * filter peers instead of re-rolling the dice on a mostly-non-BIP157
    * network every time.
    */
   if (pg->peerStats != NULL) {
      struct peerstats_entry best[32];
      int nBest;
      int i;

      nBest = peerstats_get_best(pg->peerStats, (int)ARRAYSIZE(best), best);
      for (i = 0; i < nBest && pg->active < max; i++) {
         struct peer_addr *paddr = addrbook_get_by_ip(btc->book, best[i].ip);

         if (paddr == NULL || paddr->triedalready || paddr->connected) {
            continue;
         }
         log_info(LGPFX" preferring known-good peer %d.%d.%d.%d "
             "(cfilterOk=%u, cfilterFail=%u, latency=%u us).\n",
             paddr->addr.ip[12], paddr->addr.ip[13],
             paddr->addr.ip[14], paddr->addr.ip[15],
             best[i].cfilterOk, best[i].cfilterFail, best[i].latencyUsec);
         peergroup_add_peer(paddr);
      }
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

/*
 *-------------------------------------------------------------------------
 *
 * peergroup_check_download_stall --
 *
 *      During header/cfilter sync a single downloadPeer drives progress.
 *      If that peer stops responding, the whole sync hangs with no timeout.
 *      Detect a stall (no forward progress for a few seconds) and drop the
 *      download peer so another connected peer can take over.
 *
 *-------------------------------------------------------------------------
 */
static void
peergroup_check_download_stall(void)
{
   struct peergroup *pg = btc->peerGroup;
   struct peer *dp = pg->downloadPeer;
   mtime_t now;

   /*
    * Only watch for a stall during header sync, where a single downloadPeer
    * is the sole driver by construction (see peergroup_download_headers).
    * Once we move past BITC_STATE_UPDATE_HEADERS, cfcheckpt verification and
    * cfilter/block fetching can legitimately hand control between several
    * NODE_COMPACT_FILTERS peers, so downloadPeer is no longer guaranteed to
    * be the peer actually making progress -- killing it in that phase can
    * destroy an innocent, uninvolved peer instead of the one that's stuck.
    */
   if (dp == NULL || btc->state != BITC_STATE_UPDATE_HEADERS ||
       bitc_exiting()) {
      return;
   }
   if (pg->lastProgressTS == 0) {
      pg->lastProgressTS = time_get();
      return;
   }

   now = time_get();
   if (now - pg->lastProgressTS < SYNC_STALL_USEC) {
      return;
   }

   log_warn(LGPFX" sync stalled for %llu ms; dropping download peer %s.\n",
           (unsigned long long)((now - pg->lastProgressTS) / 1000),
           peer_name(dp));

   /*
    * Reset the stall timer and destroy the peer. peer_destroy() clears
    * pg->downloadPeer, so the next connected peer becomes the download peer
    * (peergroup_refill tops up the active set). The next handshake_ok / the
    * refill loop restarts the appropriate sync phase.
    */
   pg->lastProgressTS = now;
   peer_destroy(peer_get_item(dp), ETIMEDOUT);
}


static void
peergroup_periodic_cb(void *clientData)
{
   struct peergroup *pg = btc->peerGroup;

   if (bitc_exiting()) {
      return;
   }
   peergroup_refill(FALSE);
   peergroup_check_liveness();
   peergroup_check_download_stall();

   /*
    * Persist the sync checkpoint periodically, not only on a clean exit.
    * peergroup_exit() (which also calls this) may never run on a hard kill
    * or crash mid-sync, in which case any progress made since the last save
    * would otherwise be silently lost and re-scanned from scratch on the
    * next run.
    */
   if (pg->configNeedWrite) {
      peergroup_save_lastblk(btc->config, &pg->lastBlk);
      pg->configNeedWrite = 0;
   }
   peerstats_flush(pg->peerStats);
}


/*
 *-------------------------------------------------------------------------
 *
 * peergroup_pending_blocks_cb --
 *
 *      Runs much more often than peergroup_periodic_cb so an unresponsive
 *      peer for a matched-block fetch -- or a peer that has stalled on its
 *      assigned cfilter scan chunk -- is retried within SYNC_STALL_USEC of
 *      the request, not within the (much coarser) 15s general refill tick.
 *
 *-------------------------------------------------------------------------
 */
static void
peergroup_pending_blocks_cb(void *clientData)
{
   if (bitc_exiting() || btc->peerGroup == NULL) {
      return;
   }
   peergroup_check_pending_blocks();
   peergroup_check_pending_chunks();
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
   int res;

   log_info(LGPFX" maxPeers=%u period=%.1f msec\n",
       maxPeers, periodUsec / 1000.0);

   pg = safe_calloc(1, sizeof *btc->peerGroup);
   pg->peer_list     = NULL;
   pg->active        = 0;
   pg->startTS       = time_get();
   pg->maxActive     = maxPeers;
   pg->minActiveInit = minPeersInit;
   pg->cfScanFloor   = -1;
   pg->cfTipHeight   = -1;
   pg->cfVerified    = 0;
   pg->cfSeg         = NULL;
   pg->cfSegCount    = 0;
   pg->cfDoneContig  = 0;
   pg->cfhdrStartHeight = -1;
   pg->cfhdrTipHeight   = -1;
   uint256_zero_out(&pg->cfhdrPrevHeader);
   pg->cfcheckptExpected = NULL;
   pg->cfcheckptCount    = 0;
   pg->cfcheckptPeers    = 0;
   pg->cfcheckptAgreed   = 0;
   pg->cfcheckptVerified = 0;
   pg->cfhdrSyncStarted  = 0;

   /*
    * Open the compact-filter header store and the peer quality store.
    */
   {
      char *dir = bitc_get_directory();
      char cfhdrPath[PATH_MAX];
      char pstatPath[PATH_MAX];

      snprintf(cfhdrPath, sizeof cfhdrPath, "%s/cfheaders.dat", dir);
      res = cfheaderstore_init(cfhdrPath, &pg->cfStore);
      if (res) {
         log_warn(LGPFX" failed to open cfheader store '%s'.\n", cfhdrPath);
         pg->cfStore = NULL;
      }

      snprintf(pstatPath, sizeof pstatPath, "%s/peerstats.dat", dir);
      res = peerstats_init(pstatPath, &pg->peerStats);
      if (res) {
         log_warn(LGPFX" failed to open peer stats '%s'.\n", pstatPath);
         pg->peerStats = NULL;
      }
      free(dir);
   }

   memset(pg->lastBlk.data, 0, sizeof(uint256));
   pg->hash_broadcast = hashtable_create();

   hashStr = config_getstring(config, NULL, "peergroup.lastblk");
   if (hashStr) {
      bool s = uint256_from_str(hashStr, &pg->lastBlk);
      log_info(LGPFX" loading lastBlk: %s\n", hashStr);
      if (s == 0) {
         log_warn(LGPFX" failed to parse lastBlk: %s\n", hashStr);
      }
      free(hashStr);
   }

   btc->peerGroup = pg;
   peergroup_update_info();

   poll_callback_time(btc->poll, periodUsec, 1 /* permanent */,
                      peergroup_periodic_cb, NULL);

   /*
    * Separate, more frequent timer for pending matched-block retries -- see
    * peergroup_pending_blocks_cb. 2s gives a timely retry without spamming
    * getdata on a merely-slow-but-still-responsive peer.
    */
   poll_callback_time(btc->poll, 2 * 1000 * 1000ULL, 1 /* permanent */,
                      peergroup_pending_blocks_cb, NULL);
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

   log_info(LGPFX" seeding %s\n", hostname);
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

      log_info(LGPFX" connect-only mode: %s\n", btc->connectHost);
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
      log_info(LGPFX" adding static peer '%s'\n", addr);
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
      log_info(LGPFX" saving lastBlk: %s\n", hashStr);
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

   s = poll_callback_time_remove(btc->poll, 1, peergroup_pending_blocks_cb, NULL);
   ASSERT_NOT_TESTED(s);

   if (btc->updateAndExit && btc->stop == 1) {
      mtime_t delay = time_get() - pg->startTS;
      char *str = print_latency(delay);
      log_warn("Synchronized block-store in %s.\n", str);
      free(str);
   }

   if (pg->configNeedWrite) {
      peergroup_save_lastblk(btc->config, &pg->lastBlk);
   }

   hashtable_clear_with_callback(pg->hash_broadcast, peergroup_free_tx_broadcast_cb);
   hashtable_destroy(pg->hash_broadcast);
   cfheaderstore_exit(pg->cfStore);
   pg->cfStore = NULL;
   peerstats_exit(pg->peerStats);
   pg->peerStats = NULL;
   free(pg->cfcheckptExpected);
   pg->cfcheckptExpected = NULL;
   free(pg->cfPending);
   pg->cfPending = NULL;
   free(pg->cfSeg);
   pg->cfSeg = NULL;
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
            log_warn(LGPFX" fetched %6d headers out of %d\n",
                    btc->peerGroup->numHdrFetched, btc->peerGroup->numHdrToFetch);
         }
      }
   }

   /*
    * Persist the whole batch with a single write instead of one 80-byte pwrite
    * per header. blockstore_write_headers() already coalesces all not-yet-
    * written entries (a 'headers' message carries at most 2000, well under its
    * internal 2048 cap), so calling it once per batch is both correct and far
    * fewer syscalls.
    */
   if (numAdded > 0) {
      peergroup_add_block_finalize(bs, TRUE /* header only */);
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
         log_warn(LGPFX" %s: failed to send inv: %s (%d)\n",
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


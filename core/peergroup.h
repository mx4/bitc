#pragma once

#include "basic_defs.h"
#include "bitc-defs.h"

struct peer;
struct config;
struct buff;

/*
 * Tracks one outstanding getdata(MSG_BLOCK) sent after a cfilter match, so a
 * silently unresponsive peer (no 'notfound', no data, ever) can be detected
 * by elapsed time and retried against a different connected peer.
 */
struct cf_pending_block {
   uint256   hash;
   int       height;          /* block height (for resume-watermark gating) */
   struct peer *requestedFrom;
   mtime_t   requestTS;
};

/*
 * One unit of parallel cfilter-scan work: a fixed [startHeight, endHeight]
 * range of at most CFILTER_BATCH heights. The full scan range is carved into
 * cfSegCount of these up front (see peergroup_download_filtered_blocks), so
 * cfSeg[k] always covers a fixed, deterministic height range -- there is no
 * need to search for "the segment covering height H": it's cfSeg[(H -
 * cfScanFloor) / CFILTER_BATCH].
 */
struct cf_segment {
   int          startHeight;   /* inclusive */
   int          endHeight;     /* inclusive */
   int          remaining;     /* outstanding cfilter responses for this chunk */
   struct peer *assignedPeer;  /* NULL == idle/requeued, awaiting (re)assignment */
   struct peer *avoidPeer;     /* peer that just stalled/lost this chunk; do not
                                 * immediately hand it straight back to them */
   mtime_t      progressTS;    /* time of last progress; used for stall detection */
   mtime_t      assignedTS;    /* time this (re)assignment was made; used to
                                 * measure the assigned peer's true per-chunk
                                 * completion time for peerstats speed scoring */
   bool         done;          /* remaining reached 0 and every cfilter verified */
};

struct peergroup {
   struct circlist_item *peer_list;

   /*
    * Header sync is driven by a single peer at a time; letting every connected
    * peer download headers in parallel corrupts the shared counters below.
    */
   struct peer          *downloadPeer;

   uint32                peerSequence;
   uint256               lastFilteredBlockReq;

   bool                  configNeedWrite;
   uint256               lastBlk;

   struct hashtable     *hash_broadcast;

   int                   numFetched;
   int                   numToFetch;
   int                   numHdrFetched;
   int                   numHdrToFetch;
   int                   heightTarget;

   uint32                active;
   uint32                maxActive;
   uint32                minActiveInit;

   mtime_t               startTS;
   mtime_t               firstConnectTS;
   mtime_t               lastProgressTS;    /* last time sync made forward progress */

   /*
    * BIP157 compact-filter sync state. When useBip37 is false (the default),
    * the client syncs cfheaders then cfilters instead of sending filterload +
    * merkleblock. Each cfilter is GCS-matched against the wallet's
    * scriptPubKeys, and matching blocks are fetched via getdata(MSG_BLOCK).
    *
    * The cfilter scan itself is parallel: [cfScanFloor, cfTipHeight] is
    * carved up front into cfSegCount fixed-size chunks (cfSeg[]), and
    * multiple NODE_COMPACT_FILTERS peers each stream a different chunk
    * concurrently (see peergroup_schedule_cfilters). cfheader sync and
    * cfcheckpt verification remain single-driver (downloadPeer), since the
    * cfheader hash chain has a genuine sequential dependency.
    */
   struct cfheaderstore *cfStore;

   /*
    * Per-peer-address quality history (handshake latency, real observed
    * services, proven cfilter success/failure counts), persisted across
    * runs and keyed by IP -- see core/peerstats.c. Used to prefer known-good
    * peers (especially proven compact-filter servers) when refilling the
    * active peer set, instead of picking uniformly at random from the
    * ~10k-entry, largely-unverified address book.
    */
   struct peerstats     *peerStats;

   int                   cfScanFloor;      /* first height of the cfilter scan (fixed) */
   int                   cfTipHeight;      /* last height of the cfilter scan (fixed) */
   int                   cfVerified;       /* number of cfilters verified so far (progress) */
   int                   cfBlocksPending;   /* matched full blocks awaited */
   bool                  cfStopRequested;   /* --stop-after-height reached */

   /*
    * cfSeg[k] covers heights [cfScanFloor + k*CFILTER_BATCH, ...]; see
    * struct cf_segment. cfDoneContig is the number of leading chunks (from
    * index 0) that are fully verified, i.e. every height in
    * [cfScanFloor, cfSeg[cfDoneContig-1].endHeight] has been verified. This
    * is the "contiguous watermark" used to advance the crash-safe resume
    * pointer even though chunks can complete out of order.
    */
   struct cf_segment    *cfSeg;
   int                   cfSegCount;
   int                   cfDoneContig;

   /*
    * Pending matched-block fetches (getdata(MSG_BLOCK) sent, response not
    * yet received). Tracked with a timestamp so a silently unresponsive peer
    * (common for NODE_NETWORK_LIMITED nodes asked for an old block, which
    * often don't even bother sending 'notfound') can be retried against a
    * different peer instead of hanging forever. Also used to gate how far
    * the resume watermark may advance (never past an unprocessed match).
    */
   struct cf_pending_block *cfPending;      /* dynamic array, cfBlocksPending long */
   int                      cfPendingCap;   /* allocated capacity of cfPending */
   int                   cfhdrStartHeight;  /* next height to request cfheaders for */
   int                   cfhdrTipHeight;    /* target height for cfheader sync */
   uint256               cfhdrPrevHeader;   /* prevFilterHeader for the next batch */

   /*
    * Multi-peer cfcheckpt verification (eclipse defense). Before trusting the
    * cfheader chain from a single peer, we cross-check filter headers at
    * checkpoint intervals (every 1000 blocks) across all connected
    * NODE_COMPACT_FILTERS peers. If they disagree, we reject and disconnect.
    */
   uint256              *cfcheckptExpected;  /* checkpoints from the first peer */
   int                   cfcheckptCount;    /* number of checkpoints expected */
   int                   cfcheckptPeers;     /* number of peers we sent getcfcheckpt to */
   int                   cfcheckptAgreed;    /* number of peers that agreed */
   bool                  cfcheckptVerified;  /* true once at least one peer agreed */
   bool                  cfhdrSyncStarted;   /* true once getcfheaders has been sent */
};



void peergroup_seed(void);
void peergroup_exit(struct peergroup *pg);
void peergroup_zap(struct config *config);
void peergroup_init(struct config *cfg, uint32 maxPeers, uint32 maxPeersInit,
                    mtime_t peerPeriod);
void peergroup_send_stats_inc(enum btc_msg_type type);
void peergroup_recv_stats_inc(enum btc_msg_type type);
void peergroup_refill(bool init);
void peergroup_notify_destroy(void);
void peergroup_dequeue_peerlist(const struct circlist_item *li);
void peergroup_queue_peerlist(struct circlist_item *li);
void peergroup_notify_peer_gone(struct peer *peer);
void peergroup_requeue_peer_chunks(struct peer *peer);

int peergroup_handle_handshake_ok(struct peer *peer, int peerStartingHeight);
int peergroup_handle_cfilter(struct peer *peer, const btc_msg_cfilter *cf);
int peergroup_handle_cfheaders(struct peer *peer, const btc_msg_cfheaders *cfh);
int peergroup_handle_cfcheckpt(struct peer *peer, const btc_msg_cfcheckpt *cfc);
int peergroup_handle_block(struct peer *peer, const btc_msg_block *blk);
void peergroup_retry_block_fetch(struct peer *failedPeer,
                                 const uint256 *hashes, int numHashes);
void peergroup_handle_addr(struct peer *peer, btc_msg_address **addrs,
                          size_t numAddrs);
int peergroup_lookup_broadcast_tx(struct peergroup *pg, const uint256 *hash,
                                  struct buff **bufOut);
void peergroup_stop_broadcast_tx(struct peergroup *pg, const uint256 *hash);
int peergroup_handle_headers(struct peer *peer, int peerStartingHeight,
                             const btc_block_header *headers, int n);
int peergroup_new_tx_broadcast(struct peergroup *pg, const struct buff *buf,
                               mtime_t expiry, const uint256 *hash);


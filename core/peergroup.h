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
   struct peer *requestedFrom;
   mtime_t   requestTS;
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
    * merkleblock. The cfilter scan walks from cfScanHeight upward; each
    * cfilter is GCS-matched against the wallet's scriptPubKeys, and matching
    * blocks are fetched via getdata(MSG_BLOCK).
    */
   struct cfheaderstore *cfStore;
   int                   cfScanHeight;     /* next height to request cfilters for */
   int                   cfTipHeight;      /* height of the last cfilter we requested */
   int                   cfVerified;       /* number of cfilters verified so far */
   int                   cfBlocksPending;   /* matched full blocks awaited */
   bool                  cfStopRequested;   /* --stop-after-height reached */

   /*
    * A single getcfilters(startHeight, stopHash) request causes the peer to
    * stream back one 'cfilter' message per height in [startHeight, stopHash's
    * height] -- NOT one combined response. cfBatchRemaining tracks how many
    * of those individual responses are still outstanding for the batch most
    * recently requested; the next getcfilters batch must only be requested
    * once this reaches 0, not after every single cfilter received (doing the
    * latter multiplies outstanding requests by up to CFILTER_BATCH and
    * rapidly desyncs cfScanHeight far ahead of what has actually been
    * verified).
    */
   int                   cfBatchRemaining;

   /*
    * Pending matched-block fetches (getdata(MSG_BLOCK) sent, response not
    * yet received). Tracked with a timestamp so a silently unresponsive peer
    * (common for NODE_NETWORK_LIMITED nodes asked for an old block, which
    * often don't even bother sending 'notfound') can be retried against a
    * different peer instead of hanging forever.
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


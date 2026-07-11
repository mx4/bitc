#pragma once

#include "basic_defs.h"
#include "bitc-defs.h"

struct peer;
struct config;
struct buff;

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

int peergroup_handle_handshake_ok(struct peer *peer, int peerStartingHeight);
int peergroup_handle_merkleblock(struct peer *peer, const btc_msg_merkleblock *blk);
void peergroup_handle_addr(struct peer *peer, btc_msg_address **addrs,
                          size_t numAddrs);
int peergroup_lookup_broadcast_tx(struct peergroup *pg, const uint256 *hash,
                                  struct buff **bufOut);
void peergroup_stop_broadcast_tx(struct peergroup *pg, const uint256 *hash);
int peergroup_handle_headers(struct peer *peer, int peerStartingHeight,
                             const btc_block_header *headers, int n);
int peergroup_new_tx_broadcast(struct peergroup *pg, const struct buff *buf,
                               mtime_t expiry, const uint256 *hash);


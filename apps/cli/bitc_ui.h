#pragma once

#include <netinet/in.h>
#include <pthread.h>

#include "basic_defs.h"
#include "hash.h"
#include "circlist.h"


struct poll_loop;

struct bitcui_fx {
   char        *name;
   double       value;
   char        *symbol;
};


struct bitcui_tx {
   uint256      txHash;
   char        *src;
   char        *dst;
   int64        value;
   uint32       blockHeight;
   time_t       timestamp;
   char        *desc;
};


struct bitcui_peer {
   struct sockaddr_in saddr;
   char              *id;
   char              *host;
   char              *hostname;
   char              *versionStr;
   uint32             height;
};


struct bitcui_block {
   uint32  timestamp;
   int     height;
   uint256 hash;
};


struct bitcui_addr {
   char        *addr;
   char        *desc;
   int          idx; /* only useful when generating the struct */
};


struct btcui {
   bool                  inuse;
   volatile int          stop;
   pthread_t             tid;
   struct condvar       *cv;
   struct poll_loop     *poll;
   struct mutex         *lock;
   struct circlist_item *reqList;

   char                 *statusStr;
   time_t                statusExpiry;

   /*
    * TX.
    */
   struct bitcui_tx     *tx_info;
   int                  tx_num;

   /*
    * peers (alive).
    */
   struct bitcui_peer   *peer_info;
   int                  peer_num;

   /*
    * wallets, keys.
    */
   int                addr_num;
   struct bitcui_addr *addr_info;

   /*
    * btc -> ui notification.
    */
   bool               notifyInit;
   int                eventFd;
   int                notifyFd;

   /*
    * fx
    */
   struct bitcui_fx   *fx_pairs;
   int                fx_num;
   char              *fx_provider;
   uint32             fxPeriodMin;

   /*
    * peer info.
    */
   int                num_peers_active;
   int                num_peers_alive;
   int                num_addrs;
   int                height;

   /*
    * ring of recent blocks.
    */
   int                numBlocks;
   int                blockProdIdx;
   int                blockConsIdx;
   struct bitcui_block blocks[128];

   /*
    * catch-up stats.
    */
   bool               updating;
   int                numhdr;
   int                hdrtot;
   int                blk;
   int                blktot;
};

extern struct btcui *btcui;

void bitcui_set_last_block_info(const uint256 *hash, int height, uint32 ts);
void bitcui_set_catchup_info(int numhdr, int hdrtot, int blk, int blktot);
void bitcui_set_status(const char *fmt, ...) PRINTF_GCC_DECL(1, 2);
void bitcui_set_addrs_info(int num, struct bitcui_addr *addr);
void bitcui_set_tx_info(int num_tx, struct bitcui_tx *tx_info);
void bitcui_set_peer_info(int peers_active, int peers_alive, int num_addrs,
                         struct bitcui_peer *info_alive);

char *bitcui_ip2name(const struct sockaddr_in *addr);
void bitcui_free_fx_pairs(struct bitcui_fx *fx_pairs, int fx_num);
void bitcui_fx_update(void);
void bitcui_stop(void);
int  bitcui_start(bool withui);
void bitcui_req_notify_info_update(void);


#pragma once


enum bitc_state {
   BITC_STATE_STARTING,
   BITC_STATE_UPDATE_HEADERS,
   BITC_STATE_UPDATE_TXDB,
   BITC_STATE_READY,
   BITC_STATE_EXITING,
};

enum wallet_state {
   WALLET_UNKNOWN,
   WALLET_PLAIN,
   WALLET_ENCRYPTED_LOCKED,
   WALLET_ENCRYPTED_UNLOCKED,
};


struct btc_tx_desc {
   char         label[256];
   uint32       num_addr;
   uint64       total_value;
   int64        fee;
   struct {
      char      addr[64];
      uint64    value;
   } dst[16];
};


struct BITCApp {
   enum bitc_state          state;
   enum wallet_state        wallet_state;
   struct poll_loop        *poll;
   struct config           *config;
   struct config           *contactsCfg;
   struct config           *txLabelsCfg;
   struct blockstore       *blockStore;
   struct wallet           *wallet;
   struct addrbook         *book;
   struct ncui             *ui;
   struct peergroup        *peerGroup;
   struct poolworker_state *pw;
   struct mutex            *lock;

   bool                     testnet;
   bool                     resolve_peers;
   volatile int             stop;
   bool                     updateAndExit;
   bool                     notifyInit;
   int                      eventFd;
   int                      notifyFd;
   struct circlist_item    *reqList;

   char                    *socks5_proxy;
   uint16                   socks5_port;

   char                    *connectHost;  /* -C: connect only to this peer */
   bool                     syncAndExit;  /* --sync-and-exit: quit after headers */
};

extern struct BITCApp *btc;
extern bool bitc_testing;

void bitc_req_stop(void);
void bitc_req_tx(struct btc_tx_desc *tx_desc);
char *bitc_get_directory(void);


/*
 *-------------------------------------------------------------------
 *
 * bitc_state_updating_txdb --
 *
 *-------------------------------------------------------------------
 */

static inline bool
bitc_state_updating_txdb(void)
{
   return btc->state == BITC_STATE_UPDATE_TXDB;
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_state_ready --
 *
 *-------------------------------------------------------------------
 */

static inline bool
bitc_state_ready(void)
{
   return btc->state == BITC_STATE_READY;
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_starting --
 *
 *-------------------------------------------------------------------
 */

static inline bool
bitc_starting(void)
{
   return btc->state < BITC_STATE_READY;
}


/*
 *-------------------------------------------------------------------
 *
 * bitc_exiting --
 *
 *-------------------------------------------------------------------
 */

static inline bool
bitc_exiting(void)
{
   return btc->state > BITC_STATE_READY;
}



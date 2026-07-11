#ifdef __CYGWIN__
#include <cygwin/socket.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "basic_defs.h"
#include "util.h"
#include "poll.h"
#include "netasync.h"
#include "circlist.h"
#include "hashtable.h"
#include "buff.h"

#include "btc-message.h"
#include "peer.h"
#include "peergroup.h"
#include "hash.h"
#include "block-store.h"
#include "addrbook.h"
#include "wallet.h"
#include "bitc.h"
#include "bitc_ui.h"

#define LGPFX "PEER:"

static int verbose = 0;

/*
 * Upon starting the app, we'll try to update our small view of the blockhain.
 * We proceed in 2 steps:
 *
 * BTC_MODE_UPDATE_HEADERS:
 *
 *      The getheader msg handling is pretty fast and allows us to refresh our
 *      collection of headers quickly. We'll need the result of this to be
 *      efficient in step #2.
 *
 *                      /------------\
 *                      | getheaders |<---\
 *                      \------------/    |
 *                            |           |
 *                            v           |
 *                        /--------\      |
 *                        | header |-->---/
 *                        \--------/
 *
 *
 *
 * BTC_MODE_UPDATE_TXDB:
 *
 *      We now need to verify whether any tx affecting our addresses occurred
 *      since the last time we used the app.  We've prealably asked the peer to
 *      filter the data it sends us so that we only see the blocks/tx that
 *      match the bloom-filter. We do this via a filterload msg.
 *
 *      Since we have an updated set of headers we can send a getdata for
 *      a batch of blocks to the peer. We should then receive a merkleblock msg
 *      per per block requested, each of which being followed by the relevant
 *      TXs as per the bloom-filter.
 *
 *                       /---------\
 *                       | getdata |<-------------\
 *                       \---------/              |
 *                         /     \                |
 *                        /       \               |
 *                       /         \              |
 *                      /           \             |
 *                     v             v            |
 *                 /----\    /-------------\      |
 *                 | TX |    | merkleblock |------/
 *                 \----/    \-------------/
 */


#define PEER_MAGIC      0xbadf00d0badf00d

struct peer {
   uint64                  magic;
   char                    name[32];
   char                   *hostname;
   struct sockaddr_in      saddr;
   struct netasync_socket *sock;
   struct circlist_item    item;
   struct buff             recvBuf;
   struct buff            *sendBuf;

   uint256                 last_merkle_block;

   mtime_t                 last_ts;
   uint64                  pingNonce;
   bool                    connected;
   bool                    got_version;
   bool                    got_verack;

   bool                    recvMsgHdr;
   btc_msg_header          msgHdr;

   uint32                  startingHeight;
   uint32                  protversion;
   uint64                  services;
   char                   *clientStr;

   struct peer_addr       *paddr;
};


#define GET_PEER(_li) \
      CIRCLIST_CONTAINER(_li, struct peer, item)


static void peer_receive_cb(struct netasync_socket *sock,
                            void *buf, size_t bufLen, void *clientData);


/*
 *------------------------------------------------------------------------
 *
 * peer_send_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peer_send_cb(struct netasync_socket *sock,
             void                   *clientData,
             int                     err)
{
   struct peer *peer = clientData;
   ASSERT(peer->magic == PEER_MAGIC);

   if (err != 0) {
      NOT_TESTED();
      Warning(LGPFX" %s: failed to send: %s (%d)\n",
              peer->name, strerror(err), err);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * peer_name_li --
 *
 *------------------------------------------------------------------------
 */

const char *
peer_name_li(struct circlist_item *li)
{
   return peer_name(GET_PEER(li));
}


/*
 *------------------------------------------------------------------------
 *
 * peer_name --
 *
 *------------------------------------------------------------------------
 */

const char *
peer_name(const struct peer *peer)
{
   return peer->name;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_msg --
 *
 *------------------------------------------------------------------------
 */

static int
peer_send_msg(struct peer *peer,
              enum btc_msg_type type)
{
   const void *buf;
   size_t len;

   peergroup_send_stats_inc(type);

   ASSERT(peer->sendBuf);

   buf = buff_base(peer->sendBuf);
   len = buff_curlen(peer->sendBuf);

   free(peer->sendBuf);
   peer->sendBuf = NULL;

   if (type != BTC_MSG_PING) {
      Log(LGPFX" %s: %15s -- sending  %-12s: %zu bytes.\n",
          peer->name, peer->clientStr, btcmsg_type_to_str(type),
          len);
   }

   return netasync_send(peer->sock, buf, len, peer_send_cb, peer);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_getblocks --
 *
 *------------------------------------------------------------------------
 */

int
peer_send_getblocks(struct peer *peer)
{
   uint256 *hashes = NULL;
   int num = 0;
   int res;

   blockstore_get_locator_hashes(btc->blockStore, &hashes, &num);

   res = btcmsg_craft_getblocks(hashes, num, &peer->sendBuf);
   free(hashes);
   if (res) {
      NOT_TESTED();
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_GETBLOCKS);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_getheaders --
 *
 *------------------------------------------------------------------------
 */

int
peer_send_getheaders(struct peer *peer)
{
   uint256 *hashes = NULL;
   int num = 0;
   uint256 genesis;
   int res;

   blockstore_get_genesis(btc->blockStore, &genesis);
   blockstore_get_locator_hashes(btc->blockStore, &hashes, &num);

   /*
    * The block locator is the list of hashes we already have (newest first).
    * On a fresh store it is empty: we then pass a NULL locator with genesis as
    * the hashStop so the peer returns the genesis header itself, which seeds
    * best_chain. Subsequent calls carry a real locator and stream the chain.
    */
   res = btcmsg_craft_getheaders(num > 0 ? hashes : NULL, num, &genesis,
                                 &peer->sendBuf);
   free(hashes);
   if (res) {
      NOT_TESTED();
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_GETHEADERS);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_filterload --
 *
 *------------------------------------------------------------------------
 */

static int
peer_send_filterload(struct peer *peer)
{
   btc_msg_filterload fl;
   int res;

   wallet_get_bloom_filter_info(btc->wallet, &fl.filter, &fl.filterSize,
                                &fl.numHashFuncs, &fl.tweak);

   fl.flags = BLOOM_UPDATE_P2PUBKEY_ONLY;

   res = btcmsg_craft_filterload(&fl, &peer->sendBuf);
   if (res) {
      return res;
   }
   return peer_send_msg(peer, BTC_MSG_FILTERLOAD);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_getdata --
 *
 *------------------------------------------------------------------------
 */

int
peer_send_getdata(struct peer *peer,
                  enum btc_inv_type type,
                  const uint256 *hash,
                  int numHash)
{
   int res;

   ASSERT(numHash);
   ASSERT(numHash <= BTC_MSG_GETDATA_MAX_ENTRIES);

   res = btcmsg_craft_getdata(&peer->sendBuf, type,
                              hash, numHash);
   if (res == 0) {
      res = peer_send_msg(peer, BTC_MSG_GETDATA);
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_getcfilters --
 *
 *------------------------------------------------------------------------
 */
int
peer_send_getcfilters(struct peer *peer,
                      uint8 filterType,
                      uint32 startHeight,
                      const uint256 *stopHash)
{
   btc_msg_getcfilters g;
   int res;

   g.filterType  = filterType;
   g.startHeight = startHeight;
   g.stopHash    = *stopHash;

   res = btcmsg_craft_getcfilters(&g, &peer->sendBuf);
   if (res == 0) {
      res = peer_send_msg(peer, BTC_MSG_GETCFILTERS);
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_mempool --
 *
 *------------------------------------------------------------------------
 */

int
peer_send_mempool(struct peer *peer)
{
   int res;

   res = btcmsg_craft_mempool(&peer->sendBuf);
   if (res) {
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_MEMPOOL);
}



/*
 *------------------------------------------------------------------------
 *
 * peer_send_getaddr --
 *
 *------------------------------------------------------------------------
 */

static int
peer_send_getaddr(struct peer *peer)
{
   int res;

   res = btcmsg_craft_getaddr(&peer->sendBuf);
   if (res) {
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_GETADDR);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handshake_ok --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handshake_ok(struct peer *peer)
{
   int res;

   /*
    * BIP37 bloom filtering is disabled by default on modern nodes
    * (peerbloomfilters=0 since Bitcoin Core 0.19), and such nodes drop peers
    * that send 'filterload'. Only send it to peers advertising NODE_BLOOM when
    * the legacy BIP37 path is explicitly enabled; the default path is BIP157
    * compact block filters.
    */
   if (btc->peerGroup->useBip37 &&
       (peer->services & BTC_SERVICE_NODE_BLOOM)) {
      res = peer_send_filterload(peer);
      if (res) {
         return res;
      }
   }

   /* the below should always be true */
   ASSERT(peer->protversion >= BTC_PROTO_ADDR_W_TIME);

   res = peer_send_getaddr(peer);
   if (res) {
      return res;
   }

   return peergroup_handle_handshake_ok(peer, peer->startingHeight);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_remove_addr --
 *
 *      We do not always remove the address of the peer from the addressbook,
 *      in particular if we failed to connect because the network is down.
 *
 *------------------------------------------------------------------------
 */

static bool
peer_remove_addr(int err)
{
   return err != 0 && err != EHOSTUNREACH && err != ENETDOWN &&
          err != ENETUNREACH  && err != ETIMEDOUT;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_destroy --
 *
 *------------------------------------------------------------------------
 */

void
peer_destroy(struct circlist_item *li,
             int err)
{
   struct peer *peer = GET_PEER(li);

   ASSERT(peer);

   LOG(1, (LGPFX" %s: destroying peer '%s' -- %s\n",
       peer->name, peer->hostname, peer->clientStr));

   ASSERT(peer->paddr->connected == 1);
   peer->paddr->connected = 0;
   peer->connected = 0;

   /*
    * If this was the peer driving header download, relinquish that role so the
    * next peer to connect can take over (see peergroup_download_headers).
    */
   if (btc->peerGroup && btc->peerGroup->downloadPeer == peer) {
      btc->peerGroup->downloadPeer = NULL;
   }

   if (peer_remove_addr(err)) {
      addrbook_remove_entry(btc->book, peer->paddr);
      free(peer->paddr);
      peer->paddr = NULL;
   }

   peergroup_dequeue_peerlist(&peer->item);
   netasync_close(peer->sock);
   buff_free_base(&peer->recvBuf);
   buff_free(peer->sendBuf);
   free(peer->hostname);
   free(peer->clientStr);
   memset(peer, 0xff, sizeof *peer);
   free(peer);

   peergroup_notify_destroy();
}


/*
 *------------------------------------------------------------------------
 *
 * peer_error_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peer_error_cb(struct netasync_socket *sock,
              void *clientData,
              int err)
{
   struct peer *peer = (struct peer *) clientData;

   Log(LGPFX" %s: Error. Closing conn. w/ %20s %s -- %s (%d).\n",
       peer->name, peer->hostname,
       peer->clientStr, strerror(err), err);

   peer_destroy(&peer->item, err);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_getaddr --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_getaddr(struct peer *peer)
{
   btc_msg_address *addrs;
   size_t numAddr;
   size_t i;

   numAddr = MIN(32, addrbook_get_count(btc->book));
   addrs = safe_malloc(numAddr * sizeof *addrs);

   for (i = 0; i < numAddr; i++) {
      struct peer_addr *paddr;
      paddr = addrbook_get_rand_addr(btc->book);

      // XXX: avoid sending dupe.
      memcpy(addrs + i, &paddr->addr, sizeof paddr->addr);
   }

   Warning(LGPFX" %s: send %zu addresses to %s\n",
           peer->name, numAddr, peer->hostname);
   return btcmsg_craft_addr(peer->protversion, addrs, numAddr,
                            &peer->sendBuf);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_ping --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_ping(struct peer *peer)
{
   uint64 nonce = 0;
   int res;

   Log(LGPFX" %s: %u PING from %s (%s)\n", __FUNCTION__, __LINE__,
       peer->name, peer->clientStr);

   res = btcmsg_parse_pingpong(peer->protversion, &peer->recvBuf,
                               &nonce);
   if (res) {
      return res;
   }
   res = btcmsg_craft_pong(peer->protversion, nonce, &peer->sendBuf);
   if (res) {
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_PONG);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_send_ping --
 *
 *------------------------------------------------------------------------
 */

static int
peer_send_ping(struct peer *peer)
{
   int res;

   res = btcmsg_craft_ping(peer->protversion, peer->pingNonce, &peer->sendBuf);
   if (res) {
      return res;
   }

   peer->pingNonce++;
   return peer_send_msg(peer, BTC_MSG_PING);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_notfound --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_notfound(struct peer *peer)
{
   return btcmsg_parse_notfound(&peer->recvBuf);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_alert --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_alert(struct peer *peer)
{
   return btcmsg_parse_alert(&peer->recvBuf);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_getdata --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_getdata(struct peer *peer)
{
   btc_msg_inv *inv = NULL;
   int res;
   int n;
   int i;

   /*
    * 'getdata' has the same kind of payload as 'inv'.
    */
   res = btcmsg_parse_inv(&peer->recvBuf, &inv, &n);
   if (res) {
      return res;
   }

   for (i = 0; i < n; i++) {
      struct buff *buf = NULL;

      switch (inv[i].type) {
      case INV_TYPE_MSG_TX:
         res = peergroup_lookup_broadcast_tx(btc->peerGroup, &inv[i].hash, &buf);
         if (res != 0 || buf == NULL) {
            break;
         }
         btcmsg_craft_tx(buf, &peer->sendBuf);
         buff_free(buf);
         res = peer_send_msg(peer, BTC_MSG_TX);
         if (res) {
            goto exit;
         }
         break;
      case INV_TYPE_MSG_FILTERED_BLOCK:
      case INV_TYPE_MSG_BLOCK:
      default:
         NOT_TESTED();
         res = 1;
         goto exit;
      }
   }
exit:
   free(inv);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_getblocks --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_getblocks(struct peer *peer)
{
   NOT_TESTED_ONCE();

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_tx --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_tx(struct peer *peer)
{
   const uint8 *buf;
   size_t len;
   int res;

   buf = buff_base(&peer->recvBuf);
   len = buff_maxlen(&peer->recvBuf);

   res = wallet_handle_tx(btc->wallet, &peer->last_merkle_block, buf, len);
   ASSERT(res == 0);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_merkleblock --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_merkleblock(struct peer *peer)
{
   btc_msg_merkleblock *blk;
   int res;

   res = btcmsg_parse_merkleblock(&peer->recvBuf, &blk);
   if (res) {
      NOT_TESTED();
      return res;
   }

   res = peergroup_handle_merkleblock(peer, blk);
   if (res == 0) {
      memcpy(&peer->last_merkle_block, &blk->blkHash, sizeof blk->blkHash);
   }

   /*
    * If for some reasons we received a block and we don't know its parent, we
    * need to ask the peer for all of this block's parents we don't know about.
    */
   if (!blockstore_is_block_known(btc->blockStore, &blk->header.prevBlock)) {
      char hashStr0[80];
      char hashStr1[80];
      uint256_snprintf_reverse(hashStr1, sizeof hashStr1, &blk->header.prevBlock);
      uint256_snprintf_reverse(hashStr0, sizeof hashStr0, &blk->blkHash);
      NOT_TESTED();
      Log(LGPFX" %s: got %s parent unknown %s\n",
          peer->name, hashStr0, hashStr1);
      peer_send_getblocks(peer);
   }
   btc_msg_merkleblock_free(blk);
   return res;
}



/*
 *------------------------------------------------------------------------
 *
 * peer_handle_block --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_block(struct peer *peer)
{
   btc_msg_block blk;
   int res;

   res = btcmsg_parse_block(&peer->recvBuf, &blk);

   if (res == 0) {
      /*
       * BIP157: we received a full block because its cfilter matched our
       * wallet. Hand it to the peergroup for txdb processing.
       */
      peergroup_handle_block(peer, &blk);
      btc_msg_block_free(&blk);
   }

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_headers --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_headers(struct peer *peer)
{
   btc_block_header *headers;
   int res;
   int n;

   res = btcmsg_parse_headers(&peer->recvBuf, &headers, &n);
   if (res) {
      NOT_TESTED();
      return res;
   }

   res = peergroup_handle_headers(peer, peer->startingHeight, headers, n);
   free(headers);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_pong --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_pong(struct peer *peer)
{
   uint64 nonce = 0;
   int res;

   res = btcmsg_parse_pingpong(peer->protversion, &peer->recvBuf, &nonce);
   if (res) {
      return res;
   }
   if (nonce != peer->pingNonce - 1) {
      Log(LGPFX" %s: received ping nonce %#llx instead of %#llx.\n",
          peer->name, nonce, peer->pingNonce - 1);
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_addr --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_addr(struct peer *peer)
{
   btc_msg_address **addrs = NULL;
   size_t numAddrs = 0;
   int res;

   res = btcmsg_parse_addr(peer->protversion, &peer->recvBuf,
                           &addrs, &numAddrs);
   if (res) {
      return res;
   }

   peergroup_handle_addr(peer, addrs, numAddrs);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_inv --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_inv(struct peer *peer)
{
   btc_msg_inv *inv = NULL;
   uint256 *hash;
   uint8 *type;
   char hashStr[80];
   int numHash = 0;
   int numtx = 0;
   int numblk = 0;
   int numfblk = 0;
   int n = 0;
   int res;
   int i;

   res = btcmsg_parse_inv(&peer->recvBuf, &inv, &n);
   if (res) {
      return res;
   }
   hash = safe_malloc(n * sizeof *hash);
   type = safe_malloc(n * sizeof *type);

   for (i = 0; i < n; i++) {
      bool s;

      switch (inv[i].type) {
      case INV_TYPE_MSG_BLOCK:
         numblk++;
         s = blockstore_is_block_known(btc->blockStore, &inv[i].hash);
         if (s == 0) {
            uint256_snprintf_reverse(hashStr, sizeof hashStr, &inv[i].hash);
            Log(LGPFX" %s: inv block %s\n", peer->name, hashStr);
            hash[numHash] = inv[i].hash;
            type[numHash++] = INV_TYPE_MSG_FILTERED_BLOCK;
         }
         break;
      case INV_TYPE_MSG_TX:
         /*
          * Retrieve all broadcast transactions that may be of interest to us.
          * We'll also get them once they find their way in a block.
          */
         uint256_snprintf_reverse(hashStr, sizeof hashStr, &inv[i].hash);
         Log(LGPFX" %s: matching tx %s\n", peer->name, hashStr);
         if (!wallet_has_tx(btc->wallet, &inv[i].hash)) {
            numtx++;
            hash[numHash] = inv[i].hash;
            type[numHash++] = INV_TYPE_MSG_TX;
         }
         break;
      case INV_TYPE_MSG_FILTERED_BLOCK:
         numfblk++;
         NOT_TESTED();
         goto exit;
      }
   }
   LOG(1, (LGPFX" %s: handling inv msg: tx=%2d blk=%2d numfblk=%d numHash=%d\n",
           peer->name, numtx, numblk, numfblk, numHash));

   if (bitc_state_ready()) {
      for (i = 0; i < numHash; i++) {
         uint256_snprintf_reverse(hashStr, sizeof hashStr, hash + i);
         Log(LGPFX" %s: [%d / %d] requesting %s %s\n",
             peer->name, i, numHash,
             type[i] == INV_TYPE_MSG_FILTERED_BLOCK ? "block" : "tx",
             hashStr);
         res = peer_send_getdata(peer, type[i], hash + i, 1);
      }
   }

exit:
   free(type);
   free(hash);
   free(inv);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_version --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_version(struct peer *peer)
{
   btc_msg_version version;
   int res;

   res = btcmsg_parse_version(&peer->recvBuf, &version);
   if (res) {
      return res;
   }

   peer->protversion = version.version;
   peer->startingHeight = version.startingHeight;
   peer->services = version.services;
   free(peer->clientStr);
   peer->clientStr = safe_strdup(version.strVersion);

   btcmsg_print_version(peer->name, &version);

   if (strncmp(version.strVersion, "/Satoshi", 8) != 0 &&
       strncmp(version.strVersion, "", 1) != 0) {
      Warning(LGPFX" %s: unusual client: '%s'\n",
              peer->name, peer->clientStr);
   }

   /*
    * We need peers that serve historical blocks so we can fetch the ones our
    * filters match. NODE_NETWORK_LIMITED (BIP159) peers only keep the last
    * ~288 blocks, which is not enough for an initial sync.
    */
   if ((version.services & BTC_SERVICE_NODE_NETWORK) == 0) {
      Warning(LGPFX" %s: node does not serve full blocks (services=%#llx, %s).\n",
              peer->name, (unsigned long long)version.services, peer->clientStr);
      return 1;
   }
   /*
    * A real full node reports its best block height. A startingHeight of 0 is
    * the tell-tale of the non-serving "monitoring" nodes that otherwise flood
    * and dominate the address book (they also refuse getheaders). Reject them:
    * the handshake-failure path evicts the address from the book so we do not
    * keep reconnecting to it.
    */
   if (version.startingHeight == 0) {
      Warning(LGPFX" %s: peer advertises height 0 (%s); dropping.\n",
              peer->name, peer->clientStr);
      return 1;
   }
   if (version.services & BTC_SERVICE_NODE_COMPACT_FILTERS) {
      Log(LGPFX" %s: supports BIP157 compact filters.\n", peer->name);
   }
   if (version.version < BTC_PROTO_FILTERING) {
      Log(LGPFX" %s: client '%s' does not support filtering.\n",
          peer->name, peer->clientStr);
      return 1;
   }

   peer->got_version = 1;

   res = btcmsg_craft_verack(&peer->sendBuf);
   if (res) {
      return res;
   }

   return peer_send_msg(peer, BTC_MSG_VERACK);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_verack --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_verack(struct peer *peer)
{
   if (peer->got_version == 0) {
      NOT_TESTED();
      return 1;
   }
   peer->got_verack = 1;

   return peer_handshake_ok(peer);
}


/*
 *------------------------------------------------------------------------
 *
 * BIP157 compact filter message handlers (stubs — wiring comes later).
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_cfilter(struct peer *peer)
{
   btc_msg_cfilter cf;
   int res;

   res = btcmsg_parse_cfilter(&peer->recvBuf, &cf);
   if (res) {
      Warning(LGPFX" %s: failed to parse cfilter.\n", peer->name);
      return res;
   }
   Log(LGPFX" %s: cfilter type=%u numBytes=%llu\n",
       peer->name, cf.filterType, (unsigned long long)cf.numBytes);

   res = peergroup_handle_cfilter(peer, &cf);

   btc_msg_cfilter_free(&cf);
   return res;
}


static int
peer_handle_cfheaders(struct peer *peer)
{
   btc_msg_cfheaders cfh;
   int res;

   res = btcmsg_parse_cfheaders(&peer->recvBuf, &cfh);
   if (res) {
      Warning(LGPFX" %s: failed to parse cfheaders.\n", peer->name);
      return res;
   }
   Log(LGPFX" %s: cfheaders type=%u numHeaders=%llu\n",
       peer->name, cfh.filterType, (unsigned long long)cfh.numHeaders);
   btc_msg_cfheaders_free(&cfh);
   return 0;
}


static int
peer_handle_cfcheckpt(struct peer *peer)
{
   btc_msg_cfcheckpt cfc;
   int res;

   res = btcmsg_parse_cfcheckpt(&peer->recvBuf, &cfc);
   if (res) {
      Warning(LGPFX" %s: failed to parse cfcheckpt.\n", peer->name);
      return res;
   }
   Log(LGPFX" %s: cfcheckpt type=%u numHeaders=%llu\n",
       peer->name, cfc.filterType, (unsigned long long)cfc.numHeaders);
   btc_msg_cfcheckpt_free(&cfc);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_handle_msgheader --
 *
 *------------------------------------------------------------------------
 */

static int
peer_handle_msgheader(struct peer *peer)
{
   if (!btcmsg_header_valid(&peer->msgHdr)) {
      Warning(LGPFX" %s: invalid msg header -- %s\n",
              peer->name, peer->clientStr);
      return 1;
   }

   buff_alloc_base(&peer->recvBuf, peer->msgHdr.payloadLength);
   peer->recvMsgHdr = 0;
   if (buff_maxlen(&peer->recvBuf) > 0) {
      netasync_receive(peer->sock,
                       buff_base(&peer->recvBuf),
                       buff_maxlen(&peer->recvBuf),
                       0 /* full */,
                       peer_receive_cb, peer);
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_update_timestamp --
 *
 *------------------------------------------------------------------------
 */

static void
peer_update_timestamp(struct peer *peer)
{
   peer->paddr->addr.time = time(NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_receive_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peer_receive_cb(struct netasync_socket *sock,
                void *buf,
                size_t bufLen,
                void *clientData)
{
   struct peer *peer = (struct peer *) clientData;
   enum btc_msg_type msg;
   int res = 0;

   if (peer->magic != PEER_MAGIC) {
      Panic("XXX\n");
   }
   ASSERT(peer->magic == PEER_MAGIC);
   peer->last_ts = time_get();

   if (bitc_exiting()) {
      return;
   }

   msg = btcmsg_str_to_type(peer->msgHdr.message);
   if (peer->recvMsgHdr) {
      if (peer_handle_msgheader(peer)) {
         goto exit;
      }
      if (buff_maxlen(&peer->recvBuf) > 0) {
         return;
      }
   }

   if (!btcmsg_payload_valid(&peer->recvBuf, peer->msgHdr.checksum)) {
      Warning(LGPFX" %s: invalid checksum for '%s'.\n",
              peer->name, btcmsg_type_to_str(msg));
      goto exit;
   }

   peergroup_recv_stats_inc(msg);

   if (peer->got_version == 0 || peer->got_verack == 0) {
      res = 0;
      if (peer->got_version == 0 && msg == BTC_MSG_VERSION) {
         res = peer_handle_version(peer);
      } else if (peer->got_verack == 0 && msg == BTC_MSG_VERACK) {
         res = peer_handle_verack(peer);
      } else {
         /*
          * Modern peers interleave other messages with the handshake --
          * e.g. wtxidrelay (BIP339) and sendaddrv2 (BIP155) are sent after
          * 'version' but before 'verack'. Tolerate anything that is not the
          * message we are waiting for instead of dropping the connection.
          */
         Log(LGPFX" %s: ignoring '%s' during handshake.\n",
             peer->name, btcmsg_type_to_str(msg));
      }
      if (res != 0) {
         Log(LGPFX" %s: failed msg handling: %s (%s) payloadLength=%zu\n",
                 peer->name, btcmsg_type_to_str(msg), peer->clientStr,
                 buff_maxlen(&peer->recvBuf));
         goto exit;
      }
      goto next;
   }
   if (DOLOG(1) ||
       (msg != BTC_MSG_INV && msg != BTC_MSG_ADDR &&
        msg != BTC_MSG_PING && msg != BTC_MSG_PONG)) {
      Log(LGPFX" %s: %15s -- received %-12s: %zu bytes.\n",
          peer->name, peer->clientStr, peer->msgHdr.message,
          buff_maxlen(&peer->recvBuf));
   }

   ASSERT(peer->got_version == 1 && peer->got_verack == 1);

   switch (msg) {
   case BTC_MSG_INV:         res = peer_handle_inv(peer);        break;
   case BTC_MSG_ADDR:        res = peer_handle_addr(peer);       break;
   case BTC_MSG_GETADDR:     res = peer_handle_getaddr(peer);    break;
   case BTC_MSG_PING:        res = peer_handle_ping(peer);       break;
   case BTC_MSG_PONG:        res = peer_handle_pong(peer);       break;
   case BTC_MSG_GETBLOCKS:   res = peer_handle_getblocks(peer);  break;
   case BTC_MSG_GETDATA:     res = peer_handle_getdata(peer);    break;
   case BTC_MSG_BLOCK:       res = peer_handle_block(peer);      break;
   case BTC_MSG_MERKLEBLOCK: res = peer_handle_merkleblock(peer);break;
   case BTC_MSG_TX:          res = peer_handle_tx(peer);         break;
   case BTC_MSG_ALERT:       res = peer_handle_alert(peer);      break;
   case BTC_MSG_NOTFOUND:    res = peer_handle_notfound(peer);   break;
   case BTC_MSG_HEADERS:     res = peer_handle_headers(peer);    break;
   case BTC_MSG_CFILTER:    res = peer_handle_cfilter(peer);     break;
   case BTC_MSG_CFHEADERS:  res = peer_handle_cfheaders(peer);   break;
   case BTC_MSG_CFCHECKPT:  res = peer_handle_cfcheckpt(peer);   break;
   /*
    * Benign messages sent by modern peers that we do not need to act on.
    * Acknowledging them (rather than disconnecting) keeps the connection up.
    */
   case BTC_MSG_SENDHEADERS:
   case BTC_MSG_SENDCMPCT:
   case BTC_MSG_FEEFILTER:
   case BTC_MSG_WTXIDRELAY:
   case BTC_MSG_SENDADDRV2:
   case BTC_MSG_ADDRV2:
      res = 0;
      break;
   default:
      /*
       * Unknown message. The p2p protocol says to ignore these rather than
       * drop the peer -- doing otherwise breaks against nodes that speak
       * newer messages than we implement.
       */
      Log(LGPFX" %s: ignoring unhandled msg '%s' from %s.\n",
          peer->name, btcmsg_type_to_str(msg), peer->clientStr);
      res = 0;
      break;
   }
next:
   if (msg != BTC_MSG_MERKLEBLOCK && msg != BTC_MSG_TX) {
      uint256_zero_out(&peer->last_merkle_block);
   }
   if (res != 0) {
      Warning(LGPFX" %s: failed msg handling: %s (%s) payloadLength=%zu\n",
              peer->name, btcmsg_type_to_str(msg), peer->clientStr,
              buff_maxlen(&peer->recvBuf));
      goto exit;
   }

   peer_update_timestamp(peer);
   buff_free_base(&peer->recvBuf);
   peer->recvMsgHdr = 1;
   netasync_receive(peer->sock, &peer->msgHdr, sizeof peer->msgHdr,
                    0 /* full */, peer_receive_cb, peer);

   return;
exit:
   peer_destroy(&peer->item, EINVAL);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_connect_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peer_connect_cb(struct netasync_socket *sock,
                void *clientData,
                int err)
{
   struct peer *peer = (struct peer *)clientData;

   ASSERT(peer);
   ASSERT(peer->magic == PEER_MAGIC);

   if (err != 0) {
      Log(LGPFX" %s: %s -- %s (%d).\n",
          peer->name, netasync_hostname(sock), strerror(err), err);
      peer_destroy(&peer->item, err);
      return;
   }

   peer->connected = 1;
   peer->recvMsgHdr = 1;

   Log(LGPFX" %s: connected to %s. sending version msg.\n",
       peer->name, netasync_hostname(sock));

   /*
    * Setup receiving.
    */
   netasync_receive(peer->sock, &peer->msgHdr, sizeof peer->msgHdr,
                    0 /* full */, peer_receive_cb, peer);

   /*
    * Send "version" message.
    */
   btcmsg_craft_version(&peer->sendBuf);
   peer_send_msg(peer, BTC_MSG_VERSION);
}


/*
 *-------------------------------------------------------------------------
 *
 * peer_add --
 *
 *-------------------------------------------------------------------------
 */

void
peer_add(struct peer_addr *paddr,
         int seq)
{
   struct peer *peer;

   peer = safe_calloc(1, sizeof *peer);
   peer->magic     = PEER_MAGIC;
   peer->sock      = netasync_create();
   peer->paddr     = paddr;
   peer->clientStr = safe_strdup("");
   peer->pingNonce = 0xdead0000;
   snprintf(peer->name, sizeof peer->name, "peer_%05u", seq);
   ASSERT(uint256_iszero(&peer->last_merkle_block));

   ASSERT(paddr->connected == 0);
   paddr->connected = 1;
   paddr->triedalready = 1;

   /*
    * IPv4 only.
    */
   peer->saddr.sin_family = AF_INET;
   peer->saddr.sin_port = paddr->addr.port;
   memcpy(&peer->saddr.sin_addr, &paddr->addr.ip[12], 4);

   circlist_init_item(&peer->item);
   peergroup_queue_peerlist(&peer->item);

   peer->hostname = netasync_addr2str(&peer->saddr);
   LOG(1, (LGPFX" %s: connecting to %s.\n", peer->name, peer->hostname));
   netasync_set_errorhandler(peer->sock, peer_error_cb, peer);

   if (btc->socks5_proxy) {
      netasync_use_socks(peer->sock, btc->socks5_proxy, btc->socks5_port);
   }
   netasync_connect(peer->sock, &peer->saddr,
                    15 /* 15 sec connect timeout */,
                    peer_connect_cb, peer);
}


/*
 *-------------------------------------------------------------------------
 *
 * peer_getinfo --
 *
 *-------------------------------------------------------------------------
 */

int
peer_getinfo(struct circlist_item *item,
             struct bitcui_peer *pinfo)
{
   struct peer *peer = GET_PEER(item);

   ASSERT(peer->magic == PEER_MAGIC);

   if (peer->got_verack == 0 || peer->connected == 0) {
      return 1;
   }

   if (pinfo) {
      pinfo->height     = peer->startingHeight;
      pinfo->saddr      = peer->saddr;
      pinfo->id         = safe_strdup(peer->name);
      pinfo->host       = safe_strdup(peer->hostname);
      pinfo->versionStr = safe_strdup(peer->clientStr);
   }

   return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * peer_check_liveness --
 *
 *-------------------------------------------------------------------------
 */

int
peer_check_liveness(struct circlist_item *item,
                    mtime_t now)
{
   struct peer *peer = GET_PEER(item);

   ASSERT(peer->magic == PEER_MAGIC);
   ASSERT(peer->last_ts < now);

   if (peer->connected == 0 || peer->last_ts == 0 ||
       now < peer->last_ts + 60 * 1000 * 1000) { // 60 sec
      return 0;
   }

   return peer_send_ping(peer);
}


/*
 *-------------------------------------------------------------------------
 *
 * peer_send_inv --
 *
 *-------------------------------------------------------------------------
 */

int
peer_send_inv(struct circlist_item *item,
              struct buff *buf)
{
   struct peer *peer = GET_PEER(item);

   ASSERT(peer);
   ASSERT(peer->sendBuf == NULL);

   if (peer->got_verack == 0) {
      Log(LGPFX" %s: skipping inv transmit.\n", peer->name);
      return 0;
   }

   peer->sendBuf = buff_dup(buf);

   return peer_send_msg(peer, BTC_MSG_INV);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_tx_broadcast --
 *
 *------------------------------------------------------------------------
 */

static int
peer_tx_broadcast(struct peer *peer,
                  const uint256 *hash)
{
   struct buff *bufInv;
   char hashStr[80];
   int res;

   uint256_snprintf_reverse(hashStr, sizeof hashStr, hash);
   Log(LGPFX" %s: broadcasting tx %s\n", peer->name, hashStr);
   res = btcmsg_craft_inv(&bufInv, INV_TYPE_MSG_TX, hash, 1);
   ASSERT(res == 0);

   res = peer_send_inv(&peer->item, bufInv);
   buff_free(bufInv);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * peer_broadcast_one_tx_cb --
 *
 *------------------------------------------------------------------------
 */

static void
peer_broadcast_one_tx_cb(const void *key,
                         size_t keyLen,
                         void *cbData,
                         void *keyData)
{
   struct peer *peer = cbData;
   const uint256 *hash = key;

   ASSERT(keyLen == sizeof *hash);

   peer_tx_broadcast(peer, hash);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_broadcast_all_tx --
 *
 *------------------------------------------------------------------------
 */

static void
peer_broadcast_all_tx(struct peer *peer)
{
   hashtable_for_each(btc->peerGroup->hash_broadcast, peer_broadcast_one_tx_cb, peer);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_on_ready --
 *
 *------------------------------------------------------------------------
 */

int
peer_on_ready(struct peer *peer)
{
   int res;

   res = peer_send_mempool(peer);
   if (res) {
      return res;
   }

   peer_broadcast_all_tx(peer);

   return peer_send_getblocks(peer);
}


/*
 *------------------------------------------------------------------------
 *
 * peer_on_ready_li --
 *
 *------------------------------------------------------------------------
 */

int
peer_on_ready_li(struct circlist_item *li)
{
   struct peer *peer = GET_PEER(li);

   if (peer->got_verack == 0) {
      return 0;
   }

   return peer_on_ready(peer);
}

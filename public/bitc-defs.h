#pragma once

#include "basic_defs.h"
#include "hash.h"
#include "stdlib.h"

#define BTC_CLIENT_VERSION      "0.1.0"
#define BTC_CLIENT_DESC         "SPV bitcoin client"
#define BTC_CLIENT_STR_VERSION  "/bitc:"BTC_CLIENT_VERSION

#define ONE_BTC                 (100 * 1000 * 1000.0)
#define BTC_PROTO_VERSION       70016
#define BTC_NET_MAGIC_MAIN      0xD9B4BEF9
#define BTC_NET_MAGIC_TESTNET   0x0709110B
#define BTC_PORT_MAIN           8333
#define BTC_PORT_TESTNET        18333

#define BTC_TX_MAX_SIZE         (128 * 1024)

#define BTC_MSG_INV_MAX_ENTRIES         50000
#define BTC_MSG_GETDATA_MAX_ENTRIES     50000
#define BTC_MSG_GETHEADERS_MAX_ENTRIES  2000
#define BTC_MSG_MERKLE_BLOCK_MAX_TX     5000
#define BTC_MSG_ADDR_MAX_ENTRIES        1000
#define BTC_MSG_NOTFOUND_MAX_ENTRIES    50000

enum btc_msg_type {
   BTC_MSG_UNKNOWN = 0,
   BTC_MSG_VERSION,
   BTC_MSG_VERACK,
   BTC_MSG_INV,
   BTC_MSG_GETADDR,
   BTC_MSG_ADDR,
   BTC_MSG_GETHEADERS,
   BTC_MSG_HEADERS,
   BTC_MSG_PING,
   BTC_MSG_PONG,
   BTC_MSG_GETBLOCKS,
   BTC_MSG_BLOCK,
   BTC_MSG_GETDATA,
   BTC_MSG_TX,
   BTC_MSG_MEMPOOL,
   BTC_MSG_ALERT,
   BTC_MSG_FILTERLOAD,
   BTC_MSG_FILTERADD,
   BTC_MSG_FILTERCLEAR,
   BTC_MSG_MERKLEBLOCK,
   BTC_MSG_NOTFOUND,
   /* Post-2013 protocol messages (received from modern peers). */
   BTC_MSG_SENDHEADERS,    /* BIP130 */
   BTC_MSG_SENDCMPCT,      /* BIP152 */
   BTC_MSG_CMPCTBLOCK,     /* BIP152 */
   BTC_MSG_GETBLOCKTXN,    /* BIP152 */
   BTC_MSG_BLOCKTXN,       /* BIP152 */
   BTC_MSG_FEEFILTER,      /* BIP133 */
   BTC_MSG_WTXIDRELAY,     /* BIP339 */
   BTC_MSG_SENDADDRV2,     /* BIP155 */
   BTC_MSG_ADDRV2,         /* BIP155 */
   BTC_MSG_MAX,
};

/*
 * INV_TYPE_MSG_FILTERED_BLOCK is only valid after having sent a filterload
 * message.
 */
enum btc_inv_type {
   INV_TYPE_ERROR              = 0,
   INV_TYPE_MSG_TX             = 1,
   INV_TYPE_MSG_BLOCK          = 2,
   INV_TYPE_MSG_FILTERED_BLOCK = 3,
};


/*
 * Service bits advertised in the 'version' message. See BIP159 for
 * NODE_NETWORK_LIMITED and BIP157 for NODE_COMPACT_FILTERS.
 */
enum btc_services {
   BTC_SERVICE_NODE_NETWORK         = (1 << 0),  /* serves the full block chain    */
   BTC_SERVICE_NODE_BLOOM           = (1 << 2),  /* BIP37 bloom filtering (legacy) */
   BTC_SERVICE_NODE_WITNESS         = (1 << 3),  /* serves segwit block/tx data    */
   BTC_SERVICE_NODE_COMPACT_FILTERS = (1 << 6),  /* BIP157/158 compact filters     */
   BTC_SERVICE_NODE_NETWORK_LIMITED = (1 << 10), /* serves only the last ~288 blks */
};


enum btc_proto_version {
   BTC_PROTO_MIN            = 10000,
   BTC_PROTO_PING           = 60000,
   BTC_PROTO_FILTERING      = 70001,
   BTC_PROTO_ADDR_W_TIME    = 31402,
   BTC_PROTO_SENDHEADERS    = 70012, /* BIP130 */
   BTC_PROTO_FEEFILTER      = 70013, /* BIP133 */
   BTC_PROTO_COMPACT_BLOCKS = 70014, /* BIP152 */
};


typedef struct btc_msg_header {
   uint32       magic;
   char         message[12];
   uint32       payloadLength;
   uint8        checksum[4];
} btc_msg_header;


typedef struct btc_msg_address {
   uint64       services;
   uint8        ip[16];
   uint32       time;
   uint16       port;
} btc_msg_address;


typedef struct btc_msg_version {
   uint32          version;
   uint64          services;
   uint64          time;

   btc_msg_address addrTo;
   btc_msg_address addrFrom;

   uint64          nonce;
   char            strVersion[80];
   uint32          startingHeight;
   uint8           relayTx;
} btc_msg_version;


typedef struct btc_msg_inv {
   uint32       type;
   uint256      hash;
} btc_msg_inv;


typedef struct btc_msg_alert {
   uint32       version;
   uint64       relayUntil;
   uint64       expiration;
   uint32       id;
   uint32       cancel;
   uint32       numSetCancel;
   uint32      *setCancel;
   uint32       minVer;
   uint32       maxVer;
   uint32       numSubVer;
   char       **setSubVer;
   uint32       priority;
   char        *comment;
   char        *statusBar;
   char        *reserved;
} btc_msg_alert;


#define MAX_BLOOM_FILTER_SIZE   36000
#define MAX_HASH_FUNCS          50

enum btc_msg_filter_flags {
   BLOOM_UPDATE_NONE            = 0,
   BLOOM_UPDATE_ALL             = 1,
   BLOOM_UPDATE_P2PUBKEY_ONLY   = 2,
};

typedef struct btc_msg_filterload {
   uint8       *filter;
   uint32       filterSize;
   uint32       numHashFuncs;
   uint32       tweak;
   uint8        flags;
} btc_msg_filterload;


typedef struct btc_block_header {
   uint32       version;
   uint256      prevBlock;
   uint256      merkleRoot;
   uint32       timestamp;
   uint32       bits;
   uint32       nonce;
} btc_block_header;


typedef struct btc_block_locator {
   uint32       protversion;
   int          numHashes;
   uint256      hashStop;
   uint256      hashArray[];
} btc_block_locator;


/*
 * For coinbase transactions, scriptSig is used by satoshi clients to store:
 * the height, nExtraNonce
 */
typedef struct btc_msg_tx_in {
   uint256      prevTxHash;
   uint32       prevTxOutIdx;
   uint64       scriptLength;
   uint8       *scriptSig;
   uint32       sequence;
} btc_msg_tx_in;


typedef struct btc_msg_tx_out {
   uint64       value;
   uint64       scriptLength;
   uint8       *scriptPubKey;
} btc_msg_tx_out;


typedef struct btc_msg_tx {
   uint64          in_count;
   btc_msg_tx_in  *tx_in;
   uint64          out_count;
   btc_msg_tx_out *tx_out;
   uint32          version;
   uint32          lock_time;
} btc_msg_tx;


typedef struct btc_msg_block {
   btc_block_header     header;
   uint64               txCount;
   btc_msg_tx          *tx;
} btc_msg_block;


typedef struct btc_msg_merkleblock {
   btc_block_header     header;
   uint256              blkHash;
   uint32               txCount;
   uint64               hashCount;
   uint256             *hash;
   uint64               bitArraySize;
   uint8               *bit;
   uint32               matchedTxCount;
   uint256             *matchedTxHash;
} btc_msg_merkleblock;


/*
 *------------------------------------------------------------------------
 *
 * btc_inv_type2str --
 *
 *------------------------------------------------------------------------
 */

static inline const char *
btc_inv_type2str(enum btc_inv_type type)
{
   switch (type) {
   case INV_TYPE_MSG_TX:                return "TX";
   case INV_TYPE_MSG_BLOCK:             return "BLK";
   case INV_TYPE_MSG_FILTERED_BLOCK:    return "FILTERED_BLK";
   default:                             return "INVALID_TYPE";
   }
}



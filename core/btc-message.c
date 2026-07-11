#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "basic_defs.h"
#include "script.h"
#include "util.h"
#include "serialize.h"
#include "base58.h"
#include "buff.h"
#include "bitc.h"

#include "btc-message.h"
#include "hash.h"

#define LGPFX "MSG:"


static int verbose = 0;

static const char *ipv4_pfx = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

static const struct {
   const char *msg;
} cmdStr[BTC_MSG_MAX] = {
   [BTC_MSG_UNKNOWN]      = { "unknown"     },
   [BTC_MSG_VERSION]      = { "version"     },
   [BTC_MSG_VERACK]       = { "verack"      },
   [BTC_MSG_INV]          = { "inv"         },
   [BTC_MSG_GETADDR]      = { "getaddr"     },
   [BTC_MSG_ADDR]         = { "addr"        },
   [BTC_MSG_GETHEADERS]   = { "getheaders"  },
   [BTC_MSG_HEADERS]      = { "headers"     },
   [BTC_MSG_PING]         = { "ping"        },
   [BTC_MSG_PONG]         = { "pong"        },
   [BTC_MSG_GETBLOCKS]    = { "getblocks"   },
   [BTC_MSG_BLOCK]        = { "block"       },
   [BTC_MSG_GETDATA]      = { "getdata"     },
   [BTC_MSG_TX]           = { "tx"          },
   [BTC_MSG_MEMPOOL]      = { "mempool"     },
   [BTC_MSG_ALERT]        = { "alert"       },
   [BTC_MSG_FILTERLOAD]   = { "filterload"  },
   [BTC_MSG_FILTERADD]    = { "filteradd"   },
   [BTC_MSG_FILTERCLEAR]  = { "filterclear" },
   [BTC_MSG_MERKLEBLOCK]  = { "merkleblock" },
   [BTC_MSG_NOTFOUND]     = { "notfound"    },
   [BTC_MSG_SENDHEADERS]  = { "sendheaders" },
   [BTC_MSG_SENDCMPCT]    = { "sendcmpct"   },
   [BTC_MSG_CMPCTBLOCK]   = { "cmpctblock"  },
   [BTC_MSG_GETBLOCKTXN]  = { "getblocktxn" },
   [BTC_MSG_BLOCKTXN]     = { "blocktxn"    },
   [BTC_MSG_FEEFILTER]    = { "feefilter"   },
   [BTC_MSG_WTXIDRELAY]   = { "wtxidrelay"  },
   [BTC_MSG_SENDADDRV2]   = { "sendaddrv2"  },
   [BTC_MSG_ADDRV2]       = { "addrv2"      },
   [BTC_MSG_GETCFILTERS]  = { "getcfilters"  },
   [BTC_MSG_CFILTER]      = { "cfilter"      },
   [BTC_MSG_GETCFHEADERS] = { "getcfheaders" },
   [BTC_MSG_CFHEADERS]    = { "cfheaders"    },
   [BTC_MSG_GETCFCHECKPT] = { "getcfcheckpt" },
   [BTC_MSG_CFCHECKPT]    = { "cfcheckpt"    },
};


/*
 *----------------------------------------------------------------
 *
 * btcmsg_type_to_str --
 *
 *----------------------------------------------------------------
 */

const char *
btcmsg_type_to_str(enum btc_msg_type type)
{
   if (type >= BTC_MSG_MAX) {
      return "unknown";
   }
   return cmdStr[type].msg;
}


/*
 *----------------------------------------------------------------
 *
 * btcmsg_str_to_type --
 *
 *----------------------------------------------------------------
 */

enum btc_msg_type
btcmsg_str_to_type(const char str[12])
{
   char msg[13] = { 0 };
   unsigned int i;

   strncpy(msg, str, 12);

   for (i = 0; i < BTC_MSG_MAX; i++) {
      if (strncmp(str, cmdStr[i].msg, 12) == 0) {
         return i;
      }
   }
   Warning(LGPFX" Unknown cmd '%s'\n", msg);
   return BTC_MSG_UNKNOWN;
}


/*
 *----------------------------------------------------------------
 *
 * btcmsg_print_header --
 *
 *----------------------------------------------------------------
 */

void
btcmsg_print_header(const btc_block_header *header)   // IN
{
   char prevStr[128];
   char mrklStr[128];
   char *timeStr;

   uint256_snprintf_reverse(prevStr, sizeof prevStr, &header->prevBlock);
   uint256_snprintf_reverse(mrklStr, sizeof mrklStr, &header->merkleRoot);
   timeStr = print_time_utc(header->timestamp);

   Warning(LGPFX" version    = %u\n", header->version);
   Warning(LGPFX" prevBlock  = %s\n", prevStr);
   Warning(LGPFX" merkleRoot = %s\n", mrklStr);
   Warning(LGPFX" timestamp  = %s (%#x)\n", timeStr, header->timestamp);
   Warning(LGPFX" bits       = %#x\n", header->bits);
   Warning(LGPFX" nonce      = %#x / %u\n", header->nonce, header->nonce);

   free(timeStr);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_txout --
 *
 *------------------------------------------------------------------------
 */

void
btcmsg_print_txout(const btc_msg_tx_out *txOut)
{
   char scriptStr[512];
   uint32 slen;
   char *addr = NULL;

   slen = txOut->scriptLength;

   if (slen == 25 && txOut->scriptPubKey &&
       txOut->scriptPubKey[0] == OP_DUP &&
       txOut->scriptPubKey[1] == OP_HASH160 &&
       txOut->scriptPubKey[slen - 2] == OP_EQUALVERIFY &&
       txOut->scriptPubKey[slen - 1] == OP_CHECKSIG) {
      uint160 *h = (uint160 *)(txOut->scriptPubKey + 3);
      char str[512];
      addr = b58_pubkey_from_uint160(h);
      str_snprintf_bytes(str, sizeof str, NULL,
                         txOut->scriptPubKey + 3, txOut->scriptLength - 5);
      snprintf(scriptStr, sizeof scriptStr, "DUP HASH160 %s EQUALVERIFY CHECKSIG", str);
   } else {
      str_snprintf_bytes(scriptStr, sizeof scriptStr, NULL,
                         txOut->scriptPubKey, txOut->scriptLength);
   }

   Warning(LGPFX"    value        = %.8f BTC\n", txOut->value / ONE_BTC);
   Warning(LGPFX"    scriptLen    = %llu\n", txOut->scriptLength);
   Warning(LGPFX"    scriptPubKey = %s\n", scriptStr);
   if (addr) {
      Warning(LGPFX"    scriptPayee  = %s\n", addr);
      free(addr);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_txin --
 *
 *------------------------------------------------------------------------
 */

void
btcmsg_print_txin(const btc_msg_tx_in *txIn)
{
   char scriptStr[512];
   char prevStr[128];

   uint256_snprintf_reverse(prevStr, sizeof prevStr, &txIn->prevTxHash);

   str_snprintf_bytes(scriptStr, sizeof scriptStr, NULL, txIn->scriptSig, txIn->scriptLength);

   Warning(LGPFX"    prevTxHash   = %s\n", prevStr);
   Warning(LGPFX"    prevTxOutIdx = %u\n", txIn->prevTxOutIdx);
   Warning(LGPFX"    scriptLen    = %llu\n", txIn->scriptLength);
   Warning(LGPFX"    scriptSig    = '%s'\n", scriptStr);
   Warning(LGPFX"    sequence     = %#x\n", txIn->sequence);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_tx --
 *
 *------------------------------------------------------------------------
 */

void
btcmsg_print_tx(const btc_msg_tx *tx)
{
   uint64 i;

   Log("================================================================\n");
   Warning(LGPFX"  version  = %u\n", tx->version);
   Warning(LGPFX"  lockTime = %u\n", tx->lock_time);
   Warning(LGPFX"  inCount  = %llu\n", tx->in_count);

   for (i = 0; i < tx->in_count; i++) {
      btcmsg_print_txin(tx->tx_in + i);
   }

   Warning(LGPFX"  outCount = %llu\n", tx->out_count);

   for (i = 0; i < tx->out_count; i++) {
      btcmsg_print_txout(tx->tx_out + i);
   }
   Log("================================================================\n");
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_block --
 *
 *------------------------------------------------------------------------
 */

void
btcmsg_print_block(const btc_msg_block *blk)
{
   uint64 i;

   btcmsg_print_header(&blk->header);

   Warning(LGPFX" txCount = %llu\n", blk->txCount);

   for (i = 0; i < blk->txCount; i++) {
      btcmsg_print_tx(blk->tx + i);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_addr_is_ipv4 --
 *
 *------------------------------------------------------------------------
 */

static inline bool
btcmsg_addr_is_ipv4(const struct btc_msg_address *addr)
{
   return memcmp(addr->ip, ipv4_pfx, 12) == 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_header_valid --
 *
 *------------------------------------------------------------------------
 */

bool
btcmsg_header_valid(const btc_msg_header *hdr)
{
   uint32 magic;

   magic = btc->testnet ? BTC_NET_MAGIC_TESTNET : BTC_NET_MAGIC_MAIN;

   if (hdr->magic != magic) {
      Log(LGPFX" invalid magic: %#x vs %#x\n", hdr->magic, magic);
      return 0;
   }
   if (hdr->payloadLength > 256 * 1024) {
      Log(LGPFX" payloadLength = %u\n", hdr->payloadLength);
      return 0;
   }
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_payload_valid --
 *
 *------------------------------------------------------------------------
 */

bool
btcmsg_payload_valid(const struct buff *buf,
                     const uint8 checksum[4])
{
   uint8 cksum[4] = { 0 };

   ASSERT(buff_curlen(buf) == 0);
   hash4_calc(buff_base(buf), buff_maxlen(buf), cksum);

   return memcmp(checksum, cksum, sizeof cksum) == 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_notfound --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_notfound(struct buff *buf)
{
   uint64 n;
   uint64 i;
   int res;

   res = deserialize_varint(buf, &n);
   if (res) {
      NOT_TESTED();
      return res;
   }

   if (n > BTC_MSG_NOTFOUND_MAX_ENTRIES) {
      NOT_TESTED();
      return 1;
   }

   for (i = 0; i < n; i++) {
      char str[128];
      btc_msg_inv inv;

      res = deserialize_inv(buf, &inv);
      if (res) {
         return res;
      }

      uint256_snprintf_reverse(str, sizeof str, &inv.hash);
      Warning(LGPFX" NOTFOUND: inv: %s %s\n", str, btc_inv_type2str(inv.type));
   }

   if (buff_space_left(buf) != 0) {
      return 1;
   }

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_alert --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_alert(struct buff *buf)
{
   char *payload = NULL;
   size_t payloadLength;
   char *signature = NULL;
   size_t signatureLength;
   int res;

   res = deserialize_str_alloc(buf, &payload, &payloadLength);
   if (res) {
      goto exit;
   }
   res = deserialize_str_alloc(buf, &signature, &signatureLength);
   if (res) {
      goto exit;
   }

   /*
    * 1. verify signature.
    * 2. deserialize struct BTCMsgAlert.
    */
   NOT_TESTED();

exit:
   free(payload);
   free(signature);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * bit_isset --
 *
 *------------------------------------------------------------------------
 */

static bool
bit_isset(const uint8 *bitArray,
          uint32 i)
{
   ASSERT(bitArray);
   return (bitArray[i >> 3] & (1 << (i & 0x7))) != 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_get_width --
 *
 *------------------------------------------------------------------------
 */

static uint32
btcmsg_get_width(const btc_msg_merkleblock *blk,
                 uint32                     height)
{
   return (blk->txCount + (1 << height) - 1) >> height;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_walk_tree --
 *
 *------------------------------------------------------------------------
 */

static uint256
btcmsg_walk_tree(btc_msg_merkleblock *blk,
                 uint32               height,
                 uint32               pos,
                 uint32              *bitIdx,
                 uint32              *hashIdx,
                 bool                *ok)
{
   uint256 hash;
   bool parent;

   memset(&hash, 0, sizeof hash);

   /*
    * Every index below is derived from peer-supplied counts. Bail gracefully
    * (set *ok = 0) instead of asserting so a malformed merkleblock cannot walk
    * out of bounds or crash the process.
    */
   if (!*ok || *bitIdx >= blk->bitArraySize * 8) {
      *ok = 0;
      return hash;
   }
   parent = bit_isset(blk->bit, *bitIdx);
   (*bitIdx)++;

   if (!parent || height == 0) {
      if (*hashIdx >= blk->hashCount) {
         *ok = 0;
         return hash;
      }
      hash = blk->hash[*hashIdx];

      if (height == 0 && parent) {
         if (blk->matchedTxCount >= blk->hashCount) {
            *ok = 0;
            return hash;
         }
         blk->matchedTxHash[blk->matchedTxCount] = hash;
         blk->matchedTxCount++;
      }

      (*hashIdx)++;
      return hash;
   } else {
      uint256 h[2];
      uint256 l;
      uint256 r;

      l = btcmsg_walk_tree(blk, height - 1, pos * 2, bitIdx, hashIdx, ok);
      if (pos * 2 + 1 < btcmsg_get_width(blk, height - 1)) {
         r = btcmsg_walk_tree(blk, height - 1, pos * 2 + 1, bitIdx, hashIdx, ok);
      } else {
         r = l;
      }
      h[0] = l;
      h[1] = r;

      hash256_calc(h, 2 * sizeof(uint256), &hash);

      return hash;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_verify_merkle_tree --
 *
 *------------------------------------------------------------------------
 */

static bool
btcmsg_verify_merkle_tree(btc_msg_merkleblock *blk)
{
   uint256 root;
   uint32 bitIdx = 0;
   uint32 hashIdx = 0;
   int height = 0;
   bool ok = 1;

   while (btcmsg_get_width(blk, height) > 1) {
      height++;
   }

   ASSERT(blk->matchedTxHash == NULL);
   ASSERT(blk->matchedTxCount == 0);
   /*
    * There can be at most hashCount matched leaves (each match consumes one of
    * the supplied hashes), so size by hashCount -- txCount is peer-controlled
    * and unbounded, which would allow a huge allocation.
    */
   blk->matchedTxHash = safe_malloc(MAX(blk->hashCount, 1) * sizeof(uint256));
   root = btcmsg_walk_tree(blk, height, 0, &bitIdx, &hashIdx, &ok);
   if (!ok) {
      free(blk->matchedTxHash);
      blk->matchedTxHash = NULL;
      blk->matchedTxCount = 0;
      return 0;
   }

   if (blk->matchedTxCount == 0) {
      free(blk->matchedTxHash);
      blk->matchedTxHash = NULL;
   } else {
      int i;
      /*
       * We could reclaim some space here as blk->numMatched is much smaller
       * than blk->txCount.
       */
      for (i = 0; i < blk->matchedTxCount; i++) {
         char hashStr[80];
         uint256_snprintf_reverse(hashStr, sizeof hashStr, blk->matchedTxHash + i);
         LOG(0, (LGPFX" -- tx[%u] = %s\n", i, hashStr));
      }
   }

   return uint256_issame(&root, &blk->header.merkleRoot);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_mekleblock --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_merkleblock(struct buff          *buf,
                         btc_msg_merkleblock **blkOut)
{
   btc_msg_merkleblock *blk;
   char str[128];
   uint64 i;
   int res;

   *blkOut = NULL;

   /* The header hash below reads the first 80 bytes raw; require them. */
   if (buff_maxlen(buf) <= sizeof(btc_block_header)) {
      return 1;
   }

   blk = safe_calloc(1, sizeof *blk);
   hash256_calc(buff_base(buf), sizeof(btc_block_header), &blk->blkHash);

   res = deserialize_blockheader(buf, &blk->header);

   if (res == 0) {
      uint256_snprintf_reverse(str, sizeof str, &blk->blkHash);
      LOG(1, (LGPFX" BLK: cur: %s", str));
      uint256_snprintf_reverse(str, sizeof str, &blk->header.prevBlock);
      LOG(1, (LGPFX" BLK: prv: %s\n", str));
      //btcmsg_print_header(&blk->header);
   }
   res |= deserialize_uint32(buf, &blk->txCount);
   res |= deserialize_varint(buf, &blk->hashCount);

   if (res != 0 || blk->hashCount > BTC_MSG_MERKLE_BLOCK_MAX_TX
       || blk->hashCount > blk->txCount
       || blk->txCount == 0 || blk->txCount > (1u << 22)) {
      Log(LGPFX" too many hashes: %llu vs %u (re=%d)\n",
          blk->hashCount, blk->txCount, res);
      goto error;
   }
   blk->hash = safe_malloc(blk->hashCount * sizeof *blk->hash);

   for (i = 0; i < blk->hashCount; i++) {
      res |= deserialize_uint256(buf, blk->hash + i);

      uint256_snprintf_reverse(str, sizeof str, blk->hash + i);
      LOG(1, (LGPFX" MerkleBranch: hash #%-3llu %s\n", i, str));
   }
   res |= deserialize_varint(buf, &blk->bitArraySize);
   // XXX: make the test below correct.
   if (blk->bitArraySize > blk->txCount) {
      Log(LGPFX" bitArraySize = %llu\n", blk->bitArraySize);
      goto error;
   }
   blk->bit = safe_malloc(blk->bitArraySize);
   res |= deserialize_bytes(buf, blk->bit, blk->bitArraySize);

   //Log_Bytes("BITS:", blk->bit, blk->bitArraySize);
   LOG(0, (LGPFX" txCount=%u hashCount=%llu bitArraySz=%llu\n",
           blk->txCount, blk->hashCount, blk->bitArraySize));
   if (res) {
      goto error;
   }

   if (!btcmsg_verify_merkle_tree(blk)) {
      Log(LGPFX" failed to verify merkle branch.\n");
      res = 1;
      goto error;
   }

   if (buff_space_left(buf) != 0) {
      res = 1;
      goto error;
   }

   *blkOut = blk;

   return 0;

error:
   NOT_TESTED();
   btc_msg_merkleblock_free(blk);

   /* Reached only on failure; never report success with a NULL *blkOut. */
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_block --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_block(struct buff   *buf,
                   btc_msg_block *blk)
{
   int res;

   res = deserialize_block(buf, blk);
   if (res) {
      return res;
   }

   if (buff_space_left(buf) != 0) {
      return 1;
   }

   return res;
}

/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_headers --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_headers(struct buff       *buf,
                     btc_block_header **headersOut,
                     int               *num)
{
   btc_block_header *headers;
   uint64 n;
   uint64 i;
   int res;

   *headersOut = NULL;
   *num = 0;

   res = deserialize_varint(buf, &n);
   if (res) {
      NOT_TESTED();
      return res;
   }

   if (n > BTC_MSG_GETHEADERS_MAX_ENTRIES) {
      NOT_TESTED();
      return 1;
   }

   headers = safe_malloc(n * sizeof *headers);

   for (i = 0; i < n; i++) {
      uint64 numTx;

      res |= deserialize_blockheader(buf, headers + i);
      res |= deserialize_varint(buf, &numTx);

      if (res || numTx != 0) {
         free(headers);
         return 1;
      }
   }

   if (buff_space_left(buf) != 0) {
      free(headers);
      return 1;
   }

   *headersOut = headers;
   *num = n;

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_pingpong --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_pingpong(uint32       protversion,
                      struct buff *buf,
                      uint64      *nonce)
{
   *nonce = 0;
   if (protversion > BTC_PROTO_PING) {
      return deserialize_uint64(buf, nonce);
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_msgheader --
 *
 *------------------------------------------------------------------------
 */

static int
btcmsg_craft_msgheader(struct buff **bufOut,
                       const char   *message,
                       struct buff  *bufData)
{
   struct buff *buf;
   btc_msg_header h;

   memset(&h, 0, sizeof h);

   h.magic = btc->testnet ? BTC_NET_MAGIC_TESTNET : BTC_NET_MAGIC_MAIN;
   h.payloadLength = buff_curlen(bufData);
   strncpy(h.message, message, ARRAYSIZE(h.message));
   hash4_calc(buff_base(bufData), buff_curlen(bufData), h.checksum);

   buf = buff_alloc();

   serialize_msgheader(buf, &h);
   buff_append(buf, bufData);

   *bufOut = buf;

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_tx --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_tx(struct buff *txBuf,
                struct buff **bufOut)
{
   btcmsg_craft_msgheader(bufOut, "tx", txBuf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_filterload --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_filterload(const btc_msg_filterload *fl,
                        struct buff             **bufOut)
{
   struct buff *buf;

   buf = buff_alloc();

   serialize_varint(buf, fl->filterSize);
   serialize_bytes(buf,  fl->filter, fl->filterSize);
   serialize_uint32(buf, fl->numHashFuncs);
   serialize_uint32(buf, fl->tweak);
   serialize_uint8(buf,  fl->flags);

   btcmsg_craft_msgheader(bufOut, "filterload", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_ping --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_ping(uint32        protversion,
                  uint64        nonce,
                  struct buff **buf)
{
   struct buff *bufNonce;

   bufNonce = buff_alloc();

   if (protversion > BTC_PROTO_PING) {
      serialize_uint64(bufNonce, nonce);
   }

   btcmsg_craft_msgheader(buf, "ping", bufNonce);
   buff_free(bufNonce);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_pong --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_pong(uint32        protversion,
                  uint64        nonce,
                  struct buff **buf)
{
   struct buff *bufNonce;

   bufNonce = buff_alloc();

   if (protversion > BTC_PROTO_PING) {
      serialize_uint64(bufNonce, nonce);
   }

   btcmsg_craft_msgheader(buf, "pong", bufNonce);
   buff_free(bufNonce);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_prepare_version --
 *
 *------------------------------------------------------------------------
 */

static int
btcmsg_prepare_version(struct buff *buf)
{
   btc_msg_version v;
   int res;

   memset(&v, 0, sizeof v);
   v.version        = BTC_PROTO_VERSION;
   v.services       = 0; // no block relay
   v.time           = time(NULL);
   v.nonce          = 0x2345;
   v.startingHeight = 0;
   strncpy(v.strVersion, BTC_CLIENT_STR_VERSION, ARRAYSIZE(v.strVersion));

   res = serialize_version(buf, &v);
   ASSERT(res == 0);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_prepare_blocklocator --
 *
 *------------------------------------------------------------------------
 */

static struct btc_block_locator *
btcmsg_prepare_blocklocator(const uint256 *hashes,
                            int            num,
                            const uint256 *stop)
{
   struct btc_block_locator *bl;

   bl = safe_calloc(1, sizeof *bl + num * sizeof(uint256));
   bl->protversion = BTC_PROTO_VERSION;

   if (num > 0) {
      memcpy(bl->hashArray, hashes, num * sizeof *hashes);
      bl->numHashes = num;
   }
   if (stop) {
      memcpy(&bl->hashStop, stop, sizeof *stop);
   }

   return bl;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_getblocks --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_getblocks(const uint256 *hashes,
                       int            num,
                       struct buff  **bufOut)
{
   btc_block_locator *bl;
   struct buff *buf;

   ASSERT(hashes);

   bl = btcmsg_prepare_blocklocator(hashes, num, NULL);

   buf = buff_alloc();
   serialize_blocklocator(buf, bl);
   free(bl);

   btcmsg_craft_msgheader(bufOut, "getblocks", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_getheaders --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_getheaders(const uint256 *hashes,
                        int            num,
                        const uint256 *genesis,
                        struct buff  **bufOut)
{
   btc_block_locator *bl;
   struct buff *buf;

   /*
    * Yes, this looks somewhat funny.
    *
    * However, it works. So until more time frees up..
    */
   if (num > 0) {
      bl = btcmsg_prepare_blocklocator(hashes, num, NULL);
   } else {
      bl = btcmsg_prepare_blocklocator(NULL, 0, genesis);
   }

   buf = buff_alloc();
   serialize_blocklocator(buf, bl);
   free(bl);

   btcmsg_craft_msgheader(bufOut, "getheaders", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_inv --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_inv(struct buff     **bufOut,
                 enum btc_inv_type type,
                 const uint256    *hash,
                 int               n)
{
   struct buff *buf;
   int i;

   ASSERT(n <= BTC_MSG_INV_MAX_ENTRIES);

   buf = buff_alloc();
   serialize_varint(buf, n);

   for (i = 0; i < n; i++) {
      btc_msg_inv inv;

      inv.type = type;
      inv.hash = hash[i];

      serialize_inv(buf, &inv);
   }

   btcmsg_craft_msgheader(bufOut, "inv", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_getdata --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_getdata(struct buff     **bufOut,
                     enum btc_inv_type type,
                     const uint256    *hash,
                     int               n)
{
   struct buff *buf;
   int i;

   ASSERT(n <= BTC_MSG_GETDATA_MAX_ENTRIES);

   buf = buff_alloc();
   serialize_varint(buf, n);

   for (i = 0; i < n; i++) {
      btc_msg_inv inv;

      inv.type = type;
      inv.hash = hash[i];

      serialize_inv(buf, &inv);
   }

   btcmsg_craft_msgheader(bufOut, "getdata", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_verack --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_verack(struct buff **bufOut)
{
   return btcmsg_craft_msgheader(bufOut, "verack", NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_mempool --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_mempool(struct buff **bufOut)
{
   return btcmsg_craft_msgheader(bufOut, "mempool", NULL);
}



/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_getaddr --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_getaddr(struct buff **bufOut)
{
   return btcmsg_craft_msgheader(bufOut, "getaddr", NULL);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_version --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_version(struct buff **bufOut)
{
   struct buff *buf;

   buf = buff_alloc();

   btcmsg_prepare_version(buf);
   btcmsg_craft_msgheader(bufOut, "version", buf);

   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_version --
 *
 *------------------------------------------------------------------------
 */

void
btcmsg_print_version(const char            *pfx,
                     const btc_msg_version *v)
{
   char *s = print_time_utc(v->time);

   Log(LGPFX" %s: '%s' @%d -- '%s' -- height=%u --svc=%#llx\n",
       pfx, v->strVersion, v->version, s, v->startingHeight, v->services);

   free(s);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_print_addr --
 *
 *------------------------------------------------------------------------
 */

static void
btcmsg_print_addr(const btc_msg_address *addr,
                  const char            *pfx)
{
   char *s;

   s = print_time_utc(addr->time);
   Log(LGPFX" %s : p=%u %s -- ip: %u.%u.%u.%u\n",
       pfx, ntohs(addr->port), s,
       addr->ip[12+0],
       addr->ip[12+1],
       addr->ip[12+2],
       addr->ip[12+3]);
   free(s);
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_craft_addr --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_addr(uint32                        protversion,
                  const struct btc_msg_address *addrs,
                  size_t                        numAddrs,
                  struct buff                 **bufOut)
{
   struct buff *buf;
   size_t i;

   ASSERT(numAddrs <= BTC_MSG_ADDR_MAX_ENTRIES);

   buf = buff_alloc();
   serialize_varint(buf, numAddrs);

   for (i = 0; i < numAddrs; i++) {
      serialize_addr(buf, addrs + i);
   }

   btcmsg_craft_msgheader(bufOut, "addr", buf);
   buff_free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_addr --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_addr(uint32                    protversion,
                  struct buff              *buf,
                  struct btc_msg_address ***addrsOut,
                  size_t                   *numAddrsOut)
{
   struct btc_msg_address **addrs;
   uint64 numAddressMsg = 0;
   time_t yesterday;
   int numAddrs;
   int res;
   int j;

   *numAddrsOut = 0;
   *addrsOut = NULL;

   res = deserialize_varint(buf, &numAddressMsg);

   if (res || numAddressMsg > BTC_MSG_ADDR_MAX_ENTRIES) {
      return 1;
   }

   yesterday = time(NULL) - 24 * 60 * 60;
   addrs = safe_malloc(numAddressMsg * sizeof *addrs);
   numAddrs = 0;

   for (j = 0; j < numAddressMsg; j++) {
      struct btc_msg_address addr = { 0 };

      res = deserialize_addr(protversion, buf, &addr);
      if (res) {
         goto exit;
      }
      if (!btcmsg_addr_is_ipv4(&addr)) {
         if (verbose) {
            btcmsg_print_addr(&addr, "Not IPv4");
         }
         continue;
      }
      if (addr.time < yesterday) {
         if (verbose) {
            btcmsg_print_addr(&addr, "TOO OLD");
         }
         continue;
      }

      addrs[numAddrs] = safe_malloc(sizeof addr);
      memcpy(addrs[numAddrs], &addr, sizeof addr);
      numAddrs++;
   }
   if (buff_space_left(buf) != 0) {
      res = 1;
      goto exit;
   }

   *addrsOut = addrs;
   *numAddrsOut = numAddrs;

   return 0;

exit:
   /*
    * Only addrs[0..numAddrs-1] were allocated -- the array is compacted as
    * non-IPv4/too-old entries are skipped -- so free by numAddrs, not the
    * message-index j (which would free uninitialized slots).
    */
   while (numAddrs > 0) {
      numAddrs--;
      free(addrs[numAddrs]);
   }
   free(addrs);
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_inv --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_inv(struct buff  *buf,
                 btc_msg_inv **invOut,
                 int          *num)
{
   btc_msg_inv *inv;
   uint64 n = 0;
   uint64 i;
   int res;

   *invOut = NULL;
   *num = 0;

   res = deserialize_varint(buf, &n);
   if (res) {
      NOT_TESTED();
      return res;
   }

   if (n > BTC_MSG_INV_MAX_ENTRIES) {
      NOT_TESTED();
      return 1;
   }

   inv = safe_malloc(n * sizeof *inv);

   for (i = 0; i < n; i++) {
      char str[128];

      res |= deserialize_inv(buf, inv + i);
      uint256_snprintf_reverse(str, sizeof str, &inv[i].hash);
      LOG(1, (LGPFX" inv: %s %s\n", str, btc_inv_type2str(inv[i].type)));
   }
   if (res) {
      free(inv);
      NOT_TESTED();
      return res;
   }

   *num = n;
   *invOut = inv;

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * btcmsg_parse_version --
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_parse_version(struct buff     *buf,
                     btc_msg_version *version)
{
   return deserialize_version(buf, version);
}


/*
 *---------------------------------------------------
 *
 * btc_msg_tx_dup --
 *
 *---------------------------------------------------
 */

struct btc_msg_tx *
btc_msg_tx_dup(const struct btc_msg_tx *tx0)
{
   struct btc_msg_tx *tx;
   size_t szin;
   size_t szout;
   int i;

   tx = safe_malloc(sizeof *tx);;
   memcpy(tx, tx0, sizeof *tx0);

   szin  = tx->in_count  * sizeof *tx->tx_in;
   szout = tx->out_count * sizeof *tx->tx_out;

   tx->tx_in  = safe_malloc(szin);
   tx->tx_out = safe_malloc(szout);

   memcpy(tx->tx_in,  tx0->tx_in,  szin);
   memcpy(tx->tx_out, tx0->tx_out, szout);

   for (i = 0; i < tx->in_count; i++) {
      size_t len = tx0->tx_in[i].scriptLength;
      tx->tx_in[i].scriptSig = NULL;
      if (len > 0) {
         tx->tx_in[i].scriptSig = safe_malloc(len);
         memcpy(tx->tx_in[i].scriptSig, tx0->tx_in[i].scriptSig, len);
      }
   }

   for (i = 0; i < tx->out_count; i++) {
      size_t len = tx->tx_out[i].scriptLength;
      tx->tx_out[i].scriptPubKey = NULL;
      if (len > 0) {
         tx->tx_out[i].scriptPubKey = safe_malloc(len);
         memcpy(tx->tx_out[i].scriptPubKey, tx0->tx_out[i].scriptPubKey, len);
      }
   }
   return tx;
}


/*
 *------------------------------------------------------------------------
 *
 * btc_msg_tx_init --
 *
 *------------------------------------------------------------------------
 */

void
btc_msg_tx_init(btc_msg_tx *tx)
{
   memset(tx, 0, sizeof *tx);
}


/*
 *------------------------------------------------------------------------
 *
 * btc_msg_tx_value --
 *
 *------------------------------------------------------------------------
 */

uint64
btc_msg_tx_value(const btc_msg_tx *tx)
{
   uint64 val = 0;
   int i;

   for (i = 0; i < tx->out_count; i++) {
      val += tx->tx_out[i].value;
   }
   return val;
}


/*
 *------------------------------------------------------------------------
 *
 * btc_msg_tx_free --
 *
 *------------------------------------------------------------------------
 */

void
btc_msg_tx_free(btc_msg_tx *tx)
{
   uint64 i;

   for (i = 0; i < tx->in_count; i++) {
      free(tx->tx_in[i].scriptSig);
   }
   free(tx->tx_in);
   for (i = 0; i < tx->out_count; i++) {
      free(tx->tx_out[i].scriptPubKey);
   }
   free(tx->tx_out);
}


/*
 *------------------------------------------------------------------------
 *
 * btc_msg_block_free --
 *
 *------------------------------------------------------------------------
 */

void
btc_msg_block_free(btc_msg_block *blk)
{
   uint64 i;

   for (i = 0; i < blk->txCount; i++) {
      btc_msg_tx_free(blk->tx + i);
   }
   free(blk->tx);
}


/*
 *------------------------------------------------------------------------
 *
 * btc_msg_merkleblock_free --
 *
 *------------------------------------------------------------------------
 */

void
btc_msg_merkleblock_free(btc_msg_merkleblock *blk)
{
   if (blk == NULL) {
      return;
   }
   free(blk->matchedTxHash);
   free(blk->hash);
   free(blk->bit);
   free(blk);
}


/*
 *------------------------------------------------------------------------
 *
 * BIP157 compact filter messages.
 *
 *------------------------------------------------------------------------
 */

int
btcmsg_craft_getcfilters(const btc_msg_getcfilters *g,
                         struct buff **bufOut)
{
   struct buff *buf;

   buf = buff_alloc();
   serialize_uint8(buf,   g->filterType);
   serialize_uint32(buf,  g->startHeight);
   serialize_uint256(buf, &g->stopHash);

   btcmsg_craft_msgheader(bufOut, "getcfilters", buf);
   buff_free(buf);
   return 0;
}


int
btcmsg_craft_getcfheaders(const btc_msg_getcfheaders *g,
                          struct buff **bufOut)
{
   struct buff *buf;

   buf = buff_alloc();
   serialize_uint8(buf,   g->filterType);
   serialize_uint32(buf,  g->startHeight);
   serialize_uint256(buf, &g->stopHash);

   btcmsg_craft_msgheader(bufOut, "getcfheaders", buf);
   buff_free(buf);
   return 0;
}


int
btcmsg_craft_getcfcheckpt(const btc_msg_getcfcheckpt *g,
                          struct buff **bufOut)
{
   struct buff *buf;

   buf = buff_alloc();
   serialize_uint8(buf,   g->filterType);
   serialize_uint256(buf, &g->stopHash);

   btcmsg_craft_msgheader(bufOut, "getcfcheckpt", buf);
   buff_free(buf);
   return 0;
}


int
btcmsg_parse_cfilter(struct buff *buf, btc_msg_cfilter *cf)
{
   int res;

   memset(cf, 0, sizeof *cf);

   res  = deserialize_uint8(buf, &cf->filterType);
   res |= deserialize_uint256(buf, &cf->blockHash);
   res |= deserialize_varint(buf, &cf->numBytes);
   if (res) {
      return 1;
   }
   if (cf->numBytes > 4000000) {
      Warning(LGPFX" cfilter numBytes=%llu exceeds cap.\n",
              (unsigned long long)cf->numBytes);
      return 1;
   }
   cf->filterData = safe_malloc(cf->numBytes);
   res = deserialize_bytes(buf, cf->filterData, cf->numBytes);
   if (res) {
      free(cf->filterData);
      cf->filterData = NULL;
      return 1;
   }
   return 0;
}


int
btcmsg_parse_cfheaders(struct buff *buf, btc_msg_cfheaders *cfh)
{
   int res;
   uint64 i;

   memset(cfh, 0, sizeof *cfh);

   res  = deserialize_uint8(buf, &cfh->filterType);
   res |= deserialize_uint256(buf, &cfh->stopHash);
   res |= deserialize_uint256(buf, &cfh->prevFilterHeader);
   res |= deserialize_varint(buf, &cfh->numHeaders);
   if (res) {
      return 1;
   }
   if (cfh->numHeaders > 2000) {
      Warning(LGPFX" cfheaders numHeaders=%llu exceeds cap.\n",
              (unsigned long long)cfh->numHeaders);
      return 1;
   }
   cfh->filterHashes = safe_calloc(cfh->numHeaders, sizeof *cfh->filterHashes);
   for (i = 0; i < cfh->numHeaders; i++) {
      res = deserialize_uint256(buf, &cfh->filterHashes[i]);
      if (res) {
         free(cfh->filterHashes);
         cfh->filterHashes = NULL;
         return 1;
      }
   }
   return 0;
}


int
btcmsg_parse_cfcheckpt(struct buff *buf, btc_msg_cfcheckpt *cfc)
{
   int res;
   uint64 i;

   memset(cfc, 0, sizeof *cfc);

   res  = deserialize_uint8(buf, &cfc->filterType);
   res |= deserialize_uint256(buf, &cfc->stopHash);
   res |= deserialize_varint(buf, &cfc->numHeaders);
   if (res) {
      return 1;
   }
   if (cfc->numHeaders > 100000) {
      Warning(LGPFX" cfcheckpt numHeaders=%llu exceeds cap.\n",
              (unsigned long long)cfc->numHeaders);
      return 1;
   }
   cfc->filterHeaders = safe_calloc(cfc->numHeaders, sizeof *cfc->filterHeaders);
   for (i = 0; i < cfc->numHeaders; i++) {
      res = deserialize_uint256(buf, &cfc->filterHeaders[i]);
      if (res) {
         free(cfc->filterHeaders);
         cfc->filterHeaders = NULL;
         return 1;
      }
   }
   return 0;
}


void
btc_msg_cfilter_free(btc_msg_cfilter *cf)
{
   if (cf == NULL) {
      return;
   }
   free(cf->filterData);
   cf->filterData = NULL;
}


void
btc_msg_cfheaders_free(btc_msg_cfheaders *cfh)
{
   if (cfh == NULL) {
      return;
   }
   free(cfh->filterHashes);
   cfh->filterHashes = NULL;
}


void
btc_msg_cfcheckpt_free(btc_msg_cfcheckpt *cfc)
{
   if (cfc == NULL) {
      return;
   }
   free(cfc->filterHeaders);
   cfc->filterHeaders = NULL;
}


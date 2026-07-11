#include <string.h>
#include <stdlib.h>

#include "basic_defs.h"
#include "util.h"
#include "buff.h"
#include "serialize.h"

#define LGPFX "SER:"

/*
 *------------------------------------------------------------------------
 *
 * deserialize_bytes --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_bytes(struct buff *buf,
                  void *val,
                  size_t len)
{
   return buff_copy_from(buf, val, len);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_uint8 --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_uint8(struct buff *buf,
                  uint8 *val)
{
   return deserialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_uint16 --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_uint16(struct buff *buf,
                   uint16 *val)
{
   return deserialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_uint32 --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_uint32(struct buff *buf,
                   uint32 *val)
{
   return deserialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_uint64 --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_uint64(struct buff *buf,
                   uint64 *val)
{
   return deserialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_uint256 --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_uint256(struct buff *buf,
                    uint256 *val)
{
   return deserialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_tx --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_tx(struct buff *buf,
               btc_msg_tx *tx)
{
   uint64 i;
   int res;

   res  = deserialize_uint32(buf, &tx->version);
   res |= deserialize_varint(buf, &tx->in_count);

   tx->tx_in = safe_malloc(tx->in_count * sizeof *tx->tx_in);

   for (i = 0; i < tx->in_count; i++) {
      res |= deserialize_uint256(buf, &tx->tx_in[i].prevTxHash);
      res |= deserialize_uint32(buf,  &tx->tx_in[i].prevTxOutIdx);
      res |= deserialize_varint(buf,  &tx->tx_in[i].scriptLength);
      tx->tx_in[i].scriptSig = safe_malloc(tx->tx_in[i].scriptLength);
      res |= deserialize_bytes(buf,   tx->tx_in[i].scriptSig, tx->tx_in[i].scriptLength);
      res |= deserialize_uint32(buf, &tx->tx_in[i].sequence);
   }

   res |= deserialize_varint(buf, &tx->out_count);

   tx->tx_out = safe_malloc(tx->out_count * sizeof *tx->tx_out);

   for (i = 0; i < tx->out_count; i++) {
      res |= deserialize_uint64(buf, &tx->tx_out[i].value);
      res |= deserialize_varint(buf, &tx->tx_out[i].scriptLength);
      tx->tx_out[i].scriptPubKey = safe_malloc(tx->tx_out[i].scriptLength);
      res |= deserialize_bytes(buf, tx->tx_out[i].scriptPubKey, tx->tx_out[i].scriptLength);
   }

   res |= deserialize_uint32(buf, &tx->lock_time);

   ASSERT_NOT_TESTED(buff_space_left(buf) == 0);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_tx --
 *
 *------------------------------------------------------------------------
 */

int
serialize_tx(struct buff *buf,
             const btc_msg_tx *tx)
{
   uint64 i;
   int res;

   res  = serialize_uint32(buf, tx->version);
   res |= serialize_varint(buf, tx->in_count);

   for (i = 0; i < tx->in_count; i++) {
      res |= serialize_uint256(buf, &tx->tx_in[i].prevTxHash);
      res |= serialize_uint32(buf,   tx->tx_in[i].prevTxOutIdx);
      res |= serialize_varint(buf,   tx->tx_in[i].scriptLength);
      res |= serialize_bytes(buf,    tx->tx_in[i].scriptSig, tx->tx_in[i].scriptLength);
      res |= serialize_uint32(buf,   tx->tx_in[i].sequence);
   }

   res |= serialize_varint(buf, tx->out_count);

   for (i = 0; i < tx->out_count; i++) {
      res |= serialize_uint64(buf, tx->tx_out[i].value);
      res |= serialize_varint(buf, tx->tx_out[i].scriptLength);
      res |= serialize_bytes(buf,  tx->tx_out[i].scriptPubKey, tx->tx_out[i].scriptLength);
   }

   res |= serialize_uint32(buf, tx->lock_time);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_block --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_block(struct buff *buf,
                  btc_msg_block *blk)
{
   uint64 i;
   int res;

   res  = deserialize_blockheader(buf, &blk->header);
   btcmsg_print_header(&blk->header);
   res |= deserialize_varint(buf, &blk->txCount);
   Warning("numTx=%llu\n", blk->txCount);

   blk->tx = safe_malloc(blk->txCount * sizeof *blk->tx);

   for (i = 0; i < blk->txCount; i++) {
      res |= deserialize_tx(buf, blk->tx + i);
   }

   Warning("sz: %zu vs %zu\n", buff_curlen(buf) ,buff_maxlen(buf));
   ASSERT(buff_space_left(buf) == 0);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_varint --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_varint(struct buff *buf,
                   uint64 *val)
{
   int res;
   uint8 c;

   res = deserialize_uint8(buf, &c);
   if (res) {
      return res;
   }

   if (c < 253) {
      *val = c;
   } else if (c == 253) {
      uint16 len16 = 0;
      res = deserialize_uint16(buf, &len16);
      *val = len16;
   } else if (c == 254) {
      uint32 len32 = 0;
      res = deserialize_uint32(buf, &len32);
      *val = len32;
   } else {
      uint64 len64 = 0;
      res = deserialize_uint64(buf, &len64);
      *val = len64;
   }
   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_str --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_str(struct buff *buf,
                char *str,
                size_t size)
{
   uint64 len;
   int res;

   memset(str, 0, size);

   res = deserialize_varint(buf, &len);
   if (res) {
      return res;
   }
   if (len == 0) {
      return 0;
   }

   if (len >= size) {
      NOT_TESTED();
      return 1;
   }
   str[size - 1] = '\0';
   if (len < size) {
      str[len] = '\0';
   }
   return deserialize_bytes(buf, str, len);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_str_alloc --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_str_alloc(struct buff *buf,
                      char **str,
                      size_t *len)
{
   uint64 length;
   int res;

   *str = NULL;
   if (len) {
      *len = 0;
   }

   res = deserialize_varint(buf, &length);
   if (res) {
      return res;
   }
   if (length == 0) {
      return 0;
   }

   *str = safe_calloc(1, length + 1);
   if (len) {
      *len = length;
   }

   if (deserialize_bytes(buf, *str, length)) {
      free(*str);
      *str = NULL;
      if (len) {
         *len = 0;
      }
      return 1;
   }
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_bytes --
 *
 *------------------------------------------------------------------------
 */

int
serialize_bytes(struct buff *dst,
                const void *src,
                size_t len)
{
   return buff_copy_to(dst, src, len);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_uint8 --
 *
 *------------------------------------------------------------------------
 */

int
serialize_uint8(struct buff *buf,
                const uint8 val)
{
   return serialize_bytes(buf, &val, sizeof val);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_uint16 --
 *
 *------------------------------------------------------------------------
 */

int
serialize_uint16(struct buff *buf,
                 const uint16 val)
{
   return serialize_bytes(buf, &val, sizeof val);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_uint32 --
 *
 *------------------------------------------------------------------------
 */

int
serialize_uint32(struct buff *buf,
                 const uint32 val)
{
   return serialize_bytes(buf, &val, sizeof val);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_uint64 --
 *
 *------------------------------------------------------------------------
 */

int
serialize_uint64(struct buff *buf,
                 const uint64 val)
{
   return serialize_bytes(buf, &val, sizeof val);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_uint256 --
 *
 *------------------------------------------------------------------------
 */

int
serialize_uint256(struct buff *buf,
                  const uint256 *val)
{
   return serialize_bytes(buf, val, sizeof *val);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_varint --
 *
 *------------------------------------------------------------------------
 */

int
serialize_varint(struct buff *buf,
                 const uint64 val)
{
   int res;
   uint8 c;

   if (val < 253) {
      c = val;
      return serialize_uint8(buf, c);
   } else if (val < 0x10000) {
      uint16 len16 = val;
      c = 253;
      res = serialize_uint8(buf, c);
      if (res) {
         return res;
      }
      return serialize_uint16(buf, len16);
   } else {
      uint32 len32 = val;
      c = 254;
      res = serialize_uint8(buf, c);
      if (res) {
         return res;
      }
      return serialize_uint32(buf, len32);
   }
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_str --
 *
 *------------------------------------------------------------------------
 */

int
serialize_str(struct buff *buf,
              const char *str)
{
   uint64 len;
   int res;

   len = str ? strlen(str) : 0;
   res = serialize_varint(buf, len);
   if (res) {
      return res;
   }
   return serialize_bytes(buf, str, len);
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_msgheader --
 *
 *------------------------------------------------------------------------
 */

int
serialize_msgheader(struct buff *buf,
                    const btc_msg_header *h)
{
   int res;

   res  = serialize_uint32(buf, h->magic);
   res |= serialize_bytes(buf,  h->message, ARRAYSIZE(h->message));
   res |= serialize_uint32(buf, h->payloadLength);
   res |= serialize_bytes(buf,  h->checksum, ARRAYSIZE(h->checksum));

   ASSERT_NOT_TESTED(res == 0);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_addr --
 *
 *------------------------------------------------------------------------
 */

int
serialize_addr(struct buff *buf,
               const btc_msg_address *addr)
{
   int res;

   res  = serialize_uint64(buf, addr->services);
   res |= serialize_bytes(buf,  addr->ip, ARRAYSIZE(addr->ip));
   res |= serialize_uint16(buf, addr->port);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_version --
 *
 *------------------------------------------------------------------------
 */

int
serialize_version(struct buff *buf,
                  const btc_msg_version *v)
{
   int res;

   res  = serialize_uint32(buf, v->version);
   res |= serialize_uint64(buf, v->services);
   res |= serialize_uint64(buf, v->time);

   res |= serialize_addr(buf, &v->addrTo);
   res |= serialize_addr(buf, &v->addrFrom);

   res |= serialize_uint64(buf, v->nonce);
   res |= serialize_str(buf,    v->strVersion);
   res |= serialize_uint32(buf, v->startingHeight);

   /*
    * BIP37: peers speaking >= 70001 read a trailing relay flag. We set it
    * to 0 so peers don't stream unsolicited transactions at us -- as an SPV
    * client we learn about relevant txs by fetching matched blocks.
    */
   if (v->version >= BTC_PROTO_FILTERING) {
      res |= serialize_uint8(buf, v->relayTx);
   }

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_blocklocator --
 *
 *------------------------------------------------------------------------
 */

int
serialize_blocklocator(struct buff *buf,
                       const btc_block_locator *bl)
{
   int res;
   int i;

   res  = serialize_uint32(buf, bl->protversion);
   res |= serialize_varint(buf, bl->numHashes);
   for (i = 0; i < bl->numHashes; i++) {
      res |= serialize_uint256(buf, &bl->hashArray[i]);
   }
   res |= serialize_uint256(buf, &bl->hashStop);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_blockheader --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_blockheader(struct buff *buf,
                        btc_block_header *hdr)
{
   int res;

   res  = deserialize_uint32(buf,  &hdr->version);
   res |= deserialize_uint256(buf, &hdr->prevBlock);
   res |= deserialize_uint256(buf, &hdr->merkleRoot);
   res |= deserialize_uint32(buf,  &hdr->timestamp);
   res |= deserialize_uint32(buf,  &hdr->bits);
   res |= deserialize_uint32(buf,  &hdr->nonce);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_addr --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_addr(uint32 protversion,
                 struct buff *buf,
                 btc_msg_address *addr)
{
   int res = 0;

   addr->time = 0;
   if (protversion >= BTC_PROTO_ADDR_W_TIME) {
      res = deserialize_uint32(buf, &addr->time);
   }
   res |= deserialize_uint64(buf, &addr->services);
   res |= deserialize_bytes(buf, addr->ip, ARRAYSIZE(addr->ip));
   res |= deserialize_uint16(buf, &addr->port);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * serialize_inv --
 *
 *------------------------------------------------------------------------
 */

int
serialize_inv(struct buff *buf,
              const btc_msg_inv *inv)
{
   int res;

   res  = serialize_uint32(buf, inv->type);
   res |= serialize_bytes(buf, &inv->hash, sizeof inv->hash);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_inv --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_inv(struct buff *buf,
                btc_msg_inv *inv)
{
   int res;

   res = deserialize_uint32(buf, &inv->type);
   if (res) {
      return res;
   }
   return deserialize_bytes(buf, &inv->hash, sizeof inv->hash);
}


/*
 *------------------------------------------------------------------------
 *
 * deserialize_version --
 *
 *------------------------------------------------------------------------
 */

int
deserialize_version(struct buff *buf,
                    btc_msg_version *v)
{
   int res;

   memset(v, 0, sizeof *v);

   res  = deserialize_uint32(buf, &v->version);
   res |= deserialize_uint64(buf, &v->services);
   res |= deserialize_uint64(buf, &v->time);
   res |= deserialize_addr(BTC_PROTO_MIN, buf, &v->addrTo);
   res |= deserialize_addr(BTC_PROTO_MIN, buf, &v->addrFrom);
   res |= deserialize_uint64(buf, &v->nonce);
   res |= deserialize_str(buf,     v->strVersion, sizeof v->strVersion);
   res |= deserialize_uint32(buf, &v->startingHeight);

   if (v->version >= BTC_PROTO_FILTERING &&
       buff_space_left(buf) > 0) {
      res |= deserialize_uint8(buf, &v->relayTx);
   } else {
      v->relayTx = 1;
   }
   ASSERT(buff_space_left(buf) == 0);

   return res;
}


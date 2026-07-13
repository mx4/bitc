#include "script.h"
#include "util.h"
#include "btc-message.h"
#include "serialize.h"
#include "buff.h"
#include "key.h"
#include "wallet.h"

#define LGPFX "SCRIPT:"


static const uint8 std_pubkey[] = {
   OP_PUBKEY, OP_CHECKSIG,
};

static const uint8 std_pubkeyhash[] = {
   OP_DUP, OP_HASH160, OP_PUBKEYHASH, OP_EQUALVERIFY, OP_CHECKSIG,
};


static const struct {
   enum script_txout_type type;
   size_t                 len;
   const uint8           *opcodes;
} std_scripts[] = {
   { TX_PUBKEY,     sizeof(std_pubkey),     std_pubkey },
   { TX_PUBKEYHASH, sizeof(std_pubkeyhash), std_pubkeyhash },
};


struct script_inst {
   uint8        opcode;
   const uint8 *data;
   size_t       len;
};


struct script {
   struct script_inst *inst;
   int                 len;
   int                 max_len;
};



/*
 *------------------------------------------------------------------------
 *
 * script_push_data --
 *
 *------------------------------------------------------------------------
 */

static void
script_push_data(struct buff *buf,
                 const void  *data,
                 size_t       len)
{
   ASSERT(buf->grow);

   log_info("%s: len=%zu / %#zx\n", __func__, len, len);

   if (len < OP_PUSHDATA1) {
      serialize_uint8(buf, len);
   } else if (len <= 0xff) {
      serialize_uint8(buf, OP_PUSHDATA1);
      serialize_uint8(buf, len);
   } else if (len <= 0xffff) {
      serialize_uint8(buf, OP_PUSHDATA2);
      serialize_uint16(buf, len);
   } else {
      serialize_uint8(buf, OP_PUSHDATA4);
      serialize_uint32(buf, len);
   }
   serialize_bytes(buf, data, len);
}


/*
 *------------------------------------------------------------------------
 *
 * script_sign_hash --
 *
 *------------------------------------------------------------------------
 */

static int
script_sign_hash(struct wallet         *wallet,
                 const uint160         *keyHash,
                 const uint256         *hash,
                 enum script_hash_type  hashType,
                 struct buff           *script)
{
   struct key *k;
   size_t siglen;
   uint8 *sig;
   bool s;

   k = wallet_lookup_pubkey(wallet, keyHash);
   if (k == NULL) {
      return 1;
   }

   s = key_sign(k, hash, sizeof *hash, &sig, &siglen);
   if (!s) {
      return 1;
   }
   log_info(LGPFX" siglen=%zu\n", siglen);

   /*
    * Verify the signature is good. This code is new..
    */
   s = key_verify(k, hash, sizeof *hash, sig, siglen);
   ASSERT(s == 1);

   uint8 *push_data = safe_malloc(siglen + 1);

   memcpy(push_data, sig, siglen);
   free(sig);
   push_data[siglen] = (uint8)hashType;

   script_push_data(script, push_data, siglen + 1);
   free(push_data);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * script_inst_ispush --
 *
 *------------------------------------------------------------------------
 */

static bool
script_inst_ispush(const struct script_inst *inst)
{
   return inst->opcode <= OP_PUSHDATA4;
}


/*
 *------------------------------------------------------------------------
 *
 * script_inst_match --
 *
 *------------------------------------------------------------------------
 */

static bool
script_inst_match(const struct script_inst *inst,
                  uint8 opcode_template)
{
   ASSERT(inst);

   if (opcode_template == OP_PUBKEY) {
      if (!script_inst_ispush(inst)) {
         return 0;
      }
      if (inst->len < 23 || inst->len > 120) {
         return 0;
      }
      return 1;
   } else if (opcode_template == OP_PUBKEYHASH) {
      if (!script_inst_ispush(inst)) {
         return 0;
      }
      if (inst->len != sizeof(uint160)) {
         return 0;
      }
      return 1;
   } else {
      if (script_inst_ispush(inst)) {
         return 0;
      }
      return inst->opcode == opcode_template;
   }
}


/*
 *------------------------------------------------------------------------
 *
 * script_check_resize --
 *
 *------------------------------------------------------------------------
 */

static void
script_check_resize(struct script *script)
{
   if (script->len < script->max_len) {
      return;
   }
   script->max_len *= 2;
   script->inst = safe_realloc(script->inst,
                               script->max_len * sizeof *script->inst);
}


/*
 *------------------------------------------------------------------------
 *
 * script_alloc --
 *
 *------------------------------------------------------------------------
 */

static struct script *
script_alloc(void)
{
   struct script *script;

   script = safe_malloc(sizeof *script);
   script->len = 0;
   script->max_len = 1;
   script->inst = safe_malloc(script->max_len * sizeof *script->inst);

   return script;
}


/*
 *------------------------------------------------------------------------
 *
 * script_free --
 *
 *------------------------------------------------------------------------
 */

static void
script_free(struct script *script)
{
   free(script->inst);
   free(script);
}


/*
 *------------------------------------------------------------------------
 *
 * script_parse_one_op --
 *
 *------------------------------------------------------------------------
 */

static bool
script_parse_one_op(struct buff *buf,
                    struct script_inst *inst,
                    bool *error)
{
   uint8 opcode;
   size_t len;
   int res;

   ASSERT(buf);
   ASSERT(inst);
   ASSERT(error);

   *error = 0;
   if (buff_space_left(buf) == 0) {
      /* done ! */
      return 0;
   }

   res = deserialize_uint8(buf, &opcode);
   if (res) {
      goto error;
   }
   inst->opcode = opcode;

   if (opcode < OP_PUSHDATA1) {
      len = opcode;
   } else if (opcode == OP_PUSHDATA1) {
      uint8 len8;
      res = deserialize_uint8(buf, &len8);
      if (res) {
         goto error;
      }
      len = len8;
   } else if (opcode == OP_PUSHDATA2) {
      uint16 len16;
      res = deserialize_uint16(buf, &len16);
      if (res) {
         goto error;
      }
      len = len16;
   } else if (opcode == OP_PUSHDATA4) {
      uint32 len32;
      res = deserialize_uint32(buf, &len32);
      if (res) {
         goto error;
      }
      len = len32;
   } else {
      /*
       * opcode with no data.
       */
      inst->data = NULL;
      inst->len  = 0;

      return 1;
   }

   inst->data = buff_curptr(buf);
   inst->len  = len;

   res = buff_skip(buf, len);
   if (res) {
      goto error;
   }

   return 1;
error:
   *error = 1;
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * script_parse --
 *
 *------------------------------------------------------------------------
 */

static struct script *
script_parse(struct buff *buf)
{
   struct script *script;
   bool error = 0;

   script = script_alloc();

   while (1) {
      struct script_inst inst;
      bool s;

      s = script_parse_one_op(buf, &inst, &error);
      if (s == 0) {
         break;
      }
      script->inst[script->len] = inst;
      script->len++;
      script_check_resize(script);
   }
   if (error == 0) {
      return script;
   }

   script_free(script);
   return NULL;
}


/*
 *------------------------------------------------------------------------
 *
 * script_classify --
 *
 *------------------------------------------------------------------------
 */

static enum script_txout_type
script_classify(struct script *script)
{
   int i;

   for (i = 0; i < ARRAYSIZE(std_scripts); i++) {
      const uint8 *opcodes;
      bool match = 0;
      size_t len;
      int j;

      opcodes = std_scripts[i].opcodes;
      len     = std_scripts[i].len;

      if (script->len != len) {
         continue;
      }

      for (j = 0; j < len; j++) {
         match = script_inst_match(script->inst + j, opcodes[j]);
         if (!match) {
            break;
         }
      }
      if (match) {
         /* found it! */
         return std_scripts[i].type;
      }
   }
   return TX_NONSTANDARD;
}


/*
 *------------------------------------------------------------------------
 *
 * script_txo_generate --
 *
 *------------------------------------------------------------------------
 */

int
script_txo_generate(const uint160 *pubkey,
                    uint8 **script,
                    uint64 *scriptLen)
{
   struct buff *buf = buff_alloc();

   serialize_uint8(buf, OP_DUP);
   serialize_uint8(buf, OP_HASH160);
   script_push_data(buf, pubkey, sizeof *pubkey);
   serialize_uint8(buf, OP_EQUALVERIFY);
   serialize_uint8(buf, OP_CHECKSIG);

   *script    = buff_base(buf);
   *scriptLen = buff_curlen(buf);

   free(buf);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * script_tx_sighash --
 *
 *      https://en.bitcoin.it/wiki/OP_CHECKSIG
 *
 *------------------------------------------------------------------------
 */

static void
script_tx_sighash(struct wallet           *wallet,
                  uint256                 *hash,
                  const struct buff       *scriptPubKey,
                  const struct btc_msg_tx *tx,
                  uint32                   idx,
                  enum script_hash_type    hashType)
{
   struct btc_msg_tx *tx2;
   struct buff *buf;
   int i;

   ASSERT(idx < tx->in_count);

   memset(hash, 0, sizeof *hash);
   tx2 = btc_msg_tx_dup(tx);

   log_info(LGPFX" Computing sighash for txi-%u/%" PRIu64 "\n", idx, tx2->in_count);

   /*
    * Zero-out all the inputs' signatures.
    */
   for (i = 0; i < tx2->in_count; i++) {
      tx2->tx_in[i].scriptLength = 0;
   }

   size_t len = buff_maxlen(scriptPubKey);
   ASSERT(len > 0);

   ASSERT(tx2->tx_in[idx].scriptSig == NULL);
   ASSERT(tx2->tx_in[idx].scriptLength == 0);

   tx2->tx_in[idx].scriptLength = len;
   tx2->tx_in[idx].scriptSig = safe_malloc(len);

   memcpy(tx2->tx_in[idx].scriptSig, buff_base(scriptPubKey), len);

   ASSERT((hashType & 0x1f) == SIGHASH_ALL);

   /*
    * Final step:
    *
    * Serialize tx + hashType (as a uint32) and compute hash.
    */

   buf = buff_alloc();
   serialize_tx(buf, tx2);
   serialize_uint32(buf, hashType);
   hash256_calc(buff_base(buf), buff_curlen(buf), hash);
   buff_free(buf);

   btc_msg_tx_free(tx2);
   free(tx2);
}


/*
 *------------------------------------------------------------------------
 *
 * script_match_type --
 *
 *------------------------------------------------------------------------
 */

static int
script_match_type(struct buff            *buf,
                  enum script_txout_type *type,
                  uint8                 **data_addr,
                  size_t                 *data_len)
{
   struct script *script;

   ASSERT(type);
   ASSERT(data_addr);
   ASSERT(data_len);

   *data_addr = NULL;

   script = script_parse(buf);
   if (script == NULL) {
      NOT_TESTED();
      return 1;
   }

   *type = script_classify(script);

   switch (*type) {
   case TX_PUBKEY:
      *data_len  = script->inst[0].len;
      *data_addr = safe_malloc(*data_len);
      memcpy(*data_addr, script->inst[0].data, *data_len);
      ASSERT(*data_addr);
      break;
   case TX_PUBKEYHASH:
      *data_len  = script->inst[2].len;
      *data_addr = safe_malloc(*data_len);
      ASSERT(*data_len == sizeof(uint160));
      memcpy(*data_addr, script->inst[2].data, *data_len);
      break;
   default:
      *data_addr = NULL;
      *data_len = 0;
      break;
   }

   script_free(script);
   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * script_push_pubkey --
 *
 *------------------------------------------------------------------------
 */

static int
script_push_pubkey(struct wallet *wallet,
                   const uint160 *keyHash,
                   struct buff   *scriptSig)
{
   size_t pkeylen;
   uint8 *pkey;
   struct key *k;

   k = wallet_lookup_pubkey(wallet, keyHash);
   if (k == NULL) {
      return 1;
   }

   key_get_pubkey(k, &pkey, &pkeylen);

   log_info(LGPFX" pkeylen=%zu\n", pkeylen);
   script_push_data(scriptSig, pkey, pkeylen);
   free(pkey);

   return 0;
}


/*
 *------------------------------------------------------------------------
 *
 * script_sign --
 *
 *------------------------------------------------------------------------
 */

int
script_sign(struct wallet               *wallet,
            const struct btc_msg_tx_out *txo,
            struct btc_msg_tx           *tx,
            uint32                       idx,
            enum script_hash_type        hashType)
{
   struct btc_msg_tx_in *txi;
   enum script_txout_type type;
   struct buff *scriptSig;
   struct buff scriptPubKey;
   uint8 *data_addr;
   size_t data_len;
   uint256 hash;
   int res;

   ASSERT(idx < tx->in_count);
   scriptSig = buff_alloc();
   buff_init(&scriptPubKey, txo->scriptPubKey, txo->scriptLength);

   log_bytes("scriptPubKey:", txo->scriptPubKey, txo->scriptLength);

   script_tx_sighash(wallet, &hash, &scriptPubKey, tx, idx, hashType);

   res = script_match_type(&scriptPubKey, &type, &data_addr, &data_len);
   if (res) {
      NOT_TESTED();
      goto exit;
   }

   switch (type) {
   case TX_PUBKEY:
      log_warn(LGPFX" script TX_PUBKEY\n");
      NOT_IMPLEMENTED();
      break;
   case TX_PUBKEYHASH: {
      uint160 *keyHash = (uint160*)data_addr;

      ASSERT(data_len == sizeof(uint160));

      res = script_sign_hash(wallet, keyHash, &hash, hashType, scriptSig);
      if (res) {
         NOT_TESTED();
         goto exit;
      }

      res = script_push_pubkey(wallet, keyHash, scriptSig);
      if (res) {
         NOT_TESTED();
         goto exit;
      }
      break;
   }
   default:
      NOT_IMPLEMENTED();
      log_warn(LGPFX" script TX_NONSTANDARD\n");
      break;
   }

   txi = tx->tx_in + idx;
   txi->scriptLength = buff_curlen(scriptSig);
   txi->scriptSig    = buff_base(scriptSig);

exit:
   free(scriptSig);
   free(data_addr);

   return res;
}


/*
 *------------------------------------------------------------------------
 *
 * script_parse_pubkey_hash --
 *
 *------------------------------------------------------------------------
 */

int
script_parse_pubkey_hash(const uint8 *scriptPubKey,
                         size_t scriptLength,
                         uint160 *pubkey)
{
   enum script_txout_type type;
   struct buff buf;
   size_t datalen;
   uint8 *data;
   int res;

   uint160_zero_out(pubkey);
   buff_init(&buf, (uint8*)scriptPubKey, scriptLength);

   res = script_match_type(&buf, &type, &data, &datalen);
   if (res) {
      NOT_TESTED();
      return 1;
   }

   switch (type) {
   case TX_PUBKEY:
      log_warn(LGPFX" script TX_PUBKEY\n");
      NOT_TESTED();
      hash160_calc(data, datalen, pubkey);
      break;
   case TX_PUBKEYHASH:
      ASSERT(datalen == sizeof(uint160));
      memcpy(pubkey, data, sizeof(uint160));
      break;
   default:
      NOT_TESTED();
      res = 1;
      break;
   }
   free(data);
   return res;
}

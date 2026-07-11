#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "util.h"
#include "key.h"
#include "hash.h"

#define LGPFX "KEY:"

/*
 * secp256k1 keys, backed by the OpenSSL 3.x EVP_PKEY API for signing and
 * verification. The low-level EC_KEY / ECDSA_* interface used previously is
 * deprecated in OpenSSL 3; EC_GROUP/EC_POINT scalar arithmetic (used here only
 * to derive the compressed public key from the private scalar) is not.
 */
struct key {
   EVP_PKEY     *pkey;
   uint8        *pub_key;    /* cached compressed public key */
   size_t        pub_len;
};


/*
 *------------------------------------------------------------------------
 *
 * key_pubkey_from_priv_bn --
 *
 *      Compute the compressed public key (33 bytes, 0x02/0x03 || X) for the
 *      given private scalar: pub = priv * G on secp256k1. Returns the same
 *      encoding the old i2o_ECPublicKey(COMPRESSED) path produced, so derived
 *      addresses are unchanged.
 *
 *------------------------------------------------------------------------
 */

static bool
key_pubkey_from_priv_bn(const BIGNUM *priv,
                        uint8       **pub,
                        size_t       *pub_len)
{
   EC_GROUP *grp;
   EC_POINT *point;
   BN_CTX *ctx;
   size_t len;
   bool ok = 0;

   *pub = NULL;
   *pub_len = 0;

   grp = EC_GROUP_new_by_curve_name(NID_secp256k1);
   ctx = BN_CTX_new();
   if (grp == NULL || ctx == NULL) {
      goto out;
   }
   point = EC_POINT_new(grp);
   if (point == NULL) {
      goto out;
   }

   if (EC_POINT_mul(grp, point, priv, NULL, NULL, ctx) != 1) {
      log_info(LGPFX" EC_POINT_mul failed.\n");
      goto out_point;
   }

   len = EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,
                            NULL, 0, ctx);
   if (len == 0 || len > 65) {
      goto out_point;
   }
   *pub = safe_malloc(len);
   if (EC_POINT_point2oct(grp, point, POINT_CONVERSION_COMPRESSED,
                          *pub, len, ctx) != len) {
      free(*pub);
      *pub = NULL;
      goto out_point;
   }
   *pub_len = len;
   ok = 1;

out_point:
   EC_POINT_free(point);
out:
   BN_CTX_free(ctx);
   EC_GROUP_free(grp);
   return ok;
}


/*
 *------------------------------------------------------------------------
 *
 * key_build_pkey --
 *
 *      Assemble an EVP_PKEY keypair from the private scalar and its
 *      (already computed) compressed public key.
 *
 *------------------------------------------------------------------------
 */

static EVP_PKEY *
key_build_pkey(const BIGNUM *priv,
               const uint8  *pub,
               size_t        pub_len)
{
   OSSL_PARAM_BLD *bld;
   OSSL_PARAM *params = NULL;
   EVP_PKEY_CTX *ctx = NULL;
   EVP_PKEY *pkey = NULL;

   bld = OSSL_PARAM_BLD_new();
   if (bld == NULL) {
      return NULL;
   }
   if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                       "secp256k1", 0) != 1 ||
       OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv) != 1 ||
       OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub, pub_len) != 1) {
      goto out;
   }
   params = OSSL_PARAM_BLD_to_param(bld);
   if (params == NULL) {
      goto out;
   }
   ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
   if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1) {
      goto out;
   }
   if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
      pkey = NULL;
   }

out:
   EVP_PKEY_CTX_free(ctx);
   OSSL_PARAM_free(params);
   OSSL_PARAM_BLD_free(bld);
   return pkey;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_privkey --
 *
 *------------------------------------------------------------------------
 */

bool
key_get_privkey(struct key *k,
                uint8     **priv,
                size_t     *len)
{
   BIGNUM *bn = NULL;

   ASSERT(priv);
   *priv = NULL;
   *len = 0;

   if (k->pkey == NULL) {
      return 0;
   }
   if (EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) != 1) {
      return 0;
   }

   *len = BN_num_bytes(bn) + 1;
   *priv = safe_malloc(*len);
   BN_bn2bin(bn, *priv);

   /*
    * Compressed key.
    */
   (*priv)[*len - 1] = 1;

   BN_clear_free(bn);
   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_pubkey --
 *
 *------------------------------------------------------------------------
 */

void
key_get_pubkey(struct key *k,
               uint8     **pub,
               size_t    *len)
{
   ASSERT(pub);
   *pub = safe_malloc(k->pub_len);
   *len = k->pub_len;

   memcpy(*pub, k->pub_key, *len);
}


/*
 *------------------------------------------------------------------------
 *
 * key_free --
 *
 *------------------------------------------------------------------------
 */

void
key_free(struct key *k)
{
   if (k == NULL) {
      return;
   }
   free(k->pub_key);
   EVP_PKEY_free(k->pkey);
   free(k);
}


/*
 *------------------------------------------------------------------------
 *
 * key_generate_new --
 *
 *------------------------------------------------------------------------
 */

struct key *
key_generate_new(void)
{
   EVP_PKEY_CTX *gctx;
   EVP_PKEY *pkey = NULL;
   BIGNUM *priv = NULL;
   struct key *k;
   OSSL_PARAM params[2];

   params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)"secp256k1", 0);
   params[1] = OSSL_PARAM_construct_end();

   gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
   if (gctx == NULL || EVP_PKEY_keygen_init(gctx) != 1 ||
       EVP_PKEY_CTX_set_params(gctx, params) != 1 ||
       EVP_PKEY_generate(gctx, &pkey) != 1) {
      log_info(LGPFX" EC key generation failed.\n");
      EVP_PKEY_CTX_free(gctx);
      EVP_PKEY_free(pkey);
      return NULL;
   }
   EVP_PKEY_CTX_free(gctx);

   if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1) {
      EVP_PKEY_free(pkey);
      return NULL;
   }

   k = key_alloc();
   k->pkey = pkey;
   if (!key_pubkey_from_priv_bn(priv, &k->pub_key, &k->pub_len)) {
      BN_clear_free(priv);
      key_free(k);
      return NULL;
   }
   BN_clear_free(priv);

   return k;
}


/*
 *------------------------------------------------------------------------
 *
 * key_set_privkey --
 *
 *------------------------------------------------------------------------
 */

bool
key_set_privkey(struct key *k,
                const void *privkey,
                size_t len)
{
   BIGNUM *bn;

   /*
    * Cf bitcoin/src/base58.h
    *    bitcoin/src/key.h
    *
    * If len == 33 and privkey[32] == 1, then:
    *   "the public key corresponding to this private key is (to be)
    *   compressed."
    */
   ASSERT(len == 32 || len == 33);

   bn = BN_bin2bn(privkey, 32, NULL);
   ASSERT(bn);

   if (!key_pubkey_from_priv_bn(bn, &k->pub_key, &k->pub_len)) {
      BN_clear_free(bn);
      return 0;
   }

   k->pkey = key_build_pkey(bn, k->pub_key, k->pub_len);
   BN_clear_free(bn);

   if (k->pkey == NULL) {
      free(k->pub_key);
      k->pub_key = NULL;
      k->pub_len = 0;
      return 0;
   }

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_verify --
 *
 *------------------------------------------------------------------------
 */

bool
key_verify(struct key *k,
           const void *data,
           size_t      datalen,
           const void *sig,
           size_t      siglen)
{
   EVP_PKEY_CTX *ctx;
   int res;

   ctx = EVP_PKEY_CTX_new_from_pkey(NULL, k->pkey, NULL);
   if (ctx == NULL || EVP_PKEY_verify_init(ctx) != 1) {
      EVP_PKEY_CTX_free(ctx);
      return 0;
   }
   res = EVP_PKEY_verify(ctx, sig, siglen, data, datalen);
   EVP_PKEY_CTX_free(ctx);

   return res == 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_sign --
 *
 *------------------------------------------------------------------------
 */

bool
key_sign(struct key *k,
         const void *data,
         size_t      datalen,
         uint8     **sig,
         size_t     *siglen)

{
   EVP_PKEY_CTX *ctx;
   size_t len = 0;
   uint8 *sig0;

   ASSERT(sig);
   ASSERT(siglen);

   ctx = EVP_PKEY_CTX_new_from_pkey(NULL, k->pkey, NULL);
   if (ctx == NULL || EVP_PKEY_sign_init(ctx) != 1) {
      NOT_TESTED();
      EVP_PKEY_CTX_free(ctx);
      return 0;
   }

   if (EVP_PKEY_sign(ctx, NULL, &len, data, datalen) != 1) {
      NOT_TESTED();
      EVP_PKEY_CTX_free(ctx);
      return 0;
   }
   sig0 = safe_calloc(1, len);
   if (EVP_PKEY_sign(ctx, sig0, &len, data, datalen) != 1) {
      NOT_TESTED();
      free(sig0);
      EVP_PKEY_CTX_free(ctx);
      return 0;
   }
   EVP_PKEY_CTX_free(ctx);

   *sig = sig0;
   *siglen = len;

   return 1;
}


/*
 *------------------------------------------------------------------------
 *
 * key_alloc --
 *
 *------------------------------------------------------------------------
 */

struct key *
key_alloc(void)
{
   struct key *k;

   k = safe_malloc(sizeof *k);
   k->pkey = NULL;
   k->pub_key = NULL;
   k->pub_len = 0;

   return k;
}


/*
 *------------------------------------------------------------------------
 *
 * key_get_pubkey_hash160 --
 *
 *------------------------------------------------------------------------
 */

void
key_get_pubkey_hash160(const struct key *k,
                       uint160          *hash)
{
   ASSERT(k->pub_key);
   ASSERT(k->pub_len > 0);

   Log_Bytes(LGPFX" pubkey: ", k->pub_key, k->pub_len);

   hash160_calc(k->pub_key, k->pub_len, hash);
}

#include <string.h>
#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "util.h"
#include "hash.h"
#include "crypt.h"

#define LGPFX "CRYPT:"


/*
 *---------------------------------------------------------------------
 *
 * secure_alloc --
 *
 *---------------------------------------------------------------------
 */

struct secure_area*
secure_alloc(size_t len)
{
   struct secure_area *area;
   size_t alloc_len;
   bool s;

   alloc_len = sizeof *area + len;
   area = safe_calloc(1, alloc_len);
   area->len       = len;
   area->alloc_len = alloc_len;

   s = util_memlock(area, alloc_len);
   if (s == 1) {
      return area;
   }
   free(area);

   return NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * secure_free --
 *
 *---------------------------------------------------------------------
 */

void
secure_free(struct secure_area *area)
{
   size_t len;

   if (area == NULL) {
      return;
   }

   /*
    * First clean, and only then munlock().
    */
   len = area->alloc_len;
   OPENSSL_cleanse(area, len);
   util_memunlock(area, len);
   free(area);
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_determine_count --
 *
 *---------------------------------------------------------------------
 */

static int
crypt_determine_count(const struct secure_area *pass,
                      struct crypt_key         *ckey)
{
   int64 count;
   int loop;

   count = CRYPT_NUM_ITERATIONS_OLD;
   loop = 3;

   while (loop > 0) {
      mtime_t ts;
      int len;

      ts = time_get();
      len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), ckey->salt,
                           pass->buf, pass->len, count, ckey->key, ckey->iv);

      if (len != sizeof ckey->key) {
         OPENSSL_cleanse(ckey->key, sizeof ckey->key);
         OPENSSL_cleanse(ckey->iv,  sizeof ckey->iv);
         return -1;
      }
      ts = time_get() - ts;
      ASSERT(ts > 0);
      count = count * 100 * 1000 * 1.0 / ts;
      loop--;
   }

   log_info(LGPFX" %s: result= %llu\n", __func__, count);

   return MAX(CRYPT_NUM_ITERATIONS_MIN, count);
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_set_key_from_passphrase --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_set_key_from_passphrase(const struct secure_area *pass,
                              struct crypt_key         *ckey,
                              int64                    *count_ptr)
{
   int count;
   int len;

   ASSERT(count_ptr);

   count = *count_ptr;
   if (*count_ptr == 0) {
      count = crypt_determine_count(pass, ckey);
      if (count < 0) {
         return 0;
      }
   }

   len = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), ckey->salt,
                        pass->buf, pass->len, count, ckey->key, ckey->iv);

   if (len != sizeof ckey->key) {
      OPENSSL_cleanse(ckey->key, sizeof ckey->key);
      OPENSSL_cleanse(ckey->iv,  sizeof ckey->iv);
      return 0;
   }

   if (*count_ptr == 0) {
      *count_ptr = count;
   }

   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_encrypt --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_encrypt(struct crypt_key         *ckey,
              const struct secure_area *plaintext,
              uint8                   **cipher,
              size_t                   *cipher_len)
{
   EVP_CIPHER_CTX *ctx;
   int clen;
   int flen;
   uint8 *c;
   int res;

   log_info(LGPFX" %s:%u\n", __func__, __LINE__);

   *cipher = NULL;
   *cipher_len = 0;
   clen = 0;
   flen = 0;
   clen = plaintext->len + AES_BLOCK_SIZE;

   c = safe_malloc(clen);

   ctx = EVP_CIPHER_CTX_new();

   res = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ckey->key, ckey->iv);
   res = res && EVP_EncryptUpdate(ctx, c, &clen, plaintext->buf, plaintext->len);
   res = res && EVP_EncryptFinal_ex(ctx, c + clen, &flen);

   EVP_CIPHER_CTX_free(ctx);

   if (res == 0) {
      log_info(LGPFX" %s: failed to encrypt %zu bytes\n",
          __func__, plaintext->len);
      OPENSSL_cleanse(c, clen);
      free(c);
      return 0;
   }

   *cipher = c;
   *cipher_len = clen + flen;

   return 1;
}


/*
 *---------------------------------------------------------------------
 *
 * crypt_decrypt --
 *
 *---------------------------------------------------------------------
 */

bool
crypt_decrypt(struct crypt_key    *ckey,
              const uint8         *cipher,
              size_t               cipher_len,
              struct secure_area **plaintext)
{
   struct secure_area *sec;
   EVP_CIPHER_CTX *ctx;
   int dlen;
   int flen;
   int res;

   *plaintext = NULL;
   dlen = cipher_len;
   flen = 0;

   sec = secure_alloc(dlen);

   ctx = EVP_CIPHER_CTX_new();

   res = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, ckey->key, ckey->iv);
   res = res && EVP_DecryptUpdate(ctx, sec->buf, &dlen, cipher, cipher_len);
   res = res && EVP_DecryptFinal_ex(ctx, sec->buf + dlen, &flen);

   EVP_CIPHER_CTX_free(ctx);

   if (res == 0) {
      log_info(LGPFX" %s: failed to decrypt %zu bytes\n", __func__, cipher_len);
      secure_free(sec);
      return 0;
   }

   sec->len = dlen + flen;
   *plaintext = sec;

   return 1;
}



/*
 *---------------------------------------------------------------------
 *
 * crypt_hmac_sha256 --
 *
 *---------------------------------------------------------------------
 */

void
crypt_hmac_sha256(const void  *text,
                  size_t       text_len,
                  const uint8 *key,
                  size_t       key_len,
                  uint256     *digest)
{
    uint8 buffer[1024];
    uint256 key_hash;
    uint256 buf_hash;
    uint8 ipad[65];
    uint8 opad[65];
    size_t i;

    ASSERT(text_len < 512);

    uint256_zero_out(&key_hash);

    if (key_len > 64) {
       sha256_calc(key, key_len, &key_hash);
       key_len = sizeof(key_hash);
       key = key_hash.data;
    }
    ASSERT(key_len < sizeof ipad);
    ASSERT(key_len < sizeof opad);

    memset(ipad, 0, sizeof ipad);
    memset(opad, 0, sizeof opad);

    memcpy(ipad, key, key_len);
    memcpy(opad, key, key_len);

    for (i = 0; i < 64; i++ ) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    memcpy(buffer, ipad, 64);
    memcpy(buffer + 64, text, text_len);

    sha256_calc(buffer, 64 + text_len, &buf_hash);

    memcpy(buffer, opad, 64);
    memcpy(buffer + 64, &buf_hash, sizeof buf_hash);

    sha256_calc(buffer, 64 + sizeof buf_hash, digest);
}

#pragma once

#include "basic_defs.h"

#define CRYPT_KEY_LEN            32
#define CRYPT_IV_LEN             32
#define CRYPT_SALT_LEN           8

#define CRYPT_NUM_ITERATIONS_OLD 1337
#define CRYPT_NUM_ITERATIONS_MIN 25000

struct secure_area {
   size_t alloc_len;
   size_t len;
   uint8  buf[];
};

struct secure_area* secure_alloc(size_t len);
void secure_free(struct secure_area *area);

struct crypt_key {
   uint8        key[CRYPT_KEY_LEN];
   uint8        iv[CRYPT_IV_LEN];
   uint8        salt[CRYPT_SALT_LEN];
};


bool
crypt_encrypt(struct crypt_key *ckey,
              const struct secure_area *sec,
              uint8 **cipher, size_t *cipher_len);

bool
crypt_decrypt(struct crypt_key *ckey,
              const uint8 *cipher, size_t cipher_len,
              struct secure_area **plaintext);

bool
crypt_set_key_from_passphrase(const struct secure_area *pass,
                              struct crypt_key *ckey,
                              int64 *count_ptr);

void
crypt_hmac_sha256(const void *text, size_t text_len,
                  const uint8 *key,  size_t key_len,
                  uint256 *digest);


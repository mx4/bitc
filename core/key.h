#pragma once

#include "hash.h"

struct key;

struct key *key_alloc(void);
struct key *key_generate_new(void);
void key_free(struct key *k);

bool key_set_privkey(struct key *k, const void *privkey, size_t len);
bool key_get_privkey(struct key *k, uint8 **privkey, size_t *len);
void key_get_pubkey(struct key *k, uint8 **pubkey, size_t *len);
void key_get_pubkey_hash160(const struct key *k, uint160 *hash);
void key_get_pubkey(struct key *k, uint8 **pub, size_t *len);

bool key_sign(struct key *k, const void *data, size_t len,
              uint8 **sig, size_t *siglen);
bool key_verify(struct key *k, const void *data, size_t datalen,
                const void *sig, size_t siglen);


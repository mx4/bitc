#pragma once

#include "hash.h"

enum key_address {
   PUBKEY_ADDRESS       = 0,
   SCRIPT_ADDRESS       = 5,
   PRIVKEY_ADDRESS      = 128,
   PUBKEY_ADDRESS_TEST  = 111,
   SCRIPT_ADDRESS_TEST  = 196,
   PRIVKEY_ADDRESS_TEST = 239,
};

char *b58_pubkey_from_uint160(const uint160 *digest);
void  b58_pubkey_to_uint160(const char *addr, uint160 *digest);
bool  b58_pubkey_is_valid(const char *addr);
bool  b58_privkey_to_bytes(const char *addr, uint8 **key, size_t *keylen);
char *b58_bytes_to_privkey(const uint8 *key, size_t len);
char *b58_bytes_to_pubkey(const uint8 *key, size_t len);


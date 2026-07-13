#pragma once

#include "hash.h"
#include "bitc-defs.h"
#include "bitc.h"


struct btc_tx_desc;
struct wallet;
struct config;
struct key;
struct secure_area;


struct wallet_pubkey {
   uint8 *pkey;
   size_t pkey_len;
};


void wallet_close(struct wallet *wallet);
int  wallet_open(struct config *cfg, struct secure_area *pass,
                 const char **errStr, struct wallet **wallet);
int  wallet_zap_txdb(struct config *config);
int  wallet_add_key(struct wallet *wallet, const char *desc, char **btc_addr);
bool wallet_has_tx(struct wallet *wlt, const uint256 *txHash);
char *wallet_get_filename(void);
char *wallet_get_change_addr(struct wallet *wallet);
int  wallet_handle_tx(struct wallet *wlt, const uint256 *blkHash,
                      const uint8 *buf, size_t len);

uint64 wallet_get_birth(const struct wallet *wallet);
bool wallet_is_pubkey_hash160_mine(const struct wallet *wallet, const uint160 *pub_key);
bool wallet_is_pubkey_spendable(const struct wallet *wallet, const uint160 *pub_key);
int  wallet_craft_tx(struct wallet *wlt, const struct btc_tx_desc *tx_desc, btc_msg_tx *tx);
struct key * wallet_lookup_pubkey(const struct wallet *wallet, const uint160 *pub_key);
bool wallet_verify(struct secure_area *pass, enum wallet_state *wlt_state);
int wallet_encrypt(struct wallet *wallet, struct secure_area *pass);


/*
 * BIP158: collect the scriptPubKeys to test against compact block filters.
 * For each wallet key, emits the P2PKH script:
 *   OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG  (25 bytes)
 *
 * Cached inside the wallet (rebuilt when a key is added): the returned
 * *scripts / *lens are OWNED BY THE WALLET and remain valid until the next
 * call that rebuilds the cache or wallet_close(). The caller must NOT free
 * them -- this is a change from the previous caller-frees contract, made
 * because this is called once per filter (hundreds/sec during a parallel
 * cfilter scan) and rebuilding+freeing a fresh copy every time was a real
 * CPU cost at that rate.
 */
void wallet_get_filter_scripts(struct wallet *wallet,
                               uint8 ***scripts, size_t **lens,
                               size_t *count);


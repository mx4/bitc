#pragma once

#include "basic_defs.h"
#include "bitc-defs.h"
#include "hash.h"

struct buff;

const char *btcmsg_type_to_str(enum btc_msg_type type);
enum btc_msg_type btcmsg_str_to_type(const char str[12]);

void btcmsg_print_header(const btc_block_header *header);
void btcmsg_print_block(const btc_msg_block *blk);
void btcmsg_print_version(const char *pfx, const btc_msg_version *v);
void btcmsg_print_tx(const btc_msg_tx *tx);
void btcmsg_print_txout(const btc_msg_tx_out *txOut);
void btcmsg_print_txin(const btc_msg_tx_in *txIn);

int btcmsg_craft_version(struct buff **buf);
int btcmsg_craft_verack(struct buff **buf);
int btcmsg_craft_filterload(const btc_msg_filterload *fl, struct buff **buf);
int btcmsg_craft_getaddr(struct buff **buf);
int btcmsg_craft_mempool(struct buff **buf);
int btcmsg_craft_getblocks(const uint256 *hashes, int n, struct buff **bufOut);
int btcmsg_craft_pong(uint32 protversion, uint64 nonce, struct buff **buf);
int btcmsg_craft_ping(uint32 protversion, uint64 nonce, struct buff **buf);
int btcmsg_craft_tx(struct buff *txBuf, struct buff **bufOut);
int btcmsg_craft_addr(uint32 protversion, const struct btc_msg_address *addrs,
                      size_t numAddrs, struct buff **buf);
int btcmsg_craft_getheaders(const uint256 *hashes, int n,
                            const uint256 *genesis,
                            struct buff **buf);
int btcmsg_craft_getdata(struct buff **bufOut, enum btc_inv_type type,
                         const uint256 *hash, int numHash);
int btcmsg_craft_inv(struct buff **bufOut, enum btc_inv_type type,
                     const uint256 *hash, int n);

int btcmsg_parse_notfound(struct buff *buf);
int btcmsg_parse_version(struct buff *buf, btc_msg_version *version);
int btcmsg_parse_alert(struct buff *buf);
int btcmsg_parse_pingpong(uint32 protversion, struct buff *buf, uint64 *nonce);
int btcmsg_parse_inv(struct buff *buf, btc_msg_inv **invOut, int *num);
int btcmsg_parse_headers(struct buff *buf, btc_block_header **h, int *num);
int btcmsg_parse_block(struct buff *buf, btc_msg_block *blk);
int btcmsg_parse_merkleblock(struct buff *buf, btc_msg_merkleblock **blkOut);
int btcmsg_parse_addr(uint32 prot, struct buff *buf,
                      struct btc_msg_address ***addrs, size_t *numAddrs);

bool btcmsg_header_valid(const btc_msg_header *hdr);
bool btcmsg_payload_valid(const struct buff *recvBuf, const uint8 cksum[4]);

struct btc_msg_tx * btc_msg_tx_dup(const struct btc_msg_tx *tx0);
void btc_msg_tx_free(btc_msg_tx *tx);
void btc_msg_tx_init(btc_msg_tx *tx);
uint64 btc_msg_tx_value(const btc_msg_tx *tx);

void btc_msg_block_free(btc_msg_block *blk);
void btc_msg_merkleblock_free(btc_msg_merkleblock *blk);


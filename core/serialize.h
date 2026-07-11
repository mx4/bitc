#pragma once

#include "btc-message.h"

struct buff;


int deserialize_bytes(struct buff *buf, void *val, size_t len);
int deserialize_uint8(struct buff *buf, uint8 *val);
int deserialize_uint16(struct buff *buf, uint16 *val);
int deserialize_uint32(struct buff *buf, uint32 *val);
int deserialize_uint64(struct buff *buf, uint64 *val);
int deserialize_uint256(struct buff *buf, uint256 *val);
int deserialize_varint(struct buff *buf, uint64 *val);
int deserialize_str(struct buff *buf, char *str, size_t len);
int deserialize_str_alloc(struct buff *buf, char **str, size_t *len);

int deserialize_addr(uint32 v, struct buff *buf, btc_msg_address *addr);
int deserialize_inv(struct buff *buf, btc_msg_inv *inv);
int deserialize_version(struct buff *buf, btc_msg_version *v);
int deserialize_blockheader(struct buff *buf, btc_block_header *hdr);
int deserialize_tx(struct buff *buf, btc_msg_tx *tx);
int deserialize_block(struct buff *buf, btc_msg_block *blk);

int serialize_bytes(struct buff *buf, const void *val, size_t len);
int serialize_uint8(struct buff *buf, const uint8 val);
int serialize_uint16(struct buff *buf, const uint16 val);
int serialize_uint32(struct buff *buf, const uint32 val);
int serialize_uint64(struct buff *buf, const uint64 val);
int serialize_uint256(struct buff *buf, const uint256 *val);
int serialize_varint(struct buff *buf, const uint64 val);
int serialize_str(struct buff *buf, const char *str);

int serialize_addr(struct buff *buf, const btc_msg_address *addr);
int serialize_inv(struct buff *buf, const btc_msg_inv *inv);
int serialize_version(struct buff *buf, const btc_msg_version *v);
int serialize_msgheader(struct buff *buf, const btc_msg_header *h);
int serialize_blocklocator(struct buff *buf, const btc_block_locator *bl);
int serialize_tx(struct buff *buf, const btc_msg_tx *tx);



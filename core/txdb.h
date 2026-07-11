#pragma once

#include "hash.h"
#include "bitc-defs.h"

struct txdb;
struct config;
struct btc_tx_desc;

int  txdb_zap(struct config *config);
int  txdb_open(struct config *c, const char **errStr, struct txdb **db);
void txdb_close(struct txdb *db);
bool txdb_has_tx(const struct txdb *txdb, const uint256 *hash);
int  txdb_handle_tx(struct txdb *db, const uint256 *blkHash,
                    const uint8 *buf, size_t len, bool *rel);
int  txdb_craft_tx(struct txdb *txdb, const struct btc_tx_desc *tx,
                   btc_msg_tx *new_tx);

void txdb_export_tx_info(struct txdb *txdb);
uint64 txdb_get_balance(struct txdb *txdb);
void txdb_confirm_one_tx(struct txdb *txdb, const uint256 *blkHash,
                         const uint256 *txHash);


#pragma once

#include "basic_defs.h"
#include "bitc_ui.h"

struct peer_addr;
struct circlist_item;
struct peer;

const char *peer_name(const struct peer *peer);
const char *peer_name_li(struct circlist_item *li);

void peer_add(struct peer_addr *paddr, int seq);
int  peer_check_liveness(struct circlist_item *li, mtime_t now);
void peer_destroy(struct circlist_item *li, int err);
int  peer_getinfo(struct circlist_item *item, struct bitcui_peer *pinfo);
uint64 peer_get_services(struct circlist_item *li);
const uint8 *peer_get_ip(const struct peer *peer);
bool peer_is_connected(struct circlist_item *li);
struct peer *peer_from_li(struct circlist_item *li);
struct circlist_item *peer_get_item(struct peer *peer);
int  peer_on_ready(struct peer *peer);
int  peer_on_ready_li(struct circlist_item *li);

int peer_send_inv(struct circlist_item *item, struct buff *buf);
int peer_send_getheaders(struct peer *peer);
int peer_send_getblocks(struct peer *peer);
int peer_send_mempool(struct peer *peer);
int peer_send_getdata(struct peer *peer, enum btc_inv_type type,
                      const uint256 *hash, int numHash);
int peer_send_getcfilters(struct peer *peer, uint8 filterType,
                          uint32 startHeight, const uint256 *stopHash);
int peer_send_getcfheaders(struct peer *peer, uint8 filterType,
                           uint32 startHeight, const uint256 *stopHash);
int peer_send_getcfcheckpt(struct peer *peer, uint8 filterType,
                           const uint256 *stopHash);


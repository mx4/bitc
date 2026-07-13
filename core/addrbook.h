#pragma once

#include "config.h"
#include "bitc-defs.h"

struct addrbook;

struct peer_addr {
   btc_msg_address addr;
   uint32          connected:1;
   uint32          triedalready:1;
   uint32          unused:30;
};


int addrbook_open(struct config *config, struct addrbook **bookOut);
int addrbook_close(struct addrbook *book);
uint32 addrbook_get_count(const struct addrbook *book);
bool addrbook_add_entry(struct addrbook *book, struct peer_addr *paddr);
void addrbook_zap(struct config *config);
struct peer_addr* addrbook_get_rand_addr(const struct addrbook *book);
struct peer_addr* addrbook_get_by_ip(const struct addrbook *book, const uint8 ip[16]);
void addrbook_remove_entry(struct addrbook *book, const struct peer_addr *paddr);
void addrbook_replace_entry(struct addrbook *book, struct peer_addr *paddr);


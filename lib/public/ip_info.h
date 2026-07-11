#pragma once

#include <netinet/in.h>

/*
 * This is what freegeoip.net returns:
 * {
 *    "ip":"178.194.77.142",
 *    "country_code":"CH",
 *    "country_name":"Switzerland",
 *    "region_code":"23",
 *    "region_name":"Vaud",
 *    "city":"Lausanne",
 *    "zipcode":"1000",
 *    "latitude":46.5417,
 *    "longitude":6.6815,
 *    "metro_code":"",
 *    "areacode":""
 * }
 */

struct ipinfo_entry {
   struct sockaddr_in addr;
   char              *hostname;
   char              *country_name;
   char              *country_code;
   char              *region_name;
   char              *region_code;
   char              *city;
};


void ipinfo_resolve_peer(const struct sockaddr_in *addr);
struct ipinfo_entry *ipinfo_get_entry(const struct sockaddr_in *addr);

void ipinfo_init(void);
void ipinfo_exit(void);



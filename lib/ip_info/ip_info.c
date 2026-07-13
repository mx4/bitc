#include <netdb.h>
#include <netinet/in.h>
#include <curl/curl.h>

#include "netasync.h"
#include "poolworker.h"
#include "cJSON.h"
#include "bitc.h"
#include "hashtable.h"
#include "bitc_ui.h"
#include "buff.h"
#include "ip_info.h"

#define LGPFX "IPINFO:"

static int verbose = 0;

static struct hashtable *hash_ipinfo;


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_free_entry --
 *
 *-----------------------------------------------------------------------
 */

static void
ipinfo_free_entry(const void *key,
                  size_t      keylen,
                  void       *clientData)
{
   struct ipinfo_entry *entry = clientData;

   free(entry->hostname);
   free(entry->country_code);
   free(entry->country_name);
   free(entry->region_name);
   free(entry->region_code);
   free(entry->city);
   free(entry);
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_init --
 *
 *-----------------------------------------------------------------------
 */

void
ipinfo_init(void)
{
   ASSERT(hash_ipinfo == NULL);

   hash_ipinfo = hashtable_create();
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_exit --
 *
 *-----------------------------------------------------------------------
 */

void
ipinfo_exit(void)
{
   hashtable_clear_with_callback(hash_ipinfo, ipinfo_free_entry);
   hashtable_destroy(hash_ipinfo);
   hash_ipinfo = NULL;
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_get_entry --
 *
 *-----------------------------------------------------------------------
 */

struct ipinfo_entry *
ipinfo_get_entry(const struct sockaddr_in *addr)
{
   struct ipinfo_entry *entry;
   bool s;

   ASSERT(mutex_islocked(btcui->lock));

   entry = NULL;
   s = hashtable_lookup(hash_ipinfo, addr, sizeof *addr, (void **)&entry);
   if (s == 0) {
      return NULL;
   }

   ASSERT(entry);
   return entry;
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_resolve_name_cb --
 *
 *-----------------------------------------------------------------------
 */

static void
ipinfo_resolve_name_cb(void *clientData)
{
   struct ipinfo_entry *entry = clientData;
   char host[256];
   uint32 count;
   int res;

   ASSERT(entry);

   if (btc->stop != 0 || btc->state == BITC_STATE_EXITING) {
      return;
   }

   res = getnameinfo((struct sockaddr *)&entry->addr, sizeof(entry->addr),
                     host, sizeof host, NULL, 0, 0 /* flags */);
   if (res != 0) {
      log_info(LGPFX" failed to resolve: %s (%d)\n", gai_strerror(res), res);
      return;
   }

   mutex_lock(btcui->lock);

   entry->hostname = safe_strdup(host);
   count = hashtable_getnumentries(hash_ipinfo);

   mutex_unlock(btcui->lock);

   log_info(LGPFX" host-%u = %s\n", count, host);

   bitcui_req_notify_info_update();
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_curl_write_cb --
 *
 *-----------------------------------------------------------------------
 */

static size_t
ipinfo_curl_write_cb(void *ptr,
                     size_t size,
                     size_t nmemb,
                     void *userp)
{
   size_t len = size * nmemb;
   struct buff *buf = userp;

   LOG(1, (LGPFX" %s got write of %zu bytes\n", __func__, len));
   buff_copy_to(buf, ptr, len);

   return len;
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_json_get --
 *
 *-----------------------------------------------------------------------
 */

static void
ipinfo_json_get(cJSON      *root,
                const char *name,
                char      **entry)
{
   cJSON *item;

   ASSERT(root);
   ASSERT(name);
   ASSERT(entry);

   item = cJSON_GetObjectItem(root, name);
   if (item == NULL) {
      log_info(LGPFX" couldn't retrieve '%s'.\n", name);
      return;
   }

   ASSERT(item->type == cJSON_String);
   *entry = safe_strdup(item->valuestring);
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_resolve_geo_cb --
 *
 *-----------------------------------------------------------------------
 */

static void
ipinfo_resolve_geo_cb(void *clientData)
{
   struct ipinfo_entry *entry = clientData;
   struct buff *buf;
   char url[128];
   char *ipStr;
   CURLcode res;
   CURL *h;
   cJSON *root;

   ASSERT(entry);

   if (btc->stop != 0 || bitc_exiting()) {
      return;
   }

   ipStr = netasync_addr2str(&entry->addr);
   snprintf(url, sizeof url, "https://freegeoip.net/json/%s", ipStr);
   buf = buff_alloc();

   h = curl_easy_init();
   ASSERT(h);
   curl_easy_setopt(h, CURLOPT_URL, url);
   curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, ipinfo_curl_write_cb);
   curl_easy_setopt(h, CURLOPT_WRITEDATA, buf);
   /*
    * We're using https to connect to freegeoip.net, but since the CA
    * certification bundle may not be properly set-up on the host, we skip the
    * verification phase.  It's not quite as secure as it could potentially be,
    * but the security improvement over a straight http connection channel is
    * still significant.
    *
    *   http://curl.haxx.se/docs/sslcerts.html
    */
   curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0);

   if (btc->socks5_proxy) {
      curl_easy_setopt(h, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
      curl_easy_setopt(h, CURLOPT_PROXY,     btc->socks5_proxy);
      curl_easy_setopt(h, CURLOPT_PROXYPORT, btc->socks5_port);
   }

   /*
    * Fix for bug in older versions of libcurl:
    * https://stackoverflow.com/questions/9191668/error-longjmp-causes-uninitialized-stack-frame
    */
   curl_easy_setopt(h, CURLOPT_NOSIGNAL , 1);

   res = curl_easy_perform(h);
   curl_easy_cleanup(h);
   if (res != CURLE_OK) {
      log_info(LGPFX" curl_easy_perform returned %s (%d)\n",
          curl_easy_strerror(res), res);
      goto exit;
   }

   root = cJSON_Parse(buff_base(buf));

   if (root == NULL) {
      log_info(LGPFX" Failed to parse json.\n");
      goto exit;
   }

   ipinfo_json_get(root, "country_code", &entry->country_code);
   ipinfo_json_get(root, "country_name", &entry->country_name);
   ipinfo_json_get(root, "region_name",  &entry->region_name);
   ipinfo_json_get(root, "region_code",  &entry->region_code);
   ipinfo_json_get(root, "city",         &entry->city);
   cJSON_Delete(root);
   log_info(LGPFX" %s: %s, %s, %s, %s, %s\n",
       ipStr, entry->country_code, entry->country_name,
       entry->region_name, entry->city, entry->region_code);
exit:
   buff_free(buf);
   free(ipStr);
}


/*
 *-----------------------------------------------------------------------
 *
 * ipinfo_resolve_peer --
 *
 *-----------------------------------------------------------------------
 */

void
ipinfo_resolve_peer(const struct sockaddr_in *addr)
{
   struct ipinfo_entry *entry;
   bool s;

   ASSERT(mutex_islocked(btcui->lock));

   /*
    * Let's see if we have a name for each of the peers. If not, use
    * a worker thread to resolve it.
    */

   s = hashtable_lookup(hash_ipinfo, addr, sizeof *addr, NULL);
   if (s == 1) {
      return;
   }

   entry = safe_calloc(1, sizeof *entry);
   memcpy(&entry->addr, addr, sizeof *addr);

   hashtable_insert(hash_ipinfo, addr, sizeof *addr, entry);

   /*
    * Resolve: IP -> dns name
    * Resolve: IP -> Country code
    */
   poolworker_queue_work(btc->pw, ipinfo_resolve_name_cb, entry);
   poolworker_queue_work(btc->pw, ipinfo_resolve_geo_cb,  entry);
}



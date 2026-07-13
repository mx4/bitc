#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>
#include <curl/curl.h>

#include "fx.h"
#include "poll.h"
#include "util.h"
#include "buff.h"
#include "bitc_ui.h"
#include "cJSON.h"
#include "config.h"
#include "bitc.h"

#define LGPFX "FX:"

static int verbose;

/*
 * blockchain.info now serves exclusively over HTTPS and 301-redirects any
 * plain HTTP request to https://blockchain.info/ticker. libcurl does not
 * follow redirects unless CURLOPT_FOLLOWLOCATION is set (see fx_do_update),
 * so requesting the http:// URL without that option previously handed the
 * small HTML redirect body to the JSON parser instead of ticker data,
 * silently leaving the FX panel empty (logged only as 'failed to parse
 * JSON', with no indication of the actual cause).
 */
static const char *url = "https://blockchain.info/ticker";

/*
 * Other usable URLs (unverified; mtgox no longer exists):
 *      https://blockchain.info/ticker
 *      http://api.bitcoincharts.com/v1/markets.json
 */

/*
 * inspired from:
 *       http://curl.haxx.se/libcurl/c/multi-single.html
 */

struct fx_state {
   CURL         *http_handle;
   CURLM        *multi_handle;
   struct buff *buf;

   bool         timeCb;
   int          fd_rd;
   int          fd_wr;
};

static struct fx_state fx;

static void fx_api_register_poll(void);


/*
 *---------------------------------------------------------------------------
 *
 * fx_cleanup --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_cleanup(void)
{
   buff_free(fx.buf);
   fx.buf = NULL;

   curl_multi_remove_handle(fx.multi_handle, fx.http_handle);

   curl_easy_cleanup(fx.http_handle);
   fx.http_handle = NULL;

   curl_multi_cleanup(fx.multi_handle);
   fx.multi_handle = NULL;
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_api_parse_json_entry --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_api_parse_json_entry(cJSON           *root,
                        const char      *name,
                        struct bitcui_fx *fx_pair,
                        int             *i)
{
   cJSON *item;
   cJSON *symbol;
   cJSON *last;

   item = cJSON_GetObjectItem(root, name);
   if (item == NULL) {
      log_info(LGPFX" failed to find entry '%s'.\n", name);
      return;
   }
   symbol = cJSON_GetObjectItem(item, "symbol");
   last   = cJSON_GetObjectItem(item, "last");
   if (symbol == NULL || last == NULL) {
      log_info(LGPFX" failed to parse json entry\n");
      return;
   }

   ASSERT(last->type == cJSON_Number);
   ASSERT(symbol->type == cJSON_String);

   fx_pair[*i].name   = safe_strdup(name);
   /*
    * We might need to use wcsdup() here eventually.
    */
   fx_pair[*i].symbol = safe_strdup(symbol->valuestring);
   fx_pair[*i].value  = last->valuedouble;

   if (strcmp(item->string, "USD") == 0 ||
       strcmp(item->string, "EUR") == 0 ||
       strcmp(item->string, "CHF") == 0) {
      LOG(1, (LGPFX" -- %s : %13.7f\n",
          item->string, last->valuedouble));
   }
   (*i)++;
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_api_parse_json --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_api_parse_json(void)
{
   struct bitcui_fx *fx_pairs;
   cJSON *root;
   cJSON *item;
   int n;

   root = cJSON_Parse(buff_base(fx.buf));

   if (root == NULL) {
      /*
       * Log a snippet of the raw response so a future protocol/schema
       * change (redirect, HTML error page, altered API shape, etc.) is
       * diagnosable straight from the log instead of requiring a manual
       * curl/network investigation to even find out what was returned.
       */
      const char *raw = (const char *)buff_base(fx.buf);
      size_t rawLen = buff_curlen(fx.buf);
      size_t snipLen = MIN(rawLen, 200);

      log_warn(LGPFX" failed to parse JSON (%zu bytes received): %.*s%s\n",
              rawLen, (int)snipLen, raw ? raw : "",
              rawLen > snipLen ? "..." : "");
      buff_free(fx.buf);
      fx.buf = NULL;
      return;
   }

   buff_free(fx.buf);
   fx.buf = NULL;

   n = 0;
   for (item = root->child; item != NULL; item = item->next) {
      n++;
   }

   fx_pairs = safe_malloc(n * sizeof *fx_pairs);
   n = 0;

   fx_api_parse_json_entry(root, "USD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "EUR", fx_pairs, &n);
   fx_api_parse_json_entry(root, "CHF", fx_pairs, &n);

   fx_api_parse_json_entry(root, "GBP", fx_pairs, &n);
   fx_api_parse_json_entry(root, "AUD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "CAD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "NZD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "JPY", fx_pairs, &n);
   fx_api_parse_json_entry(root, "CNY", fx_pairs, &n);
   fx_api_parse_json_entry(root, "DKK", fx_pairs, &n);
   fx_api_parse_json_entry(root, "SEK", fx_pairs, &n);
   fx_api_parse_json_entry(root, "RUB", fx_pairs, &n);
   fx_api_parse_json_entry(root, "PLN", fx_pairs, &n);
   fx_api_parse_json_entry(root, "SGD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "HKD", fx_pairs, &n);
   fx_api_parse_json_entry(root, "THB", fx_pairs, &n);
   cJSON_Delete(root);

   /*
    * Now update the UI elements.
    */

   if (btcui->fx_provider == NULL) {
      btcui->fx_provider = safe_strdup("blockchain.info");
   }
   if (btcui->fx_pairs) {
      bitcui_free_fx_pairs(btcui->fx_pairs, btcui->fx_num);
   }
   btcui->fx_pairs = fx_pairs;
   btcui->fx_num = n;

   bitcui_fx_update();
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_api_poll_cb --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_api_poll_cb(void *clientData)
{
   int still_running;
   uintptr_t v = (uintptr_t)clientData;
   CURLMcode err;

   if (v == 0) {
      fx.timeCb = 0;
   } else if (v == 1) {
      fx.fd_rd = -1;
   } else {
      ASSERT(v == 2);
      fx.fd_wr = -1;
   }

   err = curl_multi_perform(fx.multi_handle, &still_running);
   if (err != CURLM_OK) {
      log_info(LGPFX" curl_multi_perform returned %s (%d)\n",
          curl_multi_strerror(err), err);
      return;
   }

   if (still_running) {
      fx_api_register_poll();
      return;
   }

   /*
    * The transfer is done.
    */
   while (TRUE) {
      int msg_left;
      CURLMsg *msg;

      msg = curl_multi_info_read(fx.multi_handle, &msg_left);
      if (msg == NULL) {
         break;
      }
      if (msg->msg == CURLMSG_DONE) {
         ASSERT(msg->easy_handle == fx.http_handle);

         LOG(1, (LGPFX" download complete -- status %s (%d)\n",
             curl_easy_strerror(msg->data.result), msg->data.result));
         if (msg->data.result == CURLE_OK) {
            fx_api_parse_json();
            fx_cleanup();
            return;
         }
      }
   }
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_api_register_poll --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_api_register_poll(void)
{
   fd_set fdread;
   fd_set fdwrite;
   fd_set fdexcep;
   int maxfd = -1;
   CURLMcode err;
   int fd;

   FD_ZERO(&fdread);
   FD_ZERO(&fdwrite);
   FD_ZERO(&fdexcep);

   err = curl_multi_fdset(fx.multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
   if (err != CURLM_OK) {
      log_info(LGPFX" curl_multi_fdset returned %s (%d)\n",
          curl_multi_strerror(err), err);
      return;
   }

   if (maxfd == -1) {
      fx.timeCb = 1;
      poll_callback_time(btcui->poll, 100 * 1000 /* 100 msec */,
                         0 /* not permanent */,
                         fx_api_poll_cb, NULL);
      return;
   }

   for (fd = 0; fd <= maxfd; fd++) {
      bool wr = FD_ISSET(fd, &fdwrite) != 0;
      bool rd = FD_ISSET(fd, &fdread) != 0;

      if (rd == 0 && wr == 0) {
         continue;
      }

      if (rd) {
         ASSERT(fx.fd_rd == -1);
         fx.fd_rd = fd;
      }
      if (wr) {
         ASSERT(fx.fd_wr == -1);
         fx.fd_wr = fd;
      }

      LOG(1, (LGPFX" registering fd=%d rd=%d wr=%d\n", fd, rd, wr));
      poll_callback_device(btcui->poll, fd, rd, wr,
                           0 /* not permanent */,
                           fx_api_poll_cb, (void *)(uintptr_t)(rd ? 1 : 2));
   }
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_api_curl_write_cb --
 *
 *---------------------------------------------------------------------------
 */

static size_t
fx_api_curl_write_cb(void *ptr,
                     size_t size,
                     size_t nmemb,
                     void *userp)
{
   size_t len = size * nmemb;

   LOG(1, (LGPFX" %s got write of %zu bytes\n", __func__, len));
   buff_copy_to(fx.buf, ptr, len);

   return len;
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_do_update --
 *
 *---------------------------------------------------------------------------
 */

static int
fx_do_update(void)
{
   int still_running;
   CURLMcode err;

   fx.buf = buff_alloc();

   fx.http_handle = curl_easy_init();
   ASSERT(fx.http_handle);
   curl_easy_setopt(fx.http_handle, CURLOPT_URL, url);
   curl_easy_setopt(fx.http_handle, CURLOPT_WRITEFUNCTION, fx_api_curl_write_cb);
   curl_easy_setopt(fx.http_handle, CURLOPT_WRITEDATA, NULL);
   /*
    * Defensive: follow redirects (bounded) so a future http->https-style
    * migration doesn't silently hand an HTML redirect body to the JSON
    * parser again instead of failing loudly or just working.
    */
   curl_easy_setopt(fx.http_handle, CURLOPT_FOLLOWLOCATION, 1L);
   curl_easy_setopt(fx.http_handle, CURLOPT_MAXREDIRS, 5L);

   fx.multi_handle = curl_multi_init();
   curl_multi_add_handle(fx.multi_handle, fx.http_handle);
   err = curl_multi_perform(fx.multi_handle, &still_running);
   if (err != CURLM_OK) {
      log_info(LGPFX" curl_multi_fdset returned %s (%d)\n",
          curl_multi_strerror(err), err);
      return 1;
   }

   fx_api_register_poll();

   return 0;
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_periodic_cb --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_periodic_cb(void *clientData)
{
   fx_do_update();
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_init --
 *
 *---------------------------------------------------------------------------
 */

void
fx_init(void)
{
   fx.fd_rd = -1;
   fx.fd_wr = -1;

   log_info(LGPFX" using %s\n", curl_version());

   /*
    * Update every 5min by default.
    */
   btcui->fxPeriodMin = config_getint64(btc->config, 5, "fx.periodMin");
   ASSERT(btcui->fxPeriodMin > 0);

   poll_callback_time(btcui->poll, btcui->fxPeriodMin * 60 * 1000 * 1000,
                      1 /* permanent */, fx_periodic_cb, NULL);

   fx_do_update();
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_check_unregister_cbs --
 *
 *---------------------------------------------------------------------------
 */

static void
fx_check_unregister_cbs(void)
{
   bool s;

   if (fx.timeCb) {
      s = poll_callback_time_remove(btcui->poll, 0, fx_api_poll_cb, NULL);
      ASSERT(s);
   }
   if (fx.fd_rd != -1) {
      s = poll_callback_device_remove(btcui->poll, fx.fd_rd, 1, 0, 0,
                                      fx_api_poll_cb, (void*)(uintptr_t)1);
      ASSERT(s);
   }
   if (fx.fd_wr != -1) {
      s = poll_callback_device_remove(btcui->poll, fx.fd_wr, 0, 1, 0,
                                      fx_api_poll_cb, (void*)(uintptr_t)2);
      ASSERT(s);
   }
}


/*
 *---------------------------------------------------------------------------
 *
 * fx_exit --
 *
 *---------------------------------------------------------------------------
 */

void
fx_exit(void)
{
   poll_callback_time_remove(btcui->poll, 1, fx_periodic_cb, NULL);
   fx_check_unregister_cbs();
   fx_cleanup();
}


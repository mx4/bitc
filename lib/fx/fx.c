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

static const char *url = "https://blockchain.info/ticker";

struct fx_state {
   CURL         *http_handle;
   CURLM        *multi_handle;
   struct buff  *buf;
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
   if (fx.buf) {
      buff_free(fx.buf);
      fx.buf = NULL;
   }
   if (fx.http_handle) {
      curl_multi_remove_handle(fx.multi_handle, fx.http_handle);
      curl_easy_cleanup(fx.http_handle);
      fx.http_handle = NULL;
   }
   if (fx.multi_handle) {
      curl_multi_cleanup(fx.multi_handle);
      fx.multi_handle = NULL;
   }
   fx.fd_rd = -1;
   fx.fd_wr = -1;
   fx.timeCb = 0;
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
   cJSON *item = cJSON_GetObjectItem(root, name);
   if (item == NULL) {
      Log(LGPFX" failed to find entry '%s'.\n", name);
      return;
   }
   cJSON *symbol = cJSON_GetObjectItem(item, "symbol");
   cJSON *last = cJSON_GetObjectItem(item, "last");
   if (symbol == NULL || last == NULL) {
      Log(LGPFX" failed to parse json entry for %s\n", name);
      return;
   }
   if (last->type != cJSON_Number || symbol->type != cJSON_String) {
      Log(LGPFX" invalid types for %s: last=%d, symbol=%d\n",
          name, last->type, symbol->type);
      return;
   }

   fx_pair[*i].name = safe_strdup(name);
   fx_pair[*i].symbol = safe_strdup(symbol->valuestring);
   fx_pair[*i].value = last->valuedouble;

   LOG(1, (LGPFX" -- %s : %13.7f %s\n", name, fx_pair[*i].value, fx_pair[*i].symbol));
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
      Log(LGPFX" failed to parse JSON: %s\n", (char *)buff_base(fx.buf));
      buff_free(fx.buf);
      fx.buf = NULL;
      btcui->fx_pairs = NULL;
      btcui->fx_num = 0;
      bitcui_fx_update();
      return;
   }

   n = 0;
   for (item = root->child; item != NULL; item = item->next) {
      n++;
   }
   if (n == 0) {
      Log(LGPFX" no currency pairs found in JSON\n");
      cJSON_Delete(root);
      buff_free(fx.buf);
      fx.buf = NULL;
      btcui->fx_pairs = NULL;
      btcui->fx_num = 0;
      bitcui_fx_update();
      return;
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
   buff_free(fx.buf);
   fx.buf = NULL;

   if (n == 0) {
      Log(LGPFX" no valid currency pairs parsed\n");
      free(fx_pairs);
      fx_pairs = NULL;
   }

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

   LOG(1, (LGPFX" poll_cb: clientData=%lu, fd_rd=%d, fd_wr=%d\n",
           v, fx.fd_rd, fx.fd_wr));

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
      Log(LGPFX" curl_multi_perform returned %s (%d)\n",
          curl_multi_strerror(err), err);
      fx_cleanup();
      return;
   }

   if (still_running) {
      fx_api_register_poll();
      return;
   }

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
         } else {
            Log(LGPFX" curl error: %s\n", curl_easy_strerror(msg->data.result));
            btcui->fx_pairs = NULL;
            btcui->fx_num = 0;
            bitcui_fx_update();
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
   fd_set fdread, fdwrite, fdexcep;
   int maxfd = -1;
   CURLMcode err;
   int fd;

   FD_ZERO(&fdread);
   FD_ZERO(&fdwrite);
   FD_ZERO(&fdexcep);

   err = curl_multi_fdset(fx.multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
   if (err != CURLM_OK) {
      Log(LGPFX" curl_multi_fdset returned %s (%d)\n",
          curl_multi_strerror(err), err);
      fx_cleanup();
      return;
   }

   if (fx.fd_rd != -1) {
      Log(LGPFX" removing fd_rd=%d\n", fx.fd_rd);
      poll_callback_device_remove(btcui->poll, fx.fd_rd, 1, 0, 0,
                                 fx_api_poll_cb, (void*)(uintptr_t)1);
      fx.fd_rd = -1;
   }
   if (fx.fd_wr != -1) {
      Log(LGPFX" removing fd_wr=%d\n", fx.fd_wr);
      poll_callback_device_remove(btcui->poll, fx.fd_wr, 0, 1, 0,
                                 fx_api_poll_cb, (void*)(uintptr_t)2);
      fx.fd_wr = -1;
   }

   if (maxfd == -1) {
      fx.timeCb = 1;
      poll_callback_time(btcui->poll, 100 * 1000, 0, fx_api_poll_cb, NULL);
      return;
   }

   for (fd = 0; fd <= maxfd; fd++) {
      bool wr = FD_ISSET(fd, &fdwrite) != 0;
      bool rd = FD_ISSET(fd, &fdread) != 0;

      if (rd == 0 && wr == 0) {
         continue;
      }

      if (rd) {
         fx.fd_rd = fd;
      }
      if (wr) {
         fx.fd_wr = fd;
      }

      LOG(1, (LGPFX" registering fd=%d rd=%d wr=%d\n", fd, rd, wr));
      poll_callback_device(btcui->poll, fd, rd, wr, 0, fx_api_poll_cb,
                           (void *)(uintptr_t)(rd ? 1 : 2));
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

   LOG(1, (LGPFX" %s got write of %zu bytes\n", __FUNCTION__, len));
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

   if (fx.http_handle || fx.multi_handle) {
      Log(LGPFX" previous API call still in progress, skipping\n");
      return 0;
   }

   fx.buf = buff_alloc();
   if (!fx.buf) {
      Log(LGPFX" buff_alloc failed\n");
      return 1;
   }

   fx.http_handle = curl_easy_init();
   if (!fx.http_handle) {
      Log(LGPFX" curl_easy_init failed\n");
      buff_free(fx.buf);
      fx.buf = NULL;
      return 1;
   }

   curl_easy_setopt(fx.http_handle, CURLOPT_URL, url);
   curl_easy_setopt(fx.http_handle, CURLOPT_WRITEFUNCTION, fx_api_curl_write_cb);
   curl_easy_setopt(fx.http_handle, CURLOPT_WRITEDATA, NULL);

   fx.multi_handle = curl_multi_init();
   if (!fx.multi_handle) {
      Log(LGPFX" curl_multi_init failed\n");
      curl_easy_cleanup(fx.http_handle);
      fx.http_handle = NULL;
      buff_free(fx.buf);
      fx.buf = NULL;
      return 1;
   }

   curl_multi_add_handle(fx.multi_handle, fx.http_handle);
   err = curl_multi_perform(fx.multi_handle, &still_running);
   if (err != CURLM_OK) {
      Log(LGPFX" curl_multi_perform returned %s (%d)\n",
          curl_multi_strerror(err), err);
      fx_cleanup();
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
   fx.timeCb = 0;

   Log(LGPFX" using %s\n", curl_version());

   btcui->fxPeriodMin = config_getint64(btc->config, 5, "fx.periodMin");
   ASSERT(btcui->fxPeriodMin > 0);

   poll_callback_time(btcui->poll, btcui->fxPeriodMin * 60 * 1000 * 1000,
                      1, fx_periodic_cb, NULL);

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
      Log(LGPFX" removing time callback\n");
      s = poll_callback_time_remove(btcui->poll, 0, fx_api_poll_cb, NULL);
      ASSERT(s);
   }
   if (fx.fd_rd != -1) {
      Log(LGPFX" removing fd_rd=%d\n", fx.fd_rd);
      s = poll_callback_device_remove(btcui->poll, fx.fd_rd, 1, 0, 0,
                                      fx_api_poll_cb, (void*)(uintptr_t)1);
      ASSERT(s);
   }
   if (fx.fd_wr != -1) {
      Log(LGPFX" removing fd_wr=%d\n", fx.fd_wr);
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

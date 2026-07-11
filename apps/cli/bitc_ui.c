//#include <netdb.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "bitc_ui.h"
#include "util.h"
#include "hash.h"
#include "ncui.h"
#include "poll.h"
#include "bitc.h"
#include "wallet.h"
#include "fx.h"
#include "poolworker.h"
#include "ip_info.h"

#define LGPFX "BTCUI:"

static int verbose = 0;

static struct btcui ui;

struct btcui *btcui = &ui;

enum bitcui_req_type {
   BTCUI_REQ_STATUS_UPDATE = 0,
   BTCUI_REQ_INFO_UPDATE   = 1,
   BTCUI_REQ_WALLET_UPDATE = 2,
   BTCUI_REQ_TX_UPDATE     = 3,
   BTCUI_REQ_LOG           = 4,
   BTCUI_REQ_EXIT          = 5,
   BTCUI_REQ_MAX           = 6,
};

static uint32 reqCount[BTCUI_REQ_MAX];

struct bitcui_req {
   struct circlist_item  item;
   enum bitcui_req_type  type;
   uint8                 data[];
};

struct bitcui_log_req {
   char       *ts;
   char       *str;
};


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_free_fx_pairs --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_free_fx_pairs(struct bitcui_fx *fx_pairs,
                     int fx_num)
{
   int i;

   for (i = 0; i < fx_num; i++) {
      free(fx_pairs[i].name);
      free(fx_pairs[i].symbol);
   }
   free(fx_pairs);
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_free_tx_info --
 *
 *-----------------------------------------------------------------------
 */

static void
bitcui_free_tx_info(struct bitcui_tx *tx_info,
                    int tx_num)
{
   int i;

   for (i = 0; i < tx_num; i++) {
      free(tx_info[i].src);
      free(tx_info[i].dst);
      free(tx_info[i].desc);
   }
   free(tx_info);
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_free_addrs_info --
 *
 *-----------------------------------------------------------------------
 */

static void
bitcui_free_addrs_info(struct bitcui_addr *addr_info,
                       int addr_num)
{
   int i;

   for (i = 0; i < addr_num; i++) {
      free(addr_info[i].addr);
      free(addr_info[i].desc);
   }
   free(addr_info);
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_free_peers_info --
 *
 *-----------------------------------------------------------------------
 */

static void
bitcui_free_peers_info(struct bitcui_peer *peer_info,
                       int peer_num)
{
   int i;

   for (i = 0; i < peer_num; i++) {
      free(peer_info[i].id);
      free(peer_info[i].host);
      free(peer_info[i].hostname);
      free(peer_info[i].versionStr);
   }
   free(peer_info);
}



/*
 *---------------------------------------------------
 *
 * bitcui_req_notify --
 *
 *---------------------------------------------------
 */

static void
bitcui_req_notify(void)
{
   uint8 val = 1;
   ssize_t res;

   res = write(btcui->notifyFd, &val, sizeof val);
   ASSERT(res == 1);
}


/*
 *---------------------------------------------------
 *
 * bitcui_req_enqueue --
 *
 *---------------------------------------------------
 */

static void
bitcui_req_enqueue(struct bitcui_req *msg)
{
   ASSERT(msg);
   ASSERT(btcui->lock);

   mutex_lock(btcui->lock);
   circlist_queue_item(&btcui->reqList, &msg->item);
   mutex_unlock(btcui->lock);

   bitcui_req_notify();
}


/*
 *---------------------------------------------------
 *
 * bitcui_req_alloc --
 *
 *---------------------------------------------------
 */

static struct bitcui_req *
bitcui_req_alloc(enum bitcui_req_type type,
                 size_t sz)
{
   struct bitcui_req *msg;

   msg = safe_malloc(sizeof *msg + sz);
   circlist_init_item(&msg->item);
   msg->type = type;

   return msg;
}


/*
 *---------------------------------------------------
 *
 * bitcui_req_notify_log_update --
 *
 *---------------------------------------------------
 */

static void
bitcui_req_notify_log_update(const char *ts,
                             const char *str)
{
   struct bitcui_log_req *logData;
   struct bitcui_req *msg;

   msg = bitcui_req_alloc(BTCUI_REQ_LOG, sizeof(struct bitcui_log_req));

   logData = (struct bitcui_log_req *)msg->data;
   logData->ts  = safe_strdup(ts);
   logData->str = safe_strdup(str);

   bitcui_req_enqueue(msg);
}


/*
 *---------------------------------------------------
 *
 * bitcui_req_notify_tx_update --
 *
 *---------------------------------------------------
 */

static void
bitcui_req_notify_tx_update(void)
{
   struct bitcui_req *msg;

   msg = bitcui_req_alloc(BTCUI_REQ_TX_UPDATE, 0);
   bitcui_req_enqueue(msg);
}


/*
 *---------------------------------------------------
 *
 * bitcui_req_notify_wallet_update --
 *
 *---------------------------------------------------
 */

static void
bitcui_req_notify_wallet_update(void)
{
   struct bitcui_req *msg;

   msg = bitcui_req_alloc(BTCUI_REQ_WALLET_UPDATE, 0);
   bitcui_req_enqueue(msg);
}

/*
 *---------------------------------------------------
 *
 * bitcui_req_notify_info_update --
 *
 *---------------------------------------------------
 */

void
bitcui_req_notify_info_update(void)
{
   struct bitcui_req *msg;

   msg = bitcui_req_alloc(BTCUI_REQ_INFO_UPDATE, 0);
   bitcui_req_enqueue(msg);
}


/*
 *---------------------------------------------------------------------
 *
 * bitcui_req_exit --
 *
 *---------------------------------------------------------------------
 */

static void
bitcui_req_exit(void)
{
   struct bitcui_req *msg;

   if (btcui->inuse == 0) {
      return;
   }

   msg = bitcui_req_alloc(BTCUI_REQ_EXIT, 0);
   bitcui_req_enqueue(msg);
}


/*
 *---------------------------------------------------------------------
 *
 * bitcui_notify_cb --
 *
 *---------------------------------------------------------------------
 */

static void
bitcui_notify_cb(void *clientData)
{
   ssize_t res;

   do {
      uint8 val;

      res = read(btcui->eventFd, &val, sizeof val);
   } while (res > 0);

   ASSERT(res == 0 || errno == EAGAIN);

   mutex_lock(btcui->lock);

   while (!circlist_empty(btcui->reqList)) {
      struct circlist_item *li = btcui->reqList;
      struct bitcui_req *msg;

      circlist_delete_item(&btcui->reqList, li);
      msg = CIRCLIST_CONTAINER(li, struct bitcui_req, item);

      switch (msg->type) {
      case BTCUI_REQ_EXIT:
         LOG(1, (LGPFX" handling REQ_EXIT\n"));
         btcui->stop = 1;
         break;
      case BTCUI_REQ_WALLET_UPDATE:
         LOG(1, (LGPFX" handling REQ_WALLET_UPDATE\n"));
         ncui_wallet_update();
         break;
      case BTCUI_REQ_STATUS_UPDATE:
         LOG(1, (LGPFX" handling REQ_STATUS_UPDATE\n"));
         ncui_status_update(1);
         break;
      case BTCUI_REQ_INFO_UPDATE:
         LOG(1, (LGPFX" handling REQ_INFO_UPDATE\n"));
         ncui_info_update();
         ncui_peers_update();
         break;
      case BTCUI_REQ_TX_UPDATE:
         LOG(1, (LGPFX" handling REQ_TX_UPDATE\n"));
         ncui_tx_update();
         break;
      case BTCUI_REQ_LOG: {
         struct bitcui_log_req *req = (struct bitcui_log_req*)msg->data;
         ncui_log_cb(req->ts, req->str, NULL);
         free(req->ts);
         free(req->str);
      }  break;
      default:
         Panic(LGPFX" unhandled btcui msg %d\n", msg->type);
         break;
      }

      reqCount[msg->type]++;
      free(msg);
   }
   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------
 *
 * bitcui_notify_init --
 *
 *---------------------------------------------------
 */

static int
bitcui_notify_init(int *readFd,
                   int *writeFd)
{
   int fd[2];
   int flags;
   int res;

   res = pipe(fd);
   if (res != 0) {
      res = errno;
      log_info(LGPFX" Failed to create pipe: %s\n", strerror(res));
      return res;
   }
   *readFd = fd[0];
   *writeFd = fd[1];

   flags = fcntl(*readFd, F_GETFL, 0);
   if (flags < 0) {
      NOT_TESTED();
      return flags;
   }

   res = fcntl(*readFd, F_SETFL, flags | O_NONBLOCK);
   if (res < 0) {
      NOT_TESTED();
      return res;
   }
   poll_callback_device(btcui->poll, btcui->eventFd, 1, 0, 1,
                        bitcui_notify_cb, NULL);
   btcui->notifyInit = 1;

   return 0;
}


/*
 *---------------------------------------------------
 *
 * bitcui_notify_exit --
 *
 *---------------------------------------------------
 */

static void
bitcui_notify_exit(void)
{
   bool s;

   bitcui_notify_cb(NULL);

   log_info(LGPFX" REQ_STATUS_UPDATE: %u\n", reqCount[BTCUI_REQ_STATUS_UPDATE]);
   log_info(LGPFX"   REQ_INFO_UPDATE: %u\n", reqCount[BTCUI_REQ_INFO_UPDATE]);
   log_info(LGPFX" REQ_WALLET_UPDATE: %u\n", reqCount[BTCUI_REQ_WALLET_UPDATE]);
   log_info(LGPFX"     REQ_TX_UPDATE: %u\n", reqCount[BTCUI_REQ_TX_UPDATE]);
   log_info(LGPFX"          REQ_EXIT: %u\n", reqCount[BTCUI_REQ_EXIT]);

   ASSERT(btcui->notifyInit);

   s = poll_callback_device_remove(btcui->poll, btcui->eventFd, 1, 0, 1,
                                   bitcui_notify_cb, NULL);
   ASSERT(s);
}


/*
 *---------------------------------------------------
 *
 * bitcui_fx_update --
 *
 *---------------------------------------------------
 */

void
bitcui_fx_update(void)
{
   mutex_lock(btcui->lock);
   ncui_fx_update();
   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------
 *
 * bitcui_log_cb --
 *
 *---------------------------------------------------
 */

static void
bitcui_log_cb(const char *ts,
              const char *str,
              void       *clientData)
{

   if (btc->stop != 0 || bitc_exiting()) {
      return;
   }

   bitcui_req_notify_log_update(ts, str);
}


/*
 *---------------------------------------------------
 *
 * bitcui_log_exit --
 *
 *---------------------------------------------------
 */

static void
bitcui_log_exit(void)
{
   log_set_cb(NULL, NULL);
}



/*
 *---------------------------------------------------
 *
 * bitcui_log_init --
 *
 *---------------------------------------------------
 */

static void
bitcui_log_init(void)
{
   log_set_cb(bitcui_log_cb, NULL);
}


/*
 *---------------------------------------------------
 *
 * bitcui_init --
 *
 *---------------------------------------------------
 */

static int
bitcui_init(void)
{
   int res;

   btcui->poll = poll_create();

   res = bitcui_notify_init(&btcui->eventFd, &btcui->notifyFd);
   ASSERT(res == 0);

   bitcui_set_status("ui starting..");

   fx_init();
   ncui_init();
   bitcui_log_init();

   poll_callback_device(btcui->poll, STDIN_FILENO, 1, 0, 1, ncui_input_cb, NULL);
   poll_callback_time(btcui->poll, 1 * 1000 * 1000 / 2, TRUE, ncui_time_cb, NULL);

   return 0;
}


/*
 *---------------------------------------------------
 *
 * bitcui_poll_shutdown --
 *
 *---------------------------------------------------
 */

static void
bitcui_poll_shutdown(void)
{
   bool s;

   s = poll_callback_device_remove(btcui->poll, STDIN_FILENO, 1, 0, 1,
                                   ncui_input_cb, NULL);
   ASSERT(s);
   s = poll_callback_time_remove(btcui->poll, 1, ncui_time_cb, NULL);
   ASSERT(s);

   poll_destroy(btcui->poll);
   btcui->poll = NULL;
}


/*
 *---------------------------------------------------
 *
 * bitcui_exit --
 *
 *---------------------------------------------------
 */

static void
bitcui_exit(void)
{
   log_info(LGPFX" %s\n", __FUNCTION__);

   fx_exit();
   poolworker_wait(btc->pw);
   bitcui_log_exit();
   bitcui_notify_exit();
   ncui_exit();
   bitcui_free_addrs_info(ui.addr_info, ui.addr_num);
   bitcui_free_peers_info(ui.peer_info, ui.peer_num);
   bitcui_free_tx_info(ui.tx_info, ui.tx_num);
   bitcui_free_fx_pairs(ui.fx_pairs, ui.fx_num);
   free(ui.fx_provider);
   free(ui.statusStr);
   bitcui_poll_shutdown();
}


/*
 *---------------------------------------------------------------------
 *
 * bitcui_stop --
 *
 *---------------------------------------------------------------------
 */

void
bitcui_stop(void)
{
   bitcui_set_status("Exiting..");
   bitcui_req_exit();

   if (btcui->inuse == 1) {
      int res;
      log_info(LGPFX" stopping ui thread.\n");
      res = pthread_join(btcui->tid, NULL);
      ASSERT(res == 0);
      log_info(LGPFX" ui thread stopped: %d\n", res);
   }

   ASSERT(btcui->lock);
   mutex_free(btcui->lock);
   btcui->lock = NULL;

   ASSERT(btcui->cv);
   condvar_free(btcui->cv);
   memset(btcui, 0, sizeof *btcui);
}


/*
 *---------------------------------------------------------------------
 *
 * bitcui_main --
 *
 *---------------------------------------------------------------------
 */

static void *
bitcui_main(void *clientData)
{
   sigset_t set;

   sigemptyset(&set);
   sigaddset(&set, SIGQUIT);
   sigaddset(&set, SIGINT);
   pthread_sigmask(SIG_BLOCK, &set, NULL);

   log_info(LGPFX" btcui starting.\n");

   bitcui_init();
   condvar_signal(btcui->cv);

   poll_runloop(btcui->poll, &btcui->stop);

   bitcui_exit();
   log_info(LGPFX" btcui done.\n");
   pthread_exit(NULL);

   return NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * bitcui_start --
 *
 *---------------------------------------------------------------------
 */

int
bitcui_start(bool withui)
{
   int res;

   btcui->inuse = withui;
   btcui->lock  = mutex_alloc();
   btcui->cv    = condvar_alloc();
   btcui->blockProdIdx = -1;
   btcui->blockConsIdx = -1;

   if (btcui->inuse == 0) {
      return 0;
   }

   log_info(LGPFX" starting ui thread.\n");

   res = pthread_create(&btcui->tid, NULL, bitcui_main, NULL);
   ASSERT(res == 0);

   mutex_lock(btcui->lock);
   condvar_wait(btcui->cv, btcui->lock);
   mutex_unlock(btcui->lock);

   return res;
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_last_block --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_last_block_info(const uint256 *hash,
                           int            height,
                           uint32         timestamp)
{
   if (ui.inuse == 0) {
      return;
   }

   if (btcui->numBlocks > 0 &&
       uint256_issame(hash, &btcui->blocks[btcui->blockProdIdx].hash)) {
      return;
   }

   mutex_lock(btcui->lock);

   if (btcui->numBlocks < ARRAYSIZE(btcui->blocks)) {
      btcui->numBlocks++;
   }

   btcui->blockProdIdx = (btcui->blockProdIdx + 1) % ARRAYSIZE(btcui->blocks);
   btcui->blocks[btcui->blockProdIdx].hash      = *hash;
   btcui->blocks[btcui->blockProdIdx].height    = height;
   btcui->blocks[btcui->blockProdIdx].timestamp = timestamp;
   btcui->height = height;

   mutex_unlock(btcui->lock);

   bitcui_req_notify_info_update();
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_tx_info --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_tx_info(int tx_num,
                   struct bitcui_tx *tx_info)
{
   if (ui.inuse == 0) {
      return;
   }
   mutex_lock(btcui->lock);

   bitcui_free_tx_info(ui.tx_info, ui.tx_num);

   ui.tx_info = tx_info;
   ui.tx_num  = tx_num;

   mutex_unlock(btcui->lock);

   bitcui_req_notify_tx_update();
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_async_resolve_peers --
 *
 *-----------------------------------------------------------------------
 */

static void
bitcui_async_resolve_peers(void)
{
   int i;

   mutex_lock(btcui->lock);

   for (i = 0; i < ui.peer_num; i++) {
      ipinfo_resolve_peer(&ui.peer_info[i].saddr);
   }

   mutex_unlock(btcui->lock);
}

/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_peer_info --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_peer_info(int peers_active,
                     int peers_alive,
                     int num_addrs,
                     struct bitcui_peer *peer_info)
{
   if (ui.inuse == 0) {
      bitcui_free_peers_info(peer_info, peers_alive);
      return;
   }
   mutex_lock(btcui->lock);

   bitcui_free_peers_info(ui.peer_info, ui.peer_num);

   ui.num_peers_active = peers_active;
   ui.num_peers_alive  = peers_alive;
   ui.num_addrs        = num_addrs;

   ui.peer_info = peer_info;
   ui.peer_num  = peers_alive;

   mutex_unlock(btcui->lock);

   if (btc->resolve_peers) {
      bitcui_async_resolve_peers();
   }

   bitcui_req_notify_info_update();
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_addrs_info --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_addrs_info(int num,
                      struct bitcui_addr *addr)
{
   if (btcui->inuse == 0) {
      return;
   }

   mutex_lock(btcui->lock);

   bitcui_free_addrs_info(ui.addr_info, ui.addr_num);

   ui.addr_info = addr;
   ui.addr_num  = num;

   mutex_unlock(btcui->lock);

   bitcui_req_notify_wallet_update();
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_status --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_status(const char *fmt, ...)
{
   va_list args;
   struct bitcui_req *msg;
   char str[1024];

   if (btcui->inuse == 0) {
      return;
   }

   mutex_lock(btcui->lock);

   free(ui.statusStr);
   ui.statusStr = NULL;

   va_start(args, fmt);
   vsnprintf(str, sizeof str, fmt, args);
   va_end(args);

   ui.statusStr = safe_strdup(str);
   ui.statusExpiry = time(NULL) + 90; // 90 se

   mutex_unlock(btcui->lock);

   log_info(LGPFX" setting UI status to '%s'.\n", str);

   msg = bitcui_req_alloc(BTCUI_REQ_STATUS_UPDATE, 0);
   bitcui_req_enqueue(msg);
}


/*
 *-----------------------------------------------------------------------
 *
 * bitcui_set_catchup_info --
 *
 *-----------------------------------------------------------------------
 */

void
bitcui_set_catchup_info(int numhdr,
                        int hdrtot,
                        int blk,
                        int blktot)
{
   if (btcui->inuse == 0) {
      return;
   }
   mutex_lock(btcui->lock);

   ui.numhdr = numhdr;
   ui.hdrtot = hdrtot;
   ui.blk    = blk;
   ui.blktot = blktot;
   ui.updating = (numhdr < hdrtot) && (blk < blktot);

   mutex_unlock(btcui->lock);

   bitcui_req_notify_info_update();
}

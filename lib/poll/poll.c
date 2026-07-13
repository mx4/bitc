#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "basic_defs.h"
#include "util.h"
#include "circlist.h"
#include "hashtable.h"
#include "poll.h"

#define LGPFX   "POLL:"

static int verbose = 0;

struct poll_entry {
   struct circlist_item item;
   pollcallback_fun    *callback;
   void                *callbackData;
   bool                 permanent;
   bool                 queued;
   int                  refCount;
   enum poll_type       type;
   union {
      struct {
         int            fd;
         int            idx;
         bool           readable;
         bool           writeable;
      };
      struct {
         mtime_t        expiry;
         mtime_t        delay;
      };
   };
};

#define GET_ENTRY(_li) \
      CIRCLIST_CONTAINER((_li), struct poll_entry, item);

struct poll_loop {
   struct circlist_item   *list_time;
   struct circlist_item   *list_device;
   struct circlist_item   *list_free;

   struct hashtable       *hash;

   fd_set                  fds_rd;
   fd_set                  fds_wr;

   size_t                  poll_max_fds;
   struct pollfd          *poll_fds;

   bool                    use_poll;
};


/*
 *-------------------------------------------------------------------------
 *
 * poll_check_time_queue_order --
 *
 *      This assumes that only a single function will register for
 *      notifications on an fd.
 *
 *-------------------------------------------------------------------------
 */

static void
poll_check_time_queue_order(const struct poll_loop *poll)
{
   struct circlist_item *li;
   mtime_t last = 0;

   ASSERT(poll);

   CIRCLIST_SCAN(li, poll->list_time) {
      struct poll_entry *e = GET_ENTRY(li);
      ASSERT(last <= e->expiry);
      last = e->expiry;
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_get_device_key --
 *
 *      This assumes that only a single function will register for
 *      notifications on an fd.
 *
 *-------------------------------------------------------------------------
 */

static uint64
poll_get_device_key(int fd,
                    bool read,
                    bool write,
                    bool permanent)
{
   uint32 lo = ((int)read << 8) + ((int)write << 4) + permanent;

   return QWORD(fd, lo);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_get_device_key_from_entry --
 *
 *-------------------------------------------------------------------------
 */

static uint64
poll_get_device_key_from_entry(const struct poll_entry *e)
{
   ASSERT(e->type == POLL_CB_DEVICE);

   return poll_get_device_key(e->fd, e->readable, e->writeable,
                              e->permanent);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_dequeue --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_dequeue(struct circlist_item **list,
		   const struct poll_entry *e)
{
   circlist_delete_item(list, &e->item);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_get --
 *
 *-------------------------------------------------------------------------
 */

static struct poll_entry *
poll_entry_get(struct poll_loop *poll)
{
   struct circlist_item *li = poll->list_free;

   if (circlist_empty(li)) {
      return safe_malloc(sizeof(struct poll_entry));
   } else {
      circlist_delete_item(&poll->list_free, li);
      return GET_ENTRY(li);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_put --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_put(struct poll_loop *poll,
               struct poll_entry *e)
{
   ASSERT(poll);
   ASSERT(e);

   e->type = POLL_CB_NONE;
   circlist_queue_item(&poll->list_free, &e->item);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_ref --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_ref(struct poll_entry *e)
{
   ASSERT(e->refCount >= 0);
   e->refCount++;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_unref --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_unref(struct poll_loop *poll,
                 struct poll_entry **in)
{
   struct poll_entry *e = *in;

   ASSERT(e);
   ASSERT(e->refCount > 0);

   e->refCount--;
   if (e->refCount > 0) {
      return;
   }
   poll_entry_put(poll, e);
   *in = NULL;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_remove_from_hashtable --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_remove_from_hashtable(struct poll_loop *poll,
                                 const struct poll_entry *e)
{
   uint64 key;
   bool s;

   ASSERT(e->type == POLL_CB_DEVICE);
   key = poll_get_device_key_from_entry(e);

   s = hashtable_remove(poll->hash, &key, sizeof key);
   ASSERT(s);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_free --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_free(struct poll_loop *poll,
                struct poll_entry *e)
{
   if (e->type == POLL_CB_DEVICE) {
      uint64 key = poll_get_device_key_from_entry(e);
      bool s;

      s = hashtable_remove(poll->hash, &key, sizeof key);
      ASSERT(s);
   }
   free(e);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_free_entries_on_list --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_free_entries_on_list(struct poll_loop *poll,
                          struct circlist_item **list)
{
   while (!circlist_empty(*list)) {
      struct circlist_item *li = *list;
      struct poll_entry *e;

      e = GET_ENTRY(li);
      circlist_delete_item(list, li);
      poll_entry_free(poll, e);
   }
   ASSERT(*list == NULL);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_insert_time --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_insert_time(struct poll_loop *poll,
		 struct poll_entry *entry)
{
   static int count;
   ASSERT(poll && entry);
   ASSERT(entry->type == POLL_CB_TIME);
   ASSERT(entry->refCount > 0);

   entry->queued = 1;

   if (circlist_empty(poll->list_time)) {
      circlist_queue_item(&poll->list_time, &entry->item);
   } else {
      struct circlist_item *li;
      struct poll_entry *e;
      bool done = 0;

      e = GET_ENTRY(poll->list_time);
      if (entry->expiry < e->expiry) {
         circlist_push_item(&poll->list_time, &entry->item);
      } else {
         CIRCLIST_SCAN(li, poll->list_time) {
            e = GET_ENTRY(li);

            if (entry->expiry < e->expiry) {
               circlist_queue_item(&li, &entry->item);
               done = 1;
               break;
            }
         }
         if (done == 0) {
            circlist_queue_item(&poll->list_time, &entry->item);
         }
      }
   }
   /*
    * Check the order of the time queue once in a while.
    */
   count++;
   if ((count % 32) == 0) {
      poll_check_time_queue_order(poll);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_get_max_fds --
 *
 *-------------------------------------------------------------------------
 */

static int
poll_get_max_fds(void)
{
   struct rlimit lim;
   int res;

   res = getrlimit(RLIMIT_NOFILE, &lim);
   if (res) {
      log_warn(LGPFX" getrlimit failed: %s\n", strerror(errno));
      return 4096;
   }
   return lim.rlim_cur;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_create --
 *
 *-------------------------------------------------------------------------
 */

struct poll_loop *
poll_create(void)
{
   struct poll_loop *poll;

   poll = safe_malloc(sizeof *poll);

   FD_ZERO(&poll->fds_rd);
   FD_ZERO(&poll->fds_wr);

   poll->list_free       = NULL;
   poll->list_device     = NULL;
   poll->list_time       = NULL;
   poll->use_poll        = 1;

#ifdef __APPLE__
   poll->use_poll     = 1; // XXX
#endif
   poll->poll_fds     = NULL;
   poll->poll_max_fds = poll_get_max_fds();
   log_info(LGPFX" using poll_max_fds=%zu\n", poll->poll_max_fds);

   poll->hash = hashtable_create();

   if (poll->use_poll) {
      poll->poll_fds = safe_malloc(poll->poll_max_fds * sizeof(struct pollfd));
   }

   return poll;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_destroy --
 *
 *-------------------------------------------------------------------------
 */

void
poll_destroy(struct poll_loop *poll)
{
   ASSERT(poll->list_device == NULL);
   ASSERT(poll->list_time == NULL);

   poll_free_entries_on_list(poll, &poll->list_free);
   poll_free_entries_on_list(poll, &poll->list_device);
   poll_free_entries_on_list(poll, &poll->list_time);

   hashtable_destroy(poll->hash);
   poll->hash = NULL;

   free(poll->poll_fds);

   FD_ZERO(&poll->fds_rd);
   FD_ZERO(&poll->fds_wr);

   free(poll);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_device_poll --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_device_poll(struct poll_loop *spoll,
                 mtime_t deadline)
{
   struct pollfd *poll_fds = spoll->poll_fds;
   struct circlist_item *li;
   int n = 0;
   int s;

   CIRCLIST_SCAN(li, spoll->list_device) {
      struct poll_entry *e = GET_ENTRY(li);
      bool read  = e->readable;
      bool write = e->writeable;
      int fd     = e->fd;

      ASSERT(fd >= 0);

      LOG(1, (LGPFX" %s: poll(2)'ing r=%u w=%u fd=%d\n",
              __func__, read, write, fd));

      ASSERT(n < spoll->poll_max_fds);
      poll_fds[n].fd = fd;
      poll_fds[n].events = 0;
      poll_fds[n].revents = 0;
      if (read) {
         poll_fds[n].events |= POLLIN;
      }
      if (write) {
         poll_fds[n].events |= POLLOUT;
      }
      e->idx = n;
      n++;
   }

   do {
      mtime_t now = time_get();
      int timeoutMsec;

      if (deadline == 0) {
         timeoutMsec = 1000; // Wake up once per sec
      } else if (deadline <= now) {
         timeoutMsec = 0;
      } else {
         timeoutMsec = (deadline - now) / 1000;
      }

      LOG(1, (LGPFX" sleeping for %u msec n=%u\n", timeoutMsec, n));
      s = poll(poll_fds, n, timeoutMsec);
   } while (s == -1 && errno == EINTR);

   if (s == -1 && errno != EINTR) {
      s = errno;
      log_warn(LGPFX" Failed to poll(2): %s (%d)\n", strerror(s), s);
      log_warn(LGPFX" nfds=%d\n", n);
      CIRCLIST_SCAN(li, spoll->list_device) {
         struct poll_entry *e = GET_ENTRY(li);
         ssize_t res;
         uint8 c;
         log_info(LGPFX" %s: just poll'd: fd=%d r=%u w=%u cb=%p data=%p\n",
             __func__, e->fd, e->readable, e->writeable,
             e->callback, e->callbackData);
         res = read(e->fd, &c, 1);
         if (res != EAGAIN && res != 1) {
            log_warn(LGPFX" fd=%d res=%zd errno=%d (%s)\n",
                    e->fd, res, errno, strerror(errno));
         }

      }
      NOT_REACHED();
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_device_select --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_device_select(struct poll_loop *poll,
                   mtime_t deadline)
{
   struct circlist_item *li;
   int fds_max = -1;
   int s;

   FD_ZERO(&poll->fds_rd);
   FD_ZERO(&poll->fds_wr);

   CIRCLIST_SCAN(li, poll->list_device) {
      struct poll_entry *e = GET_ENTRY(li);
      bool read  = e->readable;
      bool write = e->writeable;
      int fd     = e->fd;

      ASSERT(fd >= 0);

      LOG(2, (LGPFX" %s: polling r=%u w=%u fd=%d\n",
              __func__, read, write, fd));

      if (read) {
         ASSERT(!FD_ISSET(fd, &poll->fds_rd));
         FD_SET(fd, &poll->fds_rd);
      }
      if (write) {
         ASSERT(!FD_ISSET(fd, &poll->fds_wr));
         FD_SET(fd, &poll->fds_wr);
      }
      fds_max = MAX(fds_max, fd);
   }

   do {
      mtime_t now = time_get();
      struct timeval tv;
      mtime_t timeout;

      if (deadline == 0) {
         timeout = 1000 * 1000; // Wake up once per sec
      } else if (deadline <= now) {
         timeout = 0;
      } else {
         timeout = deadline - now;
      }

      tv.tv_sec  = timeout / (1000 * 1000);
      tv.tv_usec = timeout % (1000 * 1000);

      s = select(fds_max + 1, &poll->fds_rd, &poll->fds_wr, NULL, &tv);
   } while (s == -1 && errno == EINTR);

   if (s == -1 && errno != EINTR) {
      s = errno;
      log_warn(LGPFX" Failed to select(2): %s (%d)\n", strerror(s), s);
      NOT_REACHED();
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_get_next_expiry --
 *
 *-------------------------------------------------------------------------
 */

static mtime_t
poll_get_next_expiry(const struct poll_loop *poll)
{
   struct poll_entry *e;

   ASSERT(poll);

   if (circlist_empty(poll->list_time)) {
      return 0;
   }
   e = GET_ENTRY(poll->list_time);
   return e->expiry;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_fire --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_entry_fire(const struct poll_entry *e)
{
   ASSERT(e);
   ASSERT(e->callback);
   ASSERT(e->queued);
   ASSERT(e->refCount > 0);

   if (e->type == POLL_CB_DEVICE) {
      LOG(1, (LGPFX" %s: firing DEVICE CB fd=%d r=%u w=%u p=%u fun=%p data=%p\n",
              __func__, e->fd, e->readable, e->writeable,
              e->permanent, e->callback, e->callbackData));
   } else {
      LOG(1, (LGPFX" %s: firing TIME CB p=%d fun=%p data=%p\n",
              __func__, e->permanent, e->callback, e->callbackData));
   }

   e->callback(e->callbackData);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_entry_active --
 *
 *-------------------------------------------------------------------------
 */

static bool
poll_entry_active(const struct poll_loop *poll,
                  const struct poll_entry *e)
{
   if (poll->use_poll) {
      int idx = e->idx;

      ASSERT(idx < poll->poll_max_fds);
      ASSERT(poll->poll_fds[idx].fd == e->fd);

      return (e->readable  && (poll->poll_fds[idx].revents & POLLIN)  != 0) ||
             (e->writeable && (poll->poll_fds[idx].revents & POLLOUT) != 0);
   } else {
      return (e->readable  && FD_ISSET(e->fd, &poll->fds_rd)) ||
             (e->writeable && FD_ISSET(e->fd, &poll->fds_wr));
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_run_device_queue --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_run_device_queue(struct poll_loop *poll)
{
   struct poll_entry *queue[poll->poll_max_fds * 2];
   struct circlist_item *li;
   int n = 0;
   int i;

   /*
    * Calling a callback may modify the state of the poll entries and the
    * linked-list itself. We thus need to linearize the list before calling
    * each entry and take a reference on each entry.
    */

   CIRCLIST_SCAN(li, poll->list_device) {
      struct poll_entry *e = GET_ENTRY(li);

      ASSERT(e->type == POLL_CB_DEVICE);

      if (poll_entry_active(poll, e)) {
         queue[n++] = e;
         poll_entry_ref(e);
      }
   }


   /*
    * For each entry that had activity on their respective fd, we need to call
    * the associated callback but also dequeue it if it was not a periodic
    * entry.
    */

   for (i = 0; i < n; i++) {
      struct poll_entry *e = queue[i];

      if (e->queued) {
         if (e->permanent == 0) {
            poll_entry_remove_from_hashtable(poll, e);
            poll_entry_dequeue(&poll->list_device, e);
            poll_entry_unref(poll, &e);
            ASSERT(e);
         }
         poll_entry_fire(e);
      }
      poll_entry_unref(poll, &e);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_get_next_expired --
 *
 *-------------------------------------------------------------------------
 */

static struct poll_entry *
poll_get_next_expired(struct poll_loop *poll,
                      mtime_t now)
{
   struct poll_entry *e;

   if (circlist_empty(poll->list_time)) {
      return NULL;
   }

   e = GET_ENTRY(poll->list_time);

   if (e->expiry <= now) {
      return e;
   }

   ASSERT(e->expiry > now);
   return NULL;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_recalc_expiry --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_recalc_expiry(struct poll_entry *e)
{
   e->expiry = time_get() + e->delay;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_run_time_queue --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_run_time_queue(struct poll_loop *poll)
{
   mtime_t now = time_get();

   ASSERT(poll);

   while (1) {
      struct poll_entry *e = poll_get_next_expired(poll, now);

      if (e == NULL) {
	 break;
      }

      poll_entry_ref(e);
      poll_entry_dequeue(&poll->list_time, e);
      poll_entry_fire(e);
      poll_entry_unref(poll, &e);
      ASSERT(e->refCount > 0);

      if (e->permanent == 0) {
         poll_entry_unref(poll, &e);
         ASSERT(e == NULL);
      } else {
         poll_recalc_expiry(e);
         poll_insert_time(poll, e);
      }
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_dopoll_device --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_dopoll_device(struct poll_loop *poll,
                   mtime_t deadline)
{
   if (poll->use_poll) {
      poll_device_poll(poll, deadline);
   } else {
      poll_device_select(poll, deadline);
   }
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_runloop --
 *
 *-------------------------------------------------------------------------
 */

void
poll_runloop(struct poll_loop *poll,
	     volatile int *exitPtr)
{
   ASSERT(poll);
   ASSERT(exitPtr);

   do {
      mtime_t deadline;

      poll_run_time_queue(poll);
      if (*exitPtr != 0) {
         break;
      }

      deadline = poll_get_next_expiry(poll);
      poll_dopoll_device(poll, deadline);
      if (*exitPtr != 0) {
         break;
      }
      poll_run_device_queue(poll);
   } while (*exitPtr == 0);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_insert_device --
 *
 *-------------------------------------------------------------------------
 */

static void
poll_insert_device(struct poll_loop *poll,
		   struct poll_entry *e)
{
   uint64 key;
   bool s;

   ASSERT(e->type == POLL_CB_DEVICE);

   key = poll_get_device_key_from_entry(e);

   s = hashtable_insert(poll->hash, &key, sizeof key, e);
   ASSERT(s);

   circlist_queue_item(&poll->list_device, &e->item);
   e->queued = 1;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_callback_time --
 *
 *-------------------------------------------------------------------------
 */

void
poll_callback_time(struct poll_loop *poll,
		   mtime_t delayUsec,
		   bool permanent,
		   pollcallback_fun *callback,
		   void *callbackData)
{
   struct poll_entry *e;

   ASSERT(poll);
   ASSERT(callback);

   LOG(1, (LGPFX" %s: registering time CB fun=%p cbData=%p delay=%.1f msec p=%u\n",
       __func__, callback, callbackData, delayUsec / 1000.0, permanent));

   e = poll_entry_get(poll);
   e->type         = POLL_CB_TIME;
   e->callback     = callback;
   e->callbackData = callbackData;
   e->permanent    = permanent;
   e->refCount     = 0;
   e->delay      = delayUsec;

   circlist_init_item(&e->item);

   poll_entry_ref(e);
   poll_recalc_expiry(e);
   poll_insert_time(poll, e);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_callback_device --
 *
 *-------------------------------------------------------------------------
 */

void
poll_callback_device(struct poll_loop *poll,
		     int fd,
		     bool readable,
		     bool writeable,
                     bool permanent,
		     pollcallback_fun *callback,
		     void *callbackData)
{
   struct poll_entry *e;

   LOG(1, (LGPFX" %s: registering dev CB on fd=%d fun=%p cbData=%p r=%u w=%u p=%u\n",
       __func__, fd, callback, callbackData, readable, writeable, permanent));

   ASSERT(poll);
   ASSERT(callback);

   e = poll_entry_get(poll);
   e->type          = POLL_CB_DEVICE;
   e->callback      = callback;
   e->callbackData  = callbackData;
   e->permanent     = permanent;
   e->refCount      = 0;
   e->fd          = fd;
   e->idx         = -1;
   e->readable    = readable;
   e->writeable   = writeable;

   circlist_init_item(&e->item);

   poll_entry_ref(e);
   poll_insert_device(poll, e);
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_callback_time_remove --
 *
 *-------------------------------------------------------------------------
 */

bool
poll_callback_time_remove(struct poll_loop *poll,
                          bool permanent,
                          pollcallback_fun callback,
                          void *callbackData)
{
   struct circlist_item **list;
   struct circlist_item *li;

   LOG(1, (LGPFX" %s: unregistering TIME CB fun=%p data=%p.\n",
       __func__, callback, callbackData));

   list = &poll->list_time;

   CIRCLIST_SCAN(li, *list) {
      struct poll_entry *e = GET_ENTRY(li);

      if (e->callback     == callback &&
          e->callbackData == callbackData &&
          e->permanent    == permanent) {
         e->queued = 0;
         poll_entry_dequeue(&poll->list_time, e);
         poll_entry_unref(poll, &e);
         return 1;
      }
   }

   return 0;
}


/*
 *-------------------------------------------------------------------------
 *
 * poll_callback_device_remove --
 *
 *-------------------------------------------------------------------------
 */

bool
poll_callback_device_remove(struct poll_loop *poll,
                            int fd,
                            bool readable,
                            bool writeable,
                            bool permanent,
                            pollcallback_fun callback,
                            void *callbackData)
{
   struct poll_entry *e;
   uint64 key;
   bool s;

   LOG(1, (LGPFX" %s: unregistering DEVICE CB fd=%d r=%u w=%u p=%u fun=%p.\n",
       __func__, fd, readable, writeable, permanent, callback));

   key = poll_get_device_key(fd, readable, writeable, permanent);
   e = NULL;

   s = hashtable_lookup(poll->hash, &key, sizeof key, (void **)&e);
   if (!s) {
      return 0;
   }

   ASSERT(e->type == POLL_CB_DEVICE);
   ASSERT(e->fd == fd);
   ASSERT(e->callback == callback);
   ASSERT(e->callbackData == callbackData);
   ASSERT(e->permanent == permanent);
   ASSERT(e->readable == readable);
   ASSERT(e->writeable == writeable);
   ASSERT(e->queued == 1);

   e->queued = 0;

   poll_entry_remove_from_hashtable(poll, e);
   poll_entry_dequeue(&poll->list_device, e);
   poll_entry_unref(poll, &e);

   return 1;
}

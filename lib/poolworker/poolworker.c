#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>

#include "atomic.h"
#include "basic_defs.h"
#include "util.h"
#include "circlist.h"
#include "poolworker.h"

#define LGPFX "POOL:"

static int verbose;

struct poolworker_job {
   poolworker_func       *func;
   void                  *clientData;
   struct circlist_item   item;
};

#define GET_JOB(_li) \
   CIRCLIST_CONTAINER(_li, struct poolworker_job, item);

struct poolworker_state {
   atomic_uint32         numRunning;
   atomic_uint32         exit;
   pthread_mutex_t       lock;
   pthread_cond_t        cond_req;
   pthread_cond_t        cond_cmp;
   struct circlist_item *jobs_req;
   struct circlist_item *jobs_active;
   struct {
      pthread_t          tid;
      int                jobsDone;
   } *p;
};


/*
 *---------------------------------------------------------------------
 *
 * poolworker_dequeue_job --
 *
 *---------------------------------------------------------------------
 */

static inline struct poolworker_job *
poolworker_dequeue_job(struct circlist_item **list)
{
   struct circlist_item *li;

   ASSERT(!circlist_empty(*list));

   li = *list;
   circlist_delete_item(list, li);

   return GET_JOB(li);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_destroy_job --
 *
 *---------------------------------------------------------------------
 */

static inline void
poolworker_destroy_job(struct poolworker_job *job)
{
   ASSERT(job);
   ASSERT(job->func);

   free(job);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_execute_job --
 *
 *---------------------------------------------------------------------
 */

static inline void
poolworker_execute_job(const struct poolworker_job *job)
{
   ASSERT(job);
   ASSERT(job->func);

   job->func(job->clientData);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_main --
 *
 *---------------------------------------------------------------------
 */

static void *
poolworker_main(void *clientData)
{
   struct poolworker_state *pw = clientData;
   sigset_t set;
   int id;

   sigemptyset(&set);
   sigaddset(&set, SIGQUIT);
   sigaddset(&set, SIGINT);
   pthread_sigmask(SIG_BLOCK, &set, NULL);

   id = atomic_read(&pw->numRunning);
   LOG(1, (LGPFX" thread %u started.\n", id));
   atomic_inc(&pw->numRunning);

   while (1) {
      struct poolworker_job *job;

      pthread_mutex_lock(&pw->lock);
      while (circlist_empty(pw->jobs_req) && atomic_read(&pw->exit) == 0) {
         pthread_cond_wait(&pw->cond_req, &pw->lock);
      }

      if (atomic_read(&pw->exit)) {
         pthread_mutex_unlock(&pw->lock);
         break;
      }
      job = poolworker_dequeue_job(&pw->jobs_req);
      circlist_queue_item(&pw->jobs_active, &job->item);
      pthread_mutex_unlock(&pw->lock);

      poolworker_execute_job(job);

      pthread_mutex_lock(&pw->lock);
      circlist_delete_item(&pw->jobs_active, &job->item);
      pthread_mutex_unlock(&pw->lock);

      poolworker_destroy_job(job);

      pw->p[id].jobsDone++;
      pthread_cond_signal(&pw->cond_cmp);
   }

   atomic_dec(&pw->numRunning);
   pthread_exit(NULL);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_create --
 *
 *---------------------------------------------------------------------
 */

struct poolworker_state *
poolworker_create(int numThreads)
{
   struct poolworker_state *pw;
   int i;

   pw = safe_calloc(1, sizeof *pw);
   pw->p = safe_calloc(numThreads, sizeof *pw->p);
   pw->jobs_req = NULL;
   pw->jobs_active = NULL;

   pthread_mutex_init(&pw->lock, NULL);
   pthread_cond_init(&pw->cond_req, NULL);
   pthread_cond_init(&pw->cond_cmp, NULL);

   atomic_write(&pw->numRunning, 0);
   atomic_write(&pw->exit, 0);

   log_info(LGPFX" creating %u threads\n", numThreads);

   for (i = 0; i < numThreads; i++) {
      pthread_create(&pw->p[i].tid, NULL, poolworker_main, pw);

      while (atomic_read(&pw->numRunning) != i + 1) {
         sched_yield();
      }
   }
   return pw;
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_destroy --
 *
 *---------------------------------------------------------------------
 */

void
poolworker_destroy(struct poolworker_state *pw)
{
   int numThreads;
   int i;

   numThreads = atomic_read(&pw->numRunning);

   atomic_inc(&pw->exit);
   while (atomic_read(&pw->numRunning) != 0) {
      pthread_cond_broadcast(&pw->cond_req);
      sched_yield();
   }

   for (i = 0; i < numThreads; i++) {
      int n;
      pthread_join(pw->p[i].tid, NULL);
      n = pw->p[i].jobsDone;
      if (n > 0) {
         log_info(LGPFX" n[%u]=%u\n", i, n);
      }
   }

   ASSERT(pw->jobs_active == NULL);
   ASSERT(pw->jobs_req == NULL);

   pthread_cond_destroy(&pw->cond_req);
   pthread_cond_destroy(&pw->cond_cmp);
   pthread_mutex_destroy(&pw->lock);
   free(pw->p);
   free(pw);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_wait_for_one_cmp --
 *
 *---------------------------------------------------------------------
 */

void
poolworker_wait_for_one_cmp(struct poolworker_state *pw)
{
   pthread_mutex_lock(&pw->lock);
   if (!circlist_empty(pw->jobs_req) || !circlist_empty(pw->jobs_active)) {
      pthread_cond_wait(&pw->cond_cmp, &pw->lock);
   }
   pthread_mutex_unlock(&pw->lock);
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_wait --
 *
 *---------------------------------------------------------------------
 */

void
poolworker_wait(struct poolworker_state *pw)
{
   log_info(LGPFX" quiescing..\n");

   pthread_mutex_lock(&pw->lock);
   while (!circlist_empty(pw->jobs_req) || !circlist_empty(pw->jobs_active)) {
      pthread_cond_wait(&pw->cond_cmp, &pw->lock);
   }
   pthread_mutex_unlock(&pw->lock);
   log_info(LGPFX" all done.\n");
}


/*
 *---------------------------------------------------------------------
 *
 * poolworker_queue_work --
 *
 *---------------------------------------------------------------------
 */

void
poolworker_queue_work(struct poolworker_state *pw,
                      poolworker_func *func,
                      void *clientData)
{
   struct poolworker_job *job;

   job = safe_malloc(sizeof *job);
   job->func       = func;
   job->clientData = clientData;

   circlist_init_item(&job->item);

   pthread_mutex_lock(&pw->lock);
   circlist_queue_item(&pw->jobs_req, &job->item);
   pthread_mutex_unlock(&pw->lock);

   pthread_cond_signal(&pw->cond_req);
}


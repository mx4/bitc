#pragma once

#include "basic_defs.h"

enum poll_type {
   POLL_CB_NONE,
   POLL_CB_DEVICE,
   POLL_CB_TIME,
};

struct poll_loop;
typedef void (pollcallback_fun)(void *clientdata);

struct poll_loop *poll_create(void);
void poll_destroy(struct poll_loop *poll);
void poll_runloop(struct poll_loop *poll, volatile int *exit);

bool
poll_callback_device_remove(struct poll_loop *poll,
                            int fd,
                            bool readable,
                            bool writeable,
                            bool permanent,
                            pollcallback_fun callback,
                            void *callbackData);

bool
poll_callback_time_remove(struct poll_loop *poll,
                          bool permanent,
                          pollcallback_fun callback,
                          void *callbackData);

void poll_callback_time(struct poll_loop *poll,
			mtime_t delayUsec,
			bool periodic,
			pollcallback_fun func,
			void *clientData);

void poll_callback_device(struct poll_loop *poll,
			  int fd,
			  bool readable,
			  bool writeable,
                          bool permanent,
			  pollcallback_fun func,
			  void *clientData);


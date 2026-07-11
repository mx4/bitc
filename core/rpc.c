#include <string.h>
#include <sys/socket.h>

#include "util.h"
#include "netasync.h"
#include "config.h"
#include "bitc.h"
#include "rpc.h"

#define LGPFX "RPC:"

static struct netasync_socket *sock;


/*
 *-------------------------------------------------------------------------
 *
 * rpc_exit --
 *
 *-------------------------------------------------------------------------
 */

void
rpc_exit(void)
{
   if (sock == NULL) {
      return;
   }

   netasync_close(sock);
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_accept_cb --
 *
 *-------------------------------------------------------------------------
 */

static void
rpc_accept_cb(struct netasync_socket *socket,
              void                   *clientdata,
              int                     err)
{
   ASSERT(err == 0);

   log_info(LGPFX" %s:%u -- got a connection.\n", __FUNCTION__, __LINE__);

   netasync_close(socket); // for now.
}


/*
 *-------------------------------------------------------------------------
 *
 * rpc_init --
 *
 *-------------------------------------------------------------------------
 */

int
rpc_init(void)
{
   struct sockaddr_in addr;
   int err;

   if (config_getbool(btc->config, 0, "rpc.enable") == 0) {
      log_info(LGPFX" %s: rpc disabled\n", __FUNCTION__);
      return 0;
   }

   log_info(LGPFX" %s:%u\n", __FUNCTION__, __LINE__);

   sock = netasync_create();

   err = netasync_resolve("localhost", 9990, &addr);
   if (err != 0) {
      log_info(LGPFX" failed to resolve: %s (%d)\n", strerror(err), err);
      return err;
   }
   err = netasync_bind(sock, &addr, rpc_accept_cb, NULL);
   if (err != 0) {
      log_info(LGPFX" failed to bind: %s (%d)\n", strerror(err), err);
      return err;
   }
   log_info(LGPFX" %s: listening on localhost:999.\n", __FUNCTION__);

   return 0;
}

#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include "basic_defs.h"
#include "poll.h"

struct netasync_socket;

typedef void (netasync_callback)(struct netasync_socket *socket,
                                 void *clientdata, int err);

typedef void (netasync_recv_callback)(struct netasync_socket *socket,
                                      void *buf,
                                      size_t len,
                                      void *clientdata);

time_t netasync_get_connect_ts(const struct netasync_socket *sock);
struct netasync_socket* netasync_create(void);
void netasync_close(struct netasync_socket *socket);
short int netasync_port(const struct netasync_socket *sock);
char * netasync_addr2str(const struct sockaddr_in *addr);
const char *netasync_hostname(const struct netasync_socket *sock);
void netasync_init(struct poll_loop *poll);
void netasync_exit(void);

void netasync_set_errorhandler(struct netasync_socket *sock,
                               netasync_callback *callback,
                               void *clientData);
int netasync_receive(struct netasync_socket *sock,
                     void *buf, size_t bufLen, bool partial,
                     netasync_recv_callback *callback,
                     void *clientData);

int netasync_send(struct netasync_socket *sock,
                  const void *buf,
                  size_t len,
                  netasync_callback *cb,
                  void *clientData);

int netasync_resolve(const char *hostname,
                     uint16 port,
                     struct sockaddr_in *addr);

int netasync_connect(struct netasync_socket *socket,
                     const struct sockaddr_in *addr,
                     int timeout_sec,
                     netasync_callback *cb,
                     void *clientData);
int
netasync_bind(struct netasync_socket   *sock,
              const struct sockaddr_in *addr,
              netasync_callback        *cb,
              void                     *clientData);
void
netasync_use_socks(struct netasync_socket *sock,
                   const char *hostname, short port);


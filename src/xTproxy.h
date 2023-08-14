#ifndef XTPROXY_H
#define XTPROXY_H

#include "uv.h"
#include "socks.h"
#include "packet.h"
#include "packet.h"


#ifdef VERSION
#define xTProxy_VER        VERSION
#define xTProxy_BUILD_TIME BUILD_TIME
#else
#define xTProxy_VER        "undefined"
#define xTProxy_BUILD_TIME ""
#endif


struct client_context {
    int stage;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    struct sockaddr target_addr;
    uv_write_t write_req;
    struct remote_context *remote;
    uint8_t buf[MAX_PACKET_SIZE];
};

struct remote_context {
    int stage;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_write_t write_req;
    uv_timer_t *timer;
    uv_connect_t connect_req;
    struct sockaddr *server_addr;
    struct dns_query *addr_query;
    struct client_context *client;
    struct packet packet;
    uint16_t idle_timeout;
};

struct client_context * new_client();
void close_client(struct client_context *client);
void receive_from_client(struct client_context *client);
void forward_to_client(struct client_context *client, uint8_t *buf, int buflen);
void client_accept_cb(uv_stream_t *server, int status);

struct remote_context * new_remote(uint16_t timeout);
void close_remote(struct remote_context *remote);
void connect_to_remote(struct remote_context *remote);
void receive_from_remote(struct remote_context *remote);
void forward_to_remote(struct remote_context *remote, uint8_t *buf, int buflen);
void reset_timer(struct remote_context *remote);

void close_loop(uv_loop_t *loop);

#endif // for #ifndef XTPROXY_H

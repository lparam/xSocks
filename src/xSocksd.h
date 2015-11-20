#ifndef XSOCKSD_H
#define XSOCKSD_H

#include "uv.h"
#include "socks.h"
#include "packet.h"
#include "resolver.h"


#define XSOCKSD_VER          "xSocksd/" XSOCKS_VERSION


struct client_context {
    int stage;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_write_t write_req;
    struct sockaddr addr;
    char target_addr[256];
    struct remote_context *remote;
    struct packet packet;
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
    uint16_t idle_timeout;
    uint8_t buf[MAX_PACKET_SIZE];
    struct sockaddr addr;
    struct client_context *client;
    struct resolver_query *host_query;
};

struct client_context * new_client();
void close_client(struct client_context *client);
void receive_from_client(struct client_context *client);
void forward_to_client(struct client_context *client, uint8_t *buf, int buflen);
void client_accept_cb(uv_stream_t *server, int status);

struct remote_context * new_remote(uint16_t timeout);
void close_remote(struct remote_context *remote);
void resolve_remote(struct remote_context *remote, char *host, uint16_t port);
void connect_to_remote(struct remote_context *remote);
void receive_from_remote(struct remote_context *remote);
void forward_to_remote(struct remote_context *remote, uint8_t *buf, int buflen);
void reset_timer(struct remote_context *remote);

void close_loop(uv_loop_t *loop);

int verbose;
uint16_t idle_timeout;
uv_key_t thread_resolver_key;

#endif // for #ifndef XSOCKSD_H

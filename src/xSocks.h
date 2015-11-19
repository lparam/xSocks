#ifndef XSOCKS_H
#define XSOCKS_H

#include "uv.h"
#include "socks.h"
#include "packet.h"


#define XSOCKS_VER          "xSocks/" XSOCKS_VERSION


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
    struct remote_context *remote;
    uint8_t buf[MAX_PACKET_SIZE];
    uint8_t buflen;
    uint8_t cmd;
    char target_addr[256];
};

struct remote_context {
    int stage;
    int direct;
    uv_os_sock_t tcp_fd;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_write_t write_req;
    uv_timer_t *timer;
    uv_connect_t connect_req;
    struct sockaddr addr;
    struct client_context *client;
    struct packet packet;
    uint16_t idle_timeout;
};

struct client_context * new_client();
void close_client(struct client_context *client);
void receive_from_client(struct client_context *client);
void forward_to_client(struct client_context *client, uint8_t *buf, int buflen);
void client_accept_cb(uv_stream_t *server, int status);
void request_ack(struct client_context *client, enum s5_rep rep);

struct remote_context * new_remote(uint16_t timeout, struct sockaddr *addr);
void close_remote(struct remote_context *remote);
void connect_to_remote(struct remote_context *remote);
void receive_from_remote(struct remote_context *remote);
void forward_to_remote(struct remote_context *remote, uint8_t *buf, int buflen);
void reset_timer(struct remote_context *remote);

#ifdef ANDROID
int vpn;
#endif
int acl;
int verbose;
uint16_t idle_timeout;
struct sockaddr bind_addr;
struct sockaddr server_addr;

#endif // for #ifndef XSOCKS_H

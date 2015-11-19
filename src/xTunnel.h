#ifndef XTUNNEL_H
#define XTUNNEL_H

#include "uv.h"
#include "socks.h"
#include "packet.h"


#define TUNNEL_VER          "xTunnel/" XSOCKS_VERSION


struct source_context {
    int stage;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_write_t write_req;
    struct packet packet;
    struct target_context *target;
};

struct target_context {
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_write_t write_req;
    uv_connect_t connect_req;
    struct packet packet;
    struct source_context *source;
};

enum tunnel_mode {
    TUNNEL_MODE_CLIENT,
    TUNNEL_MODE_SERVER,
};

enum tunnel_stage {
    TUNNEL_STAGE_FORWARD,
    TUNNEL_STAGE_DEAD,
};

struct source_context * new_source();
void close_source(struct source_context *source);
void source_accept_cb(uv_stream_t *server, int status);
void forward_to_source(struct source_context *source, uint8_t *buf, int buflen);
void receive_from_source(struct source_context *source);

struct target_context * new_target();
void close_target(struct target_context *target);
void connect_to_target(struct target_context *target);
void forward_to_target(struct target_context *target, uint8_t *buf, int buflen);
void receive_from_target(struct target_context *target);

int verbose;
enum tunnel_mode mode;
struct sockaddr target_addr;

#endif // for #ifndef XTUNNEL_H

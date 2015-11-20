#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "socks.h"
#include "xForwarder.h"


static void remote_send_cb(uv_write_t *req, int status);
static void remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
static void request_to_server(struct remote_context *remote);


static void
remote_timer_expire(uv_timer_t *handle) {
    struct remote_context *remote = handle->data;
    struct client_context *client = remote->client;
    if (verbose) {
        struct sockaddr peername;
        int namelen = sizeof peername;
        uv_tcp_getpeername(&client->handle.tcp, &peername, &namelen);
        char addr[INET6_ADDRSTRLEN + 1];
        int port = ip_name(&peername, addr, sizeof addr);
        logger_log(LOG_WARNING, "%s:%d <-> %s timeout", addr, port, dest_addr_buf);
    }
    close_client(client);
    close_remote(remote);
}

void
reset_timer(struct remote_context *remote) {
    if (remote->timer != NULL) {
        remote->timer->data = remote;
        uv_timer_start(remote->timer, remote_timer_expire, remote->idle_timeout * 1000, 0);
    }
}

static void
timer_close_cb(uv_handle_t *handle) {
    free(handle);
}

struct remote_context *
new_remote(uint16_t timeout) {
    struct remote_context *remote = malloc(sizeof(*remote));
    memset(remote, 0, sizeof(*remote));
    remote->timer = malloc(sizeof(uv_timer_t));
    remote->idle_timeout = timeout;
    return remote;
}

static void
free_remote(struct remote_context *remote) {
    if (remote->client != NULL) {
        remote->client = NULL;
    }
    free(remote);
    remote = NULL;
}

static void
remote_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct remote_context *remote = (struct remote_context *)handle->data;
    struct packet *packet = &remote->packet;
    if (packet->size) {
        buf->base = (char*)packet->buf + packet->offset;
        buf->len = packet->size - packet->offset;
    } else {
        buf->base = (char*)packet->buf + (packet->read ? 1 : 0);
        buf->len = packet->read ? 1 : HEADER_BYTES;
    }
}

static void
remote_close_cb(uv_handle_t *handle) {
    struct remote_context *remote = handle->data;
    free_remote(remote);
}

void
close_remote(struct remote_context *remote) {
    assert(uv_is_closing(&remote->handle.handle) == 0);

    remote->timer->data = NULL;
    uv_close((uv_handle_t *)remote->timer, timer_close_cb);

    remote->timer = NULL;
    remote->stage = XSTAGE_DEAD;

    remote->handle.handle.data = remote;
    uv_close(&remote->handle.handle, remote_close_cb);
}

static void
remote_connect_cb(uv_connect_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        reset_timer(remote);
        client->stage = XSTAGE_FORWARD;
        remote->stage = XSTAGE_FORWARD;
        request_to_server(remote);
        receive_from_remote(remote);

    } else {
        if (status != UV_ECANCELED) {
            char addrbuf[INET6_ADDRSTRLEN + 1];
            ip_name(&server_addr, addrbuf, sizeof(addrbuf));
            logger_log(LOG_ERR, "connect to %s failed: %s", addrbuf, uv_strerror(status));
            close_client(client);
            close_remote(remote);
        }
    }
}

void
receive_from_remote(struct remote_context *remote) {
    packet_reset(&remote->packet);
    remote->handle.stream.data = remote;
    uv_read_start(&remote->handle.stream, remote_alloc_cb, remote_recv_cb);
}

void
forward_to_remote(struct remote_context *remote, uint8_t *buf, int buflen) {
    buf -= HEADER_BYTES;
    write_size(buf, buflen);
    buflen += HEADER_BYTES;
    uv_buf_t data = uv_buf_init((char*)buf, buflen);
    remote->write_req.data = remote;
    uv_write(&remote->write_req, &remote->handle.stream, &data, 1, remote_send_cb);
}

static void
request_to_server(struct remote_context *remote) {
    static uint16_t portlen = 2;
    size_t buflen;
    char buf[260] = {0};
    struct client_context *client = remote->client;

    struct sockaddr *addr = &dest_addr;

    /*
     *
     * xSocks request
     * +------+----------+----------+
     * | ATYP | BND.ADDR | BND.PORT |
     * +------+----------+----------+
     * |  1   | Variable |    2     |
     * +------+----------+----------+
     *
     */
    if (addr->sa_family == AF_INET) {
        size_t in_addr_len = sizeof(struct in_addr);
        buflen = sizeof(struct xSocks_request) + in_addr_len + portlen;
        buf[0] = ATYP_IPV4;
        memcpy(buf + 1, &((struct sockaddr_in *)addr)->sin_addr, in_addr_len);
        memcpy(buf + 1 + in_addr_len, &((struct sockaddr_in *)addr)->sin_port, portlen);

    } else {
        size_t in6_addr_len = sizeof(struct in6_addr);
        buflen = sizeof(struct xSocks_request) + sizeof(struct in6_addr) + portlen;
        buf[0] = ATYP_IPV6;
        memcpy(buf + 1, &((struct sockaddr_in6 *)addr)->sin6_addr, in6_addr_len);
        memcpy(buf + 1 + in6_addr_len, &((struct sockaddr_in6 *)addr)->sin6_port, portlen);
    }

    int clen = buflen + PRIMITIVE_BYTES;
    uint8_t *c = client->buf + HEADER_BYTES;
    int rc = crypto_encrypt(c, (uint8_t*)buf, buflen);
    if (!rc) {
        forward_to_remote(remote, c, clen);
    }
}

void
connect_to_remote(struct remote_context *remote) {
    remote->stage = XSTAGE_CONNECT;
    remote->connect_req.data = remote;
    int rc = uv_tcp_connect(&remote->connect_req, &remote->handle.tcp, &server_addr, remote_connect_cb);
    if (rc) {
        char addrbuf[INET6_ADDRSTRLEN + 1];
        ip_name(&server_addr, addrbuf, sizeof(addrbuf));
        logger_log(LOG_ERR, "connect to %s error: %s", addrbuf, uv_strerror(rc));
        close_client(remote->client);
        close_remote(remote);
    }
}

static void
remote_send_cb(uv_write_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        reset_timer(remote);
        receive_from_client(client);

    } else {
        logger_log(LOG_ERR, "forward to server failed: %s", uv_strerror(status));
    }
}

static void
remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct remote_context *remote;
    struct client_context *client;

    remote = stream->data;
    client = remote->client;

    if (nread > 0) {
        reset_timer(remote);
        struct packet *packet = &remote->packet;
        int rc = packet_filter(packet, buf->base, nread);
        if (rc == PACKET_COMPLETED) {
            uint8_t *m = packet->buf;
            int mlen = packet->size - PRIMITIVE_BYTES;

            int err = crypto_decrypt(m, packet->buf, packet->size);
            if (err) {
                goto error;
            }

            uv_read_stop(&remote->handle.stream);
            forward_to_client(client, m, mlen);

        } else if (rc == PACKET_INVALID) {
            goto error;
        }

    } else if (nread < 0){
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "receive from %s failed: %s", dest_addr_buf, uv_strerror(nread));
        }
        close_client(client);
        close_remote(remote);
    }

    return;

error:
    logger_log(LOG_ERR, "invalid tcp packet");
    close_client(client);
    close_remote(remote);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "socks.h"
#include "xsocks.h"


static void client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void client_send_cb(uv_write_t *req, int status);
static void client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


struct client_context *
new_client() {
    struct client_context *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->stage = XSTAGE_HANDSHAKE;
    return client;
}

static void
free_client(struct client_context *client) {
    if (client->remote != NULL) {
        client->remote = NULL;
    }
    free(client);
}

static void
client_close_cb(uv_handle_t *handle) {
    struct client_context *client = (struct client_context *)handle->data;
    free_client(client);
}

void
close_client(struct client_context *client) {
    client->stage = XSTAGE_DEAD;
    client->handle.handle.data = client;
    uv_close(&client->handle.handle, client_close_cb);
}

static int
verify_methods(char *buf, ssize_t buflen) {
    struct socks5_method_request *req = (struct socks5_method_request *)buf;
    return buflen == 1 + 1 + req->nmethods;
}

static int
verify_request(char *buf, ssize_t buflen) {
    size_t len;
    struct socks5_request *req = (struct socks5_request *)buf;

    if (req->atyp == ATYP_IPV4) {
        len = sizeof(struct socks5_request) + sizeof(struct in_addr) + 2;
    } else if (req->atyp == ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(req->addr);
        len = sizeof(struct socks5_request) + 1 + namelen + 2;
    } else if (req->atyp == ATYP_IPV6) {
        len = sizeof(struct socks5_request) + sizeof(struct in6_addr) + 2;
    } else {
        len = 0;
    }

    return len == buflen;
}

void
receive_from_client(struct client_context *client) {
    client->handle.stream.data = client;
    uv_read_start(&client->handle.stream, client_alloc_cb, client_recv_cb);
}

void
forward_to_client(struct client_context *client, uint8_t *buf, int buflen) {
    uv_buf_t reply = uv_buf_init((char*)buf, buflen);
    client->write_req.data = client;
    uv_write_t *write_req = malloc(sizeof *write_req);
    write_req->data = client;
    uv_write(write_req, &client->handle.stream, &reply, 1, client_send_cb);
}

/*
 *
 * SOCKS5 Replies
 * +----+-----+-------+------+----------+----------+
 * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   | Variable |    2     |
 * +----+-----+-------+------+----------+----------+
 *
 */
void
request_ack(struct client_context *client, enum s5_rep rep) {
    struct remote_context *remote = client->remote;
    struct sockaddr addr;
    int addrlen = sizeof(addr);
    int buflen;
    uint8_t *buf;

    buf = remote->packet.buf;
    buf[0] = 0x05; // VER
    buf[1] = rep;  // REP
    buf[2] = 0x00; // RSV

    memset(&addr, 0, sizeof(addr));
    if (client->cmd == S5_CMD_UDP_ASSOCIATE) {
        uv_tcp_getsockname(&client->handle.tcp, (struct sockaddr *) &addr, &addrlen);
    } else {
        uv_tcp_getsockname(&remote->handle.tcp, (struct sockaddr *) &addr, &addrlen);
    }
    if (addr.sa_family == AF_INET6) {
        buf[3] = 0x04;  /* ATYP - IPv6. */
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)&addr;
        memcpy(buf + 4, &addr6->sin6_addr, 16); /* BND.ADDR */
        memcpy(buf + 20, &addr6->sin6_port, 2); /* BND.PORT */
        buflen = 22;
    } else {
        buf[3] = 0x01;  /* ATYP - IPv4. */
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)&addr;
        memcpy(buf + 4, &addr4->sin_addr, 4); /* BND.ADDR */
        memcpy(buf + 8, &addr4->sin_port, 2); /* BND.PORT */
        buflen = 10;
    }

    if (rep == S5_REP_SUCCESSED && client->cmd == S5_CMD_CONNECT) {
        client->stage = XSTAGE_FORWARD;
    } else {
        client->stage = XSTAGE_TERMINATE;
    }

    // TODO: handle server can't connect but cmd is udp associate case
    forward_to_client(client, buf, buflen);
}

static void
handshake(struct client_context *client) {
    client->stage = XSTAGE_REQUEST;
    forward_to_client(client, (uint8_t*)"\x5\x0", 2);
}

static void
request_start(struct client_context *client, char *req_buf) {
    struct socks5_request *req = (struct socks5_request *)req_buf;
    struct remote_context *remote = client->remote;

    assert(remote->stage == XSTAGE_FORWARD);

    client->cmd = req->cmd;

    if (req->cmd != S5_CMD_CONNECT && req->cmd != S5_CMD_UDP_ASSOCIATE) {
        logger_log(LOG_ERR, "unsupported cmd: 0x%02x", req->cmd);
        request_ack(client, S5_REP_CMD_NOT_SUPPORTED);
        return;
    }

    char buf[260] = {0};
    size_t buflen;
    uint16_t portlen = 2;

    /*
     *
     * xsocks request
     * +------+----------+----------+
     * | ATYP | BND.ADDR | BND.PORT |
     * +------+----------+----------+
     * |  1   | Variable |    2     |
     * +------+----------+----------+
     *
     */
    if (req->atyp == ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr);
        buflen = sizeof(struct xsocks_request) + in_addr_len + portlen;
        buf[0] = ATYP_IPV4;
        memcpy(buf + 1, req->addr, in_addr_len);
        memcpy(buf + 1 + in_addr_len, req->addr + in_addr_len, portlen);

        uv_inet_ntop(AF_INET, (const void *)(req->addr), client->target_addr, INET_ADDRSTRLEN);
        uint16_t port = read_size((uint8_t*)(req->addr + in_addr_len));
        sprintf(client->target_addr, "%s:%u", client->target_addr, port);

    } else if (req->atyp == ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(req->addr);
        if (namelen > 0xFF) {
            logger_log(LOG_ERR, "unsupported address type: 0x%02x", req->atyp);
            request_ack(client, S5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
            return;
        }
        buflen = sizeof(struct xsocks_request) + 1 + namelen + portlen;
        buf[0] = ATYP_HOST;
        memcpy(buf + 1, req->addr, 1 + namelen);
        memcpy(buf + 1 + 1 + namelen, req->addr + 1 + namelen, portlen);

        memcpy(client->target_addr, req->addr + 1, namelen);
        uint16_t port = read_size((uint8_t*)(req->addr + 1 + namelen));
        sprintf(client->target_addr, "%s:%u", client->target_addr, port);

    } else if (req->atyp == ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr);
        buflen = sizeof(struct xsocks_request) + in6_addr_len + portlen;
        buf[0] = ATYP_IPV6;
        memcpy(buf + 1, req->addr, in6_addr_len);
        memcpy(buf + 1 + in6_addr_len, req->addr + in6_addr_len, portlen);

        uv_inet_ntop(AF_INET6, (const void *)(req->addr), client->target_addr, INET_ADDRSTRLEN);
        uint16_t port = read_size((uint8_t*)(req->addr + in6_addr_len));
        sprintf(client->target_addr, "%s:%u", client->target_addr, port);

    } else {
        logger_log(LOG_ERR, "unsupported address type: 0x%02x", req->atyp);
        request_ack(client, S5_REP_ADDRESS_TYPE_NOT_SUPPORTED);
        return;
    }

    request_ack(client, S5_REP_SUCCESSED);

    // TODO: handle UDP ASSOCIATE
    if (req->cmd == S5_CMD_CONNECT) {
        if (verbose) {
            logger_log(LOG_INFO, "connect to %s", client->target_addr);
        }
        int clen = buflen + PRIMITIVE_BYTES;
        uint8_t *c = client->buf + HEADER_BYTES;
        int rc = crypto_encrypt(c, (uint8_t *)buf, buflen);
        if (!rc) {
            forward_to_remote(remote, c, clen);
        }
    }
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct client_context *client = handle->data;
    buf->base = (char*)(client->buf + OVERHEAD_BYTES);
    buf->len = sizeof(client->buf) - OVERHEAD_BYTES;
}

static void
client_send_cb(uv_write_t *req, int status) {
    struct client_context *client = req->data;
    struct remote_context *remote = client->remote;

    if (status == 0) {
        if (client->stage == XSTAGE_REQUEST) {
            receive_from_client(client);

        } else if (client->stage == XSTAGE_FORWARD) {
            receive_from_remote(remote);

        } else if (client->stage == XSTAGE_TERMINATE) {
            close_client(client);
            close_remote(remote);
        }

    } else {
        char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
        int port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
        logger_log(LOG_ERR, "%s -> %s:%d failed: %s", client->target_addr, addrbuf, port, uv_strerror(status));
    }

    free(req);
}

static void
client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client_context *client = stream->data;
    struct remote_context *remote = client->remote;
    int clen;

    if (nread > 0) {
        reset_timer(remote);
        uv_read_stop(&client->handle.stream);

        switch (client->stage) {
        case XSTAGE_HANDSHAKE:
            if (verify_methods(buf->base, nread)) {
                handshake(client);
            } else {
                logger_log(LOG_ERR, "invalid method packet");
                close_client(client);
                close_remote(remote);
            }

            break;

        case XSTAGE_REQUEST:
            if (verify_request(buf->base, nread)) {
                request_start(client, buf->base);
            } else {
                logger_log(LOG_ERR, "invalid request packet");
                close_client(client);
                close_remote(remote);
            }

            break;

        case XSTAGE_FORWARD:
            clen = nread + PRIMITIVE_BYTES;
            uint8_t *c = client->buf + HEADER_BYTES;
            int rc = crypto_encrypt(c, (uint8_t*)buf->base, nread);
            if (rc) {
                logger_log(LOG_ERR, "encrypt failed");
                close_client(client);
                close_remote(remote);
            }
            forward_to_remote(remote, c, clen);

            break;

        default:
            break;
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
            logger_log(LOG_ERR, "receive from %s:%d failed: %s", addrbuf, port, uv_strerror(nread));
        }
        close_client(client);
        close_remote(remote);
    }
}

void
client_accept_cb(uv_stream_t *server, int status) {
    struct client_context *client = new_client();
    struct remote_context *remote = new_remote(idle_timeout);

    client->remote = remote;
    remote->client = client;

    uv_timer_init(server->loop, remote->timer);

    uv_tcp_init(server->loop, &client->handle.tcp);
    uv_tcp_init(server->loop, &remote->handle.tcp);


    int rc = uv_accept(server, &client->handle.stream);
    if (rc == 0) {
        int namelen = sizeof client->addr;
        uv_tcp_getpeername(&client->handle.tcp, &client->addr, &namelen);
        reset_timer(remote); // start timer
        connect_to_remote(remote);
    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
        close_remote(remote);
    }
}

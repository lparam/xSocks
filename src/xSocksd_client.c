#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "xSocksd.h"


static void client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void client_send_cb(uv_write_t *req, int status);
static void client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


struct client_context *
new_client() {
    struct client_context *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->stage = XSTAGE_REQUEST;
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
verify_request(uint8_t *buf, ssize_t buflen) {
    size_t len;
    static uint16_t portlen = 2;
    struct xSocks_request *req = (struct xSocks_request *)buf;

    if (req->atyp == ATYP_IPV4) {
        len = sizeof(struct xSocks_request) + sizeof(struct in_addr) + portlen;
    } else if (req->atyp == ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(req->addr);
        len = sizeof(struct xSocks_request) + 1 + namelen + portlen;
    } else if (req->atyp == ATYP_IPV6) {
        len = sizeof(struct xSocks_request) + sizeof(struct in6_addr) + portlen;
    } else {
        logger_log(LOG_ERR, "unsupported address type: 0x%02x", req->atyp);
        len = 0;
    }

    return len == buflen;
}

static int
analyse_request_addr(struct xSocks_request *req, struct sockaddr *dest, char *dest_buf, char *host) {
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } addr;
    int addrlen;
    uint16_t portlen = 2; // network byte order port number, 2 bytes

    memset(&addr, 0, sizeof(addr));

    if (req->atyp == ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr); // 4 bytes for IPv4 address
        addr.addr4.sin_family = AF_INET;
        memcpy(&addr.addr4.sin_addr, req->addr, in_addr_len);
        memcpy(&addr.addr4.sin_port, req->addr + in_addr_len, portlen);

        uv_inet_ntop(AF_INET, (const void *)(req->addr), dest_buf, INET_ADDRSTRLEN);
        uint16_t port = read_size((uint8_t*)(req->addr + in_addr_len));
        sprintf(dest_buf, "%s:%u", dest_buf, port);

        addrlen = 4 + portlen;

    } else if (req->atyp == ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(req->addr); // 1 byte of name length
        if (namelen > 0xFF) {
            return 0;
        }
        memcpy(&addr.addr4.sin_port, req->addr + 1 + namelen, portlen);

        memcpy(host, req->addr + 1, namelen);
        host[namelen] = '\0';
        memcpy(dest_buf, req->addr + 1, namelen);
        uint16_t port = read_size((uint8_t*)(req->addr + 1 + namelen));
        sprintf(dest_buf, "%s:%u", dest_buf, port);

        addrlen = 1 + namelen + portlen;

    } else if (req->atyp == ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr); // 16 bytes for IPv6 address
        memcpy(&addr.addr6.sin6_addr, req->addr, in6_addr_len);
        memcpy(&addr.addr6.sin6_port, req->addr + in6_addr_len, portlen);

        uv_inet_ntop(AF_INET6, (const void *)(req->addr), dest_buf, INET_ADDRSTRLEN);
        uint16_t port = read_size((uint8_t*)(req->addr + in6_addr_len));
        sprintf(dest_buf, "%s:%u", dest_buf, port);

        addrlen = 16 + portlen;

    } else {
        return 0;
    }

    memcpy(dest, &addr.addr, sizeof(struct sockaddr));
    return addrlen;
}

void
receive_from_client(struct client_context *client) {
    packet_reset(&client->packet);
    client->handle.stream.data = client;
    uv_read_start(&client->handle.stream, client_alloc_cb, client_recv_cb);
}

void
forward_to_client(struct client_context *client, uint8_t *buf, int buflen) {
    buf -= HEADER_BYTES;
    write_size(buf, buflen);
    buflen += HEADER_BYTES;
    uv_buf_t data = uv_buf_init((char*)buf, buflen);
    client->write_req.data = client;
    uv_write(&client->write_req, &client->handle.stream, &data, 1, client_send_cb);
}

static int
request_start(struct client_context *client) {
    char host[256] = {0};
    uint16_t *portbuf; // avoid Wstrict-aliasing
    struct remote_context *remote = client->remote;
    struct xSocks_request *request = (struct xSocks_request *)client->packet.buf;

    int addrlen = analyse_request_addr(request, &remote->addr, client->target_addr, host);
    if (addrlen < 1) {
        logger_log(LOG_ERR, "unsupported address type: 0x%02x", request->atyp);
        close_client(client);
        close_remote(remote);
        return 1;
    }
    assert(strlen(client->target_addr) > 2);

    switch (request->atyp) {
        case ATYP_IPV4:
        case ATYP_IPV6:
            if (verbose) {
                logger_log(LOG_INFO, "connect to %s", client->target_addr);
            }
            connect_to_remote(remote);
            break;

        case ATYP_HOST:
            portbuf = ((uint16_t *)(client->packet.buf + 1 + addrlen - 2));
            resolve_remote(remote, host, *portbuf);
            break;

        default:
            break;
    }

    return 0;
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct client_context *client = handle->data;
    struct packet *packet = &client->packet;
    if (packet->size) {
        buf->base = (char*)packet->buf + packet->offset;
        buf->len = packet->size - packet->offset;
    } else {
        buf->base = (char*)packet->buf + (packet->read ? 1 : 0);
        buf->len = packet->read ? 1 : HEADER_BYTES;
    }
}

static void
client_send_cb(uv_write_t *req, int status) {
    struct client_context *client = req->data;
    struct remote_context *remote = client->remote;

    if (status == 0) {
        if (client->stage == XSTAGE_FORWARD) {
            receive_from_remote(remote);
        }

    } else {
        char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
        logger_log(LOG_ERR, "%s -> %s:%d failed: %s", client->target_addr, addrbuf, port, uv_strerror(status));
    }
}

static void
client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client_context *client = stream->data;
    struct remote_context *remote = client->remote;

    if (nread > 0) {
        reset_timer(remote);
        struct packet *packet = &client->packet;
        int rc = packet_filter(packet, buf->base, nread);
        if (rc == PACKET_UNCOMPLETE) {
            return;
        } else if (rc == PACKET_INVALID) {
            goto error;
        }

        int clen = packet->size;
        int mlen = packet->size - PRIMITIVE_BYTES;
        uint8_t *c = packet->buf, *m = packet->buf;

        int err = crypto_decrypt(m, c, clen);
        if (err) {
            goto error;
        }

        uv_read_stop(stream);

        switch (client->stage) {
        case XSTAGE_REQUEST:
            if (verify_request(m, mlen)) {
                if (request_start(client)) {
                    goto error;
                }
            } else {
                goto error;
            }
            break;

        case XSTAGE_FORWARD:
            forward_to_remote(remote, m, mlen);
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

    return;

error:
    logger_log(LOG_ERR, "invalid tcp packet");
    close_client(client);
    close_remote(remote);
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
        reset_timer(remote);
        receive_from_client(client);
    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
        close_remote(remote);
    }
}

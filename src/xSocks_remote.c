#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "xSocks.h"


static void remote_send_cb(uv_write_t *req, int status);
static void remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


static void
remote_timer_expire(uv_timer_t *handle) {
    struct remote_context *remote = handle->data;
    struct client_context *client = remote->client;
    if (verbose) {
        if (client->cmd == S5_CMD_UDP_ASSOCIATE) {
            logger_log(LOG_WARNING, "udp assocation timeout");
        } else {
            char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
            uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
            if (client->stage == XSTAGE_FORWARD) {
                logger_log(LOG_WARNING, "%s:%d <-> %s timeout", addrbuf, port, client->target_addr);
            } else {
                logger_log(LOG_WARNING, "%s:%d timeout", addrbuf, port);
            }
        }
    }

    assert(client->stage != XSTAGE_TERMINATE);
    request_ack(client, S5_REP_TTL_EXPIRED);
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
new_remote(uint16_t timeout, struct sockaddr *addr) {
    struct remote_context *remote = malloc(sizeof(*remote));
    memset(remote, 0, sizeof(*remote));
    remote->stage = XSTAGE_HANDSHAKE;
    remote->timer = malloc(sizeof(uv_timer_t));
    remote->idle_timeout = timeout;
    remote->addr = addr ? *addr : server_addr;
    return remote;
}

static void
free_remote(struct remote_context *remote) {
    remote->client = NULL;
    free(remote);
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
    if (remote == NULL) return;
    assert(uv_is_closing(&remote->handle.handle) == 0);

    remote->timer->data = NULL;
    uv_close((uv_handle_t *)remote->timer, timer_close_cb);

    remote->timer = NULL;
    remote->stage = XSTAGE_DEAD;

    remote->handle.handle.data = remote;
    uv_close(&remote->handle.handle, remote_close_cb);
}

static void
forward_client_request_packet(struct remote_context *remote, struct client_context *client) {
    int clen = client->buflen + PRIMITIVE_BYTES;
    uint8_t *c = client->buf + HEADER_BYTES;
    int rc = crypto_encrypt(c, client->buf + OVERHEAD_BYTES, client->buflen);
    if (!rc) {
        forward_to_remote(remote, c, clen);
    }
}

static void
remote_connect_cb(uv_connect_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        if (!remote->direct) {
            forward_client_request_packet(remote, client);
        }

        remote->stage = XSTAGE_FORWARD;
        reset_timer(remote);
        receive_from_client(client);
        receive_from_remote(remote);

    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "connect to remote failed: %s", uv_strerror(status));
            request_ack(client, S5_REP_HOST_UNREACHABLE);
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
    uv_buf_t data;

    if (remote->direct) {
        data = uv_buf_init((char*)buf, buflen);
        remote->write_req.data = remote;
        uv_write(&remote->write_req, &remote->handle.stream, &data, 1, remote_send_cb);

    } else {
        buf -= HEADER_BYTES;
        write_size(buf, buflen);
        buflen += HEADER_BYTES;
        data = uv_buf_init((char*)buf, buflen);
        remote->write_req.data = remote;
        uv_write(&remote->write_req, &remote->handle.stream, &data, 1, remote_send_cb);
    }
}

void
connect_to_remote(struct remote_context *remote) {
    remote->stage = XSTAGE_CONNECT;
    remote->connect_req.data = remote;

    int rc = uv_tcp_connect(&remote->connect_req, &remote->handle.tcp, &remote->addr, remote_connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "connect to remote error: %s", uv_strerror(rc));
        request_ack(remote->client, S5_REP_NETWORK_UNREACHABLE);
    }
}

static void
remote_send_cb(uv_write_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        receive_from_client(client);
    } else {
        logger_log(LOG_ERR, "forward to remote failed: %s", uv_strerror(status));
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
        if (remote->direct) {
            uv_read_stop(&remote->handle.stream);
            forward_to_client(client, (uint8_t*)buf->base, nread);

        } else {
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
        }

    } else if (nread < 0){
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "receive from %s failed: %s", client->target_addr, uv_strerror(nread));
        }
        goto destroy;
    }

    return;

error:
    logger_log(LOG_ERR, "invalid tcp packet");
destroy:
    close_client(client);
    close_remote(remote);
}

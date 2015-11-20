#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "socks.h"
#include "xForwarder.h"


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

void
receive_from_client(struct client_context *client) {
    client->handle.stream.data = client;
    uv_read_start(&client->handle.stream, client_alloc_cb, client_recv_cb);
}

void
forward_to_client(struct client_context *client, uint8_t *buf, int buflen) {
    uv_buf_t reply = uv_buf_init((char*)buf, buflen);
    client->write_req.data = client;
    uv_write(&client->write_req, &client->handle.stream, &reply, 1, client_send_cb);
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
        if (client->stage == XSTAGE_FORWARD) {
            receive_from_remote(remote);
        }

    } else {
        if (verbose) {
            logger_log(LOG_ERR, "forward to client failed: %s", uv_strerror(status));
        }
    }
}

static void
client_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct client_context *client = stream->data;
    struct remote_context *remote = client->remote;

    if (nread > 0) {
        uv_read_stop(&client->handle.stream);
        int clen = nread + PRIMITIVE_BYTES;
        uint8_t *c = client->buf + HEADER_BYTES;
        int rc = crypto_encrypt(c, (uint8_t*)buf->base, nread);
        if (rc) {
            logger_log(LOG_ERR, "invalid packet");
            close_client(client);
            close_remote(remote);
        } else {
            forward_to_remote(remote, c, clen);
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "receive from server failed: %s", uv_strerror(nread));
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
        reset_timer(remote);
        connect_to_remote(remote);
    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
        close_remote(remote);
    }
}

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "xSocksd.h"


static void remote_send_cb(uv_write_t *req, int status);
static void remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);


static void
remote_timer_expire(uv_timer_t *handle) {
    struct remote_context *remote = handle->data;
    struct client_context *client = remote->client;
    if (verbose) {
        char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
        if (client->stage < XSTAGE_FORWARD) {
            logger_log(LOG_WARNING, "%s:%d timeout", addrbuf, port);
        } else {
            logger_log(LOG_WARNING, "%s:%d <-> %s timeout", addrbuf, port, client->target_addr);
        }
    }
    close_client(remote->client);
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
    buf->base = (char*)(remote->buf + OVERHEAD_BYTES);
    buf->len = sizeof(remote->buf) - OVERHEAD_BYTES;
}

static void
remote_close_cb(uv_handle_t *handle) {
    struct remote_context *remote = handle->data;
    free_remote(remote);
}

void
close_remote(struct remote_context *remote) {
    if (remote->stage == XSTAGE_RESOLVE) {
        resolver_cancel(remote->host_query);
    }

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

        receive_from_client(client);
        receive_from_remote(remote);

    } else {
        if (status != UV_ECANCELED) {
            // TODO: handle RST
            logger_log(LOG_ERR, "connect to %s failed: %s", client->target_addr, uv_strerror(status));
            close_client(client);
            close_remote(remote);
        }
    }
}

void
receive_from_remote(struct remote_context *remote) {
    remote->handle.stream.data = remote;
    uv_read_start(&remote->handle.stream, remote_alloc_cb, remote_recv_cb);
}

void
forward_to_remote(struct remote_context *remote, uint8_t *buf, int buflen) {
    uv_buf_t request = uv_buf_init((char*)buf, buflen);
    remote->write_req.data = remote;
    uv_write_t *write_req = malloc(sizeof(*write_req));
    write_req->data = remote;
    uv_write(write_req, &remote->handle.stream, &request, 1, remote_send_cb);
}

void
connect_to_remote(struct remote_context *remote) {
    remote->stage = XSTAGE_CONNECT;
    remote->connect_req.data = remote;
    int rc = uv_tcp_connect(&remote->connect_req, &remote->handle.tcp, &remote->addr, remote_connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "connect to %s error: %s", remote->client->target_addr, uv_strerror(rc));
        close_client(remote->client);
        close_remote(remote);
    }
}

static void
resolve_cb(struct sockaddr *addr, void *data) {
    struct remote_context *remote = data;

    if (addr == NULL) {
        logger_log(LOG_ERR, "resolve %s failed: %s",
          remote->client->target_addr, resolver_error(remote->host_query));
        remote->stage = XSTAGE_TERMINATE;
        close_client(remote->client);
        close_remote(remote);

    } else {
        if (verbose) {
            logger_log(LOG_INFO, "connect to %s", remote->client->target_addr);
        }
        remote->addr = *addr;
        connect_to_remote(remote);
    }
}

void
resolve_remote(struct remote_context *remote, char *host, uint16_t port) {
    if (verbose) {
        logger_log(LOG_INFO, "resolve %s", host);
    }
    struct resolver_context *dns = uv_key_get(&thread_resolver_key);
    remote->stage = XSTAGE_RESOLVE;
    remote->host_query = resolver_query(dns, host, port, resolve_cb, remote);
    if (remote->host_query == NULL) {
        remote->stage = XSTAGE_TERMINATE;
        close_client(remote->client);
        close_remote(remote);
    }
}

static void
remote_send_cb(uv_write_t *req, int status) {
    struct remote_context *remote = (struct remote_context *)req->data;
    struct client_context *client = remote->client;

    if (status == 0) {
        receive_from_client(client);

    } else {
        char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t port = ip_name(&client->addr, addrbuf, sizeof addrbuf);
        logger_log(LOG_ERR, "%s:%d -> failed: %s", addrbuf, port, client->target_addr, uv_strerror(status));
    }

    free(req);
}

static void
remote_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct remote_context *remote;
    struct client_context *client;

    remote = stream->data;
    client = remote->client;

    if (nread > 0) {
        reset_timer(remote);
        uv_read_stop(&remote->handle.stream);
        int clen = nread + PRIMITIVE_BYTES;
        uint8_t *c = remote->buf + HEADER_BYTES;
        int rc = crypto_encrypt(c, (uint8_t*)buf->base, nread);
        if (!rc) {
            forward_to_client(client, c, clen);
        } else {
            logger_log(LOG_ERR, "invalid tcp packet");
            close_client(client);
            close_remote(remote);
        }

    } else if (nread < 0){
        if (nread != UV_EOF) {
            logger_log(LOG_ERR, "receive from %s failed: %s", client->target_addr, uv_strerror(nread));
        }
        close_client(client);
        close_remote(remote);
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#include <netinet/in.h>
#include <linux/netfilter_ipv4.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "common.h"
#include "crypto.h"
#include "socks.h"
#include "xTproxy.h"


#define SO_ORIGINAL_DST_IPV6 80

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
        if (nread != UV_EOF && verbose) {
            logger_log(LOG_ERR, "receive from server failed: %s", uv_strerror(nread));
        }
        close_client(client);
        close_remote(remote);
    }
}

static int
getdestaddr(int fd, struct sockaddr *destaddr, sa_family_t family) {
    socklen_t socklen = sizeof(*destaddr);
    if (family == AF_INET6) {
        return getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST_IPV6, destaddr, &socklen);
    } else {
        return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
    }
}

void
client_accept_cb(uv_stream_t *handle, int status) {
    struct server_context *server = container_of(handle, struct server_context, tcp);
    struct client_context *client = new_client();
    struct remote_context *remote = new_remote(idle_timeout);

    client->remote = remote;
    remote->client = client;
    remote->server_addr = server->server_addr;

    uv_timer_init(handle->loop, remote->timer);

    uv_tcp_init(handle->loop, &client->handle.tcp);
    uv_tcp_init(handle->loop, &remote->handle.tcp);

    int rc = uv_accept(handle, &client->handle.stream);

    uv_os_fd_t fd;
    uv_fileno(&client->handle.handle, &fd);
    int err = getdestaddr(fd, &client->target_addr, server->local_addr->sa_family);
    if (err) {
        logger_log(LOG_ERR, "get original destination error: %s", strerror(errno));
        exit(1);
        return;
    }

    if (rc == 0) {
        reset_timer(remote);
        if (verbose) {
            char addrbuf[INET6_ADDRSTRLEN + 1] = {0};
            int port = ip_name(&client->target_addr, addrbuf, sizeof(addrbuf));
            logger_log(LOG_INFO, "connect to %s:%d", addrbuf, port);
        }
        connect_to_remote(remote);

    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_client(client);
        close_remote(remote);
    }
}

#include <stdlib.h>
#include <string.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "common.h"
#include "socks.h"
#include "packet.h"
#include "cache.h"


#define KEY_BYTES 32U
#define IPV4_HEADER_LEN 7
#define IPV6_HEADER_LEN 19

struct client_context {
    struct sockaddr addr;
    uv_udp_t *local_handle;
    uv_udp_t server_handle;
    uv_timer_t *timer;
    char key[KEY_BYTES + 1];
};

extern uint16_t idle_timeout;
static int addrlen = IPV4_HEADER_LEN;

static void free_cb(void *element);
static int select_cb(void *element, void *opaque);
static void client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void client_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);

#include "udprelay.c"

static void
timer_expire(uv_timer_t *handle) {
    struct client_context *client = handle->data;
    uv_mutex_lock(&mutex);
    cache_remove(cache, client->key);
    uv_mutex_unlock(&mutex);
}

static void
timer_close_cb(uv_handle_t *handle) {
    free(handle);
}

static void
reset_timer(struct client_context *client) {
    client->timer->data = client;
    uv_timer_start(client->timer, timer_expire, idle_timeout * 1000, 0);
}

static struct client_context *
new_client() {
    struct client_context *client = malloc(sizeof(*client));
    memset(client, 0, sizeof(*client));
    client->timer = malloc(sizeof(uv_timer_t));
    return client;
}

static void
client_close_cb(uv_handle_t *handle) {
    struct client_context *client = container_of(handle, struct client_context, server_handle);
    free(client);
}

static void
close_client(struct client_context *client) {
    uv_close((uv_handle_t *)client->timer, timer_close_cb);
    if (!uv_is_closing((uv_handle_t *)&client->server_handle)) {
        uv_close((uv_handle_t *)&client->server_handle, client_close_cb);
    } else {
        free(client);
    }
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *buffer = malloc(suggested_size);
    buf->base = buffer + PRIMITIVE_BYTES + addrlen;
    buf->len = suggested_size - PRIMITIVE_BYTES - addrlen;
}

static void
server_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void
client_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "[udp] forward to client failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base);
    free(req);
}


static void
forward_to_client(struct client_context *client, uint8_t *data, ssize_t len) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = client;
    uv_udp_send(write_req, client->local_handle, buf, 1, &client->addr, client_send_cb);
}

/*
 *
 * xSocks UDP Response
 * +------+----------+----------+----------+
 * | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +------+----------+----------+----------+
 * |  1   | Variable |    2     | Variable |
 * +------+----------+----------+----------+
 *
 */
static void
server_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        struct client_context *client = handle->data;
        reset_timer(client);

        int mlen = nread - PRIMITIVE_BYTES;
        uint8_t *m = (uint8_t *)buf->base;
        int rc = crypto_decrypt(m, (uint8_t *)buf->base, nread);
        if (rc) {
            logger_log(LOG_ERR, "invalid packet");
            goto err;
        }

        memmove(m, m + addrlen, mlen - addrlen);
        mlen -= addrlen;

        forward_to_client(client, m , mlen);

    } else {
        goto err;
    }

    return;

err:
    free(buf->base);
}

static void
server_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        logger_log(LOG_ERR, "[udp] forward to server failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base);
    free(req);
}

/*
 *
 * xSocks UDP Request
 * +------+----------+----------+----------+
 * | ATYP | DST.ADDR | DST.PORT |   DATA   |
 * +------+----------+----------+----------+
 * |  1   | Variable |    2     | Variable |
 * +------+----------+----------+----------+
 *
 */
static void
forward_to_server(struct sockaddr *server_addr, struct client_context *client, uint8_t *data, ssize_t datalen) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = datalen;
    write_req->data = client;;
    uv_udp_send(write_req, &client->server_handle, buf, 1, server_addr, server_send_cb);
}

static void
client_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    struct server_context *server = container_of(handle, struct server_context, udp);
    if (server->dest_addr->sa_family == AF_INET6) {
        addrlen = IPV6_HEADER_LEN;
    }
    if (nread > 0) {
        char key[KEY_BYTES + 1] = {0};
        crypto_generickey((uint8_t *)key, sizeof(key) -1, (uint8_t*)addr, sizeof(*addr), NULL, 0);

        struct client_context *client = NULL;
        uv_mutex_lock(&mutex);
        cache_lookup(cache, key, (void *)&client);
        uv_mutex_unlock(&mutex);

        if (client == NULL) {
            client = new_client();
            client->addr = *addr;
            client->local_handle = handle;
            memcpy(client->key, key, sizeof(key));
            uv_timer_init(handle->loop, client->timer);
            uv_udp_init(handle->loop, &client->server_handle);
            client->server_handle.data = client;
            uv_udp_recv_start(&client->server_handle, server_alloc_cb, server_recv_cb);
            uv_mutex_lock(&mutex);
            cache_insert(cache, client->key, (void *)client);
            uv_mutex_unlock(&mutex);
        }

        int clen = nread + PRIMITIVE_BYTES + addrlen;
        int mlen = nread + addrlen;
        uint8_t *c = (uint8_t *)buf->base - PRIMITIVE_BYTES - addrlen;
        uint8_t *m = (uint8_t *)buf->base - addrlen;

        if (server->dest_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)server->dest_addr;
            m[0] = 1;
            memcpy(m + 1, &addr->sin_addr, 4);
            memcpy(m + 1 + 4, &addr->sin_port, 2);
        } else {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)server->dest_addr;
            m[0] = 4;
            memcpy(m + 1, &addr->sin6_addr, 16);
            memcpy(m + 1 + 16, &addr->sin6_port, 2);
        }

        int rc = crypto_encrypt(c, m, mlen);
        if (!rc) {
            reset_timer(client);
            forward_to_server(server->server_addr, client, c, clen);
        }

    } else {
        goto error;
    }

    return;

error:
    free(buf->base - addrlen - PRIMITIVE_BYTES);
}

static void
free_cb(void *element) {
    struct client_context *client = (struct client_context *)element;
    close_client(client);
}

static int
select_cb(void *element, void *opaque) {
    struct client_context *client = (struct client_context *)element;
    if (client->local_handle->loop == opaque) {
        return 1;
    }
    return 0;
}

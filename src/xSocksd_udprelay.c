#include <stdlib.h>
#include <string.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "common.h"
#include "crypto.h"
#include "socks.h"
#include "packet.h"
#include "cache.h"
#include "resolver.h"


#define KEY_BYTES 32U
#define IPV4_HEADER_LEN 7
#define IPV6_HEADER_LEN 19

struct target_context {
    uv_udp_t                target_handle;
    uv_udp_t               *server_handle;
    struct sockaddr         client_addr;
    struct sockaddr         dest_addr;
    uint16_t                dest_port;
    uv_timer_t             *timer;
    struct resolver_query  *host_query;
    int                     header_len;
    uint8_t                *buf;
    ssize_t                 buflen;
    char                    key[KEY_BYTES + 1];
};

extern int verbose;
extern uint16_t idle_timeout;
extern uv_key_t thread_resolver_key;

static void free_cb(void *element);
static int select_cb(void *element, void *opaque);
static void client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void client_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);

#include "udprelay.c"

static void
timer_expire(uv_timer_t *handle) {
    struct target_context *target = handle->data;
    uv_mutex_lock(&mutex);
    cache_remove(cache, target->key);
    uv_mutex_unlock(&mutex);
}

static void
timer_close_cb(uv_handle_t *handle) {
    free(handle);
}

static void
reset_timer(struct target_context *target) {
    target->timer->data = target;
    uv_timer_start(target->timer, timer_expire, idle_timeout * 1000, 0);
}


struct target_context *
new_target() {
    struct target_context *target = malloc(sizeof(*target));
    memset(target, 0, sizeof(*target));
    target->timer = malloc(sizeof(uv_timer_t));
    return target;
}

static void
target_close_cb(uv_handle_t *handle) {
    struct target_context *target = container_of(handle, struct target_context, target_handle);
    free(target);
}

static void
close_target(struct target_context *target) {
    uv_close((uv_handle_t *)target->timer, timer_close_cb);
    if (!uv_is_closing((uv_handle_t *)&target->target_handle)) {
        uv_close((uv_handle_t *)&target->target_handle, target_close_cb);
    } else {
        free(target);
    }
}

static void
target_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct target_context *target = handle->data;
    buf->base = malloc(suggested_size) + PRIMITIVE_BYTES + target->header_len;
    buf->len = suggested_size - PRIMITIVE_BYTES - target->header_len;
}

static void
client_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
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
forward_to_client(struct target_context *target, uint8_t *data, ssize_t len) {
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = target;
    uv_udp_send(write_req, target->server_handle, buf, 1, &target->client_addr, client_send_cb);
}

static void
target_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    struct target_context *target = handle->data;
    if (nread > 0) {
        reset_timer(target);
        int mlen = target->header_len + nread;
        uint8_t *m = (uint8_t *)buf->base - target->header_len;

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
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
            m[0] = 1;
            memcpy(m + 1, &addr4->sin_addr, 4);
            memcpy(m + 1 + 4, &addr4->sin_port, 2);
        } else {
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
            m[0] = 4;
            memcpy(m + 1, &addr6->sin6_addr, 16);
            memcpy(m + 1 + 16, &addr6->sin6_port, 2);
        }

        int clen = PRIMITIVE_BYTES + target->header_len + nread;
        uint8_t *c = (uint8_t *)buf->base - target->header_len - PRIMITIVE_BYTES;
        int rc = crypto_encrypt(c, m, mlen);
        if (!rc) {
            if (verbose) {
                char src[INET6_ADDRSTRLEN + 1] = {0};
                char dst[INET6_ADDRSTRLEN + 1] = {0};
                uint16_t src_port = 0, dst_port = 0;
                src_port = ip_name(addr, src, sizeof src);
                dst_port = ip_name(&target->client_addr, dst, sizeof dst);
                logger_log(LOG_INFO, "%s:%d <- %s:%d", dst, dst_port, src, src_port);
            }
            forward_to_client(target, c, clen);
        }

    } else {
        free(buf->base - target->header_len - PRIMITIVE_BYTES);
    }
}

static void
target_send_cb(uv_udp_send_t *req, int status) {
    if (status) {
        // TODO: close target
        logger_log(LOG_ERR, "[udp] forward to target failed: %s", uv_strerror(status));
    }
    uv_buf_t *buf = (uv_buf_t *)(req + 1);
    free(buf->base);
    free(req);
}

static void
forward_to_target(struct target_context *target, uint8_t *data, ssize_t len) {
    if (verbose) {
        char src[INET6_ADDRSTRLEN + 1] = {0};
        char dst[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t src_port = 0, dst_port = 0;
        src_port = ip_name(&target->client_addr, src, sizeof src);
        dst_port = ip_name(&target->dest_addr, dst, sizeof dst);
        logger_log(LOG_INFO, "%s:%d -> %s:%d", src, src_port, dst, dst_port);
    }
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = target;
    uv_udp_send(write_req, &target->target_handle, buf, 1, &target->dest_addr, target_send_cb);
}

static void
resolve_cb(struct sockaddr *addr, void *data) {
    struct target_context *target = data;
    if (addr) {
        target->header_len = addr->sa_family == AF_INET ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        target->dest_addr = *addr;
        forward_to_target(target, target->buf, target->buflen);

    } else {
        free(target->buf);
        logger_log(LOG_ERR, "[udp] resolve failed: %s", resolver_error(target->host_query));
    }
}

static void
resolve_target(struct target_context *target, char *host, uint16_t port) {
    if (verbose) {
        logger_log(LOG_INFO, "resolve %s", host);
    }
    struct resolver_context *dns = uv_key_get(&thread_resolver_key);
    target->host_query = resolver_query(dns, host, port, resolve_cb, target);
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
client_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        int mlen = nread - PRIMITIVE_BYTES;
        uint8_t *m = (uint8_t *)buf->base;
        int rc = crypto_decrypt(m, (uint8_t *)buf->base, nread);
        if (rc) {
            logger_log(LOG_ERR, "invalid udp packet");
            goto err;
        }

        char host[256] = {0};
        struct sockaddr dest_addr;
        struct xSocks_request *request = (struct xSocks_request *)m;
        int addrlen = parse_target_address(request, &dest_addr, host);
        if (addrlen < 1) {
            logger_log(LOG_ERR, "unsupported address type: 0x%02x", request->atyp);
            goto err;
        }

        uint16_t port = (*(uint16_t *)(m + 1 + addrlen - 2));

        char key[KEY_BYTES + 1] = {0};
        crypto_generickey((uint8_t *)key, sizeof(key) -1, (uint8_t*)addr, sizeof(*addr), NULL, 0);

        struct target_context *target = NULL;
        uv_mutex_lock(&mutex);
        cache_lookup(cache, key, (void *)&target);
        uv_mutex_unlock(&mutex);
        if (target == NULL) {
            if (verbose) {
                cache_log(request->atyp, addr, &dest_addr, host, port, 0);
            }

            target = new_target();
            target->client_addr = *addr;
            target->server_handle = handle;
            memcpy(target->key, key, sizeof(key));

            uv_timer_init(handle->loop, target->timer);

            uv_udp_init(handle->loop, &target->target_handle);
            target->target_handle.data = target;
            rc = uv_udp_recv_start(&target->target_handle, target_alloc_cb, target_recv_cb);
            if (rc) {
                logger_stderr("listen udp target error: %s", uv_strerror(rc));
            }

            uv_mutex_lock(&mutex);
            cache_insert(cache, target->key, (void *)target);
            uv_mutex_unlock(&mutex);
        } else {
            if (verbose) {
                cache_log(request->atyp, addr, &dest_addr, host, port, 1);
            }
        }
        reset_timer(target);

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
        uint8_t atyp = request->atyp;
        mlen -= 1 + addrlen;
        memmove(m, m + 1 + addrlen, mlen);

        switch (atyp) {

        case ATYP_IPV4:
        case ATYP_IPV6:
            target->header_len = dest_addr.sa_family == AF_INET ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
            target->dest_addr = dest_addr;
            forward_to_target(target, m, mlen);
            break;

        case ATYP_HOST:
            target->buf = m;
            target->buflen = mlen;
            resolve_target(target, host, port);
            break;

        default:
            break;
        }

        return;

    } else {
        goto err;
    }

err:
    free(buf->base);
}

static void
free_cb(void *element) {
    struct target_context *target = (struct target_context *)element;
    close_target(target);
}

static int
select_cb(void *element, void *opaque) {
    struct target_context *target = (struct target_context *)element;
    if (target->server_handle->loop == opaque) {
        return 1;
    }
    return 0;
}

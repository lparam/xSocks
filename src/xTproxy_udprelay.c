#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "common.h"
#include "crypto.h"
#include "socks.h"
#include "packet.h"
#include "cache.h"


#define KEY_BYTES 32U
#define IPV4_HEADER_LEN 7
#define IPV6_HEADER_LEN 19

#define IP_TRANSPARENT 19
#define IP_ORIGDSTADDR 20
#define IP_RECVORIGDSTADDR IP_ORIGDSTADDR

struct client_context {
    int bind_server;
    struct sockaddr addr;
    struct sockaddr dest_addr;
    uv_udp_t server_handle;
    uv_udp_t *dest_handle;
    uv_timer_t *timer;
    char key[KEY_BYTES + 1];
};

extern int verbose;
extern uint16_t idle_timeout;
static uv_mutex_t mutex;
static struct cache *cache;

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
dest_close_cb(uv_handle_t *handle) {
    free(handle);
}

static void
client_close_cb(uv_handle_t *handle) {
    struct client_context *client = container_of(handle, struct client_context, server_handle);
    free(client);
}

static void
close_client(struct client_context *client) {
    uv_close((uv_handle_t *)client->timer, timer_close_cb);
    if (client->dest_handle) {
        uv_close((uv_handle_t *)client->dest_handle, dest_close_cb);
    }
    uv_close((uv_handle_t *)&client->server_handle, client_close_cb);
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
    if (verbose) {
        char src[INET6_ADDRSTRLEN + 1] = {0};
        char dst[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t dst_port = 0, src_port = 0;
        src_port = ip_name(&client->dest_addr, src, sizeof src);
        dst_port = ip_name(&client->addr, dst, sizeof dst);
        logger_log(LOG_INFO, "%s:%d <- %s:%d", dst, dst_port, src, src_port);
    }
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = len;
    write_req->data = client;
    uv_udp_send(write_req, client->dest_handle, buf, 1, &client->addr, client_send_cb);
}

static void
server_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    if (nread > 0) {
        struct client_context *client = handle->data;
        reset_timer(client);

        int mlen = nread - PRIMITIVE_BYTES;
        uint8_t *m = (uint8_t *)buf->base;
        int rc = crypto_decrypt(m, (uint8_t *)buf->base, nread);
        if (rc) {
            logger_log(LOG_ERR, "invalid udp packet");
            goto err;
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
        union {
            struct sockaddr addr;
            struct sockaddr_in addr4;
            struct sockaddr_in6 addr6;
        } dest_addr;
        if (m[0] == ATYP_IPV4) {
            dest_addr.addr4.sin_family = AF_INET;
            memcpy(&dest_addr.addr4.sin_addr, m + 1, 4);
            memcpy(&dest_addr.addr4.sin_port, m + 5, 2);

        } else {
            dest_addr.addr6.sin6_family = AF_INET6;
            memcpy(&dest_addr.addr6.sin6_addr, m + 1, 16);
            memcpy(&dest_addr.addr6.sin6_port, m + 17, 2);
        }

        int addrlen = m[0] == ATYP_IPV4 ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;
        memmove(m, m + addrlen, mlen - addrlen);
        mlen -= addrlen;

        if (!client->bind_server) {
            uv_os_sock_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if (sock < 0) {
                logger_stderr("socket error: %s\n", strerror(errno));
            }
            int yes = 1;
            if (setsockopt(sock, SOL_IP, IP_TRANSPARENT, &yes, sizeof(int))) {
                logger_stderr("setsockop IP_TRANSPARENT error: %s)", strerror(errno));
            }

            client->dest_handle = malloc(sizeof(uv_udp_t));
            uv_udp_init(handle->loop, client->dest_handle);
            rc = uv_udp_open(client->dest_handle, sock);
            if (rc) {
                logger_stderr("udp open error: %s", uv_strerror(rc));
            }
            rc = uv_udp_bind(client->dest_handle, &dest_addr.addr, UV_UDP_REUSEADDR);
            if (rc) {
                logger_stderr("udp server bind error: %s", uv_strerror(rc));
            }

            client->bind_server = 1;
        }

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

static void
forward_to_server(struct sockaddr *server_addr, struct client_context *client, uint8_t *data, ssize_t datalen) {
    if (verbose) {
        char src[INET6_ADDRSTRLEN + 1] = {0};
        char dst[INET6_ADDRSTRLEN + 1] = {0};
        uint16_t dst_port = 0, src_port = 0;
        src_port = ip_name(&client->addr, src, sizeof src);
        dst_port = ip_name(&client->dest_addr, dst, sizeof dst);
        logger_log(LOG_INFO, "%s:%d -> %s:%d", src, src_port, dst, dst_port);
    }
    uv_udp_send_t *write_req = malloc(sizeof(*write_req) + sizeof(uv_buf_t));
    uv_buf_t *buf = (uv_buf_t *)(write_req + 1);
    buf->base = (char *)data;
    buf->len = datalen;
    write_req->data = client;;
    uv_udp_send(write_req, &client->server_handle, buf, 1, server_addr, server_send_cb);
}

static int
getdestaddr(struct msghdr *msg, struct sockaddr *dstaddr) {
    struct cmsghdr *cmsg;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } addr;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(&addr.addr4, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            addr.addr4.sin_family = AF_INET;
            memcpy(dstaddr, &addr.addr, sizeof(struct sockaddr));
            return 0;

        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(&addr.addr6, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            addr.addr6.sin6_family = AF_INET6;
            memcpy(dstaddr, &addr.addr, sizeof(struct sockaddr));
            return 0;
        }
    }

    return 1;
}

static void
poll_cb(uv_poll_t *watcher, int status, int events) {
 	char buffer[1024] = {0};
    char control_buffer[64] = {0};
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr client_addr;
    struct server_context *server = container_of(watcher, struct server_context, watcher);

    if (status >= 0) {
        msg.msg_name = &client_addr;
        msg.msg_namelen = sizeof(client_addr);
        msg.msg_control = control_buffer;
        msg.msg_controllen = sizeof(control_buffer);
        iov[0].iov_base = buffer;
        iov[0].iov_len = sizeof(buffer);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

        int msglen = recvmsg(watcher->io_watcher.fd, &msg, 0);
        if (msglen <= 0) {
            logger_stderr("receive from client error: %s", strerror(errno));
        }

        struct sockaddr dest_addr;
        if (getdestaddr(&msg, &dest_addr)) {
            logger_stderr("can not get destination address");
        }

        int addrlen = dest_addr.sa_family == AF_INET ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;

        int mlen = addrlen + msglen;
        int clen = PRIMITIVE_BYTES + mlen;
        uint8_t *c = malloc(clen);
        uint8_t *m = c + PRIMITIVE_BYTES;

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
        if (dest_addr.sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)&dest_addr;
            m[0] = ATYP_IPV4;
            memcpy(m + 1, &addr->sin_addr, 4);
            memcpy(m + 1 + 4, &addr->sin_port, 2);

        } else {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&dest_addr;
            m[0] = ATYP_IPV6;
            memcpy(m + 1, &addr->sin6_addr, 16);
            memcpy(m + 1 + 16, &addr->sin6_port, 2);
        }
        memcpy(m + addrlen, buffer, msglen);

        int rc = crypto_encrypt(c, m, mlen);
        if (!rc) {
            char key[KEY_BYTES + 1] = {0};
            crypto_generickey((uint8_t *)key, sizeof(key) -1, (uint8_t *)&client_addr, sizeof(client_addr), NULL, 0);

            struct client_context *client = NULL;
            uv_mutex_lock(&mutex);
            cache_lookup(cache, key, (void *)&client);
            uv_mutex_unlock(&mutex);
            if (client == NULL) {
                client = new_client();
                client->addr = client_addr;
                memcpy(client->key, key, sizeof(key));

                uv_timer_init(watcher->loop, client->timer);

                uv_udp_init(watcher->loop, &client->server_handle);
                client->server_handle.data = client;
                uv_udp_recv_start(&client->server_handle, server_alloc_cb, server_recv_cb);

                uv_mutex_lock(&mutex);
                cache_insert(cache, client->key, (void *)client);
                uv_mutex_unlock(&mutex);
            }

            client->dest_addr = dest_addr;
            reset_timer(client);
            forward_to_server(server->server_addr, client, c, clen);
        }
    }
}

static void
free_cb(void *element) {
    struct client_context *client = (struct client_context *)element;
    close_client(client);
}

static int
select_cb(void *element, void *opaque) {
    struct client_context *client = (struct client_context *)element;
    if (client->server_handle.loop == opaque) {
        return 1;
    }
    return 0;
}

int
udprelay_init() {
    uv_mutex_init(&mutex);
    cache_create(&cache, 1024, free_cb);
    return 0;
}

int
udprelay_start(uv_loop_t *loop, struct server_context *server) {
    int rc, yes = 1;

    if (setsockopt(server->udp_fd, SOL_IP, IP_TRANSPARENT, &yes, sizeof(int))) {
        logger_stderr("setsockopt IP_TRANSPARENT error: %s", strerror(errno));
    }
    if (setsockopt(server->udp_fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &yes, sizeof(int))) {
        logger_stderr("setsockopt IP_RECVORIGDSTADDR error: %s", strerror(errno));
    }

    uv_udp_init(loop, &server->udp);

    if ((rc = uv_udp_open(&server->udp, server->udp_fd))) {
        logger_stderr("udp open error: %s", uv_strerror(rc));
        return 1;
    }

    if ((rc = uv_udp_bind(&server->udp, server->local_addr, UV_UDP_REUSEADDR))) {
        logger_stderr("udp bind error: %s", uv_strerror(rc));
        return 1;
    }

    uv_poll_init_socket(loop, &server->watcher, server->udp_fd);
    uv_poll_start(&server->watcher, UV_READABLE, poll_cb);

    return 0;
}

void
udprelay_close(struct server_context *server) {
    uv_poll_stop(&server->watcher);
    close(server->udp_fd);
    uv_mutex_lock(&mutex);
    cache_removeall(cache, server->udp.loop, select_cb);
    uv_mutex_unlock(&mutex);
}

void
udprelay_destroy() {
    uv_mutex_destroy(&mutex);
    free(cache);
}

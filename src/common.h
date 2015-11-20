#ifndef COMMON_H
#define COMMON_H

#include "uv.h"
#include "socks.h"

#define XSOCKS_VERSION      "0.4.3"

struct server_context {
    int index;
    int udprelay;
    int tcp_fd;
    int udp_fd;
    uv_tcp_t tcp;
    uv_udp_t udp;
    uv_poll_t watcher;
    uv_sem_t semaphore;
    uv_async_t async_handle;
    uv_thread_t thread_id;
    int resolver;
    int nameserver_num;
    char **nameservers;
    uv_connection_cb accept_cb;
    struct sockaddr *dest_addr;
    struct sockaddr *local_addr;
    struct sockaddr *server_addr;
};

struct signal_ctx {
    int signum;
    uv_signal_t sig;
};

int signal_process(char *signal, const char *pidfile);
void consumer_start(void *arg);
int parse_target_address(const struct xSocks_request *req, struct sockaddr *addr, char *host);
void cache_log(uint8_t atyp, const struct sockaddr *src_addr, const struct sockaddr *dst_addr, const char *host, uint16_t port, int hit);
int protect_socket(int fd);

#endif // for #ifndef COMMON_H

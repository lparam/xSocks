#ifndef _COMMON_H
#define _COMMON_H

#include "uv.h"

#define XSOCKS_VERSION      "0.2.1"

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

#endif // for #ifndef _COMMON_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "uv.h"
#include "logger.h"
#include "util.h"
#include "common.h"


struct resolver_context *
resolver_init(uv_loop_t *loop, int mode, char **nameservers, int nameserver_num) __attribute__((weak));
void resolver_shutdown(struct resolver_context *rctx) __attribute__((weak));
void resolver_destroy(struct resolver_context *ctx) __attribute__((weak));

int udprelay_start(uv_loop_t *loop, struct server_context *server) __attribute__((weak));
void udprelay_close(struct server_context *server) __attribute__((weak));

extern void close_loop(uv_loop_t *loop);


static void
consumer_close(uv_async_t *handle) {
    struct server_context *server = container_of(handle, struct server_context, async_handle);

    uv_close((uv_handle_t*) &server->tcp, NULL);
    uv_close((uv_handle_t*) &server->async_handle, NULL);

    if (server->udprelay) {
        udprelay_close(server);
    }

    if (server->nameserver_num >= 0) {
        struct resolver_context *res = handle->loop->data;
        resolver_shutdown(res);
    }
}

static void
tcp_bind(uv_loop_t *loop, struct server_context *server) {
    int rc;

    uv_tcp_init(loop, &server->tcp);

    rc = uv_tcp_open(&server->tcp, server->tcp_fd);
    if (rc) {
        logger_stderr("tcp open error: %s", uv_strerror(rc));
    }

    uv_async_init(loop, &server->async_handle, consumer_close);

    rc = uv_tcp_bind(&server->tcp, server->local_addr, 0);
    if (rc || errno) {
        logger_stderr("bind error: %s", rc ? uv_strerror(rc) : strerror(errno));
        exit(1);
    }

    rc = uv_listen((uv_stream_t*)&server->tcp, SOMAXCONN, server->accept_cb);
    if (rc) {
        logger_stderr("listen error: %s", rc ? uv_strerror(rc) : strerror(errno));
        exit(1);
    }
}

void
consumer_start(void *arg) {
    uv_loop_t loop;
    struct server_context *server = arg;

#ifndef CROSS_COMPILE
    char name[24] = {0};
    sprintf(name, "consumer-%d", server->index + 1);
    pthread_setname_np(pthread_self(), name);
#endif

    uv_loop_init(&loop);

    struct resolver_context *res = NULL;
    if (server->nameserver_num >= 0) {
        res = resolver_init(&loop, 0,
          server->nameserver_num == 0 ? NULL : server->nameservers, server->nameserver_num);
        loop.data = res;
    }

    tcp_bind(&loop, server);

    if (server->udprelay) {
        udprelay_start(&loop, server);
    }

    uv_run(&loop, UV_RUN_DEFAULT);

    close_loop(&loop);

    if (server->nameserver_num >= 0) {
        resolver_destroy(res);
    }

    uv_sem_post(&server->semaphore);
}

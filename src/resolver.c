#define CARES_STATICLIB
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "tree.h"
#include "ares.h"
#include "resolver.h"
#include "util.h"
#include "logger.h"


struct resolver_context {
    uv_loop_t *loop;
    ares_channel channel;
    uv_timer_t timer;
    RB_HEAD(query_task_list, query_task) handles;
};

struct resolver_query {
    dns_host_callback callback;
    void *data;
    uint16_t port;
    int status;
};

struct query_task {
    uv_loop_t *loop;
    ares_socket_t sock;
    uv_poll_t watcher;
    RB_ENTRY(query_task) node;
};


static int
compare_query_tasks(const struct query_task *a, const struct query_task *b) {
    if (a->sock < b->sock) return -1;
    if (a->sock > b->sock) return 1;
    return 0;
}


RB_GENERATE_STATIC(query_task_list, query_task, node, compare_query_tasks)


static void
timer_expire(uv_timer_t *handle) {
    struct resolver_context *dns = container_of(handle, struct resolver_context, timer);
    assert(!RB_EMPTY(&dns->handles));
    ares_process_fd(dns->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}


static void
ares_poll_cb(uv_poll_t *watcher, int status, int events) {
    struct resolver_context *dns = watcher->data;
    struct query_task *task = container_of(watcher, struct query_task, watcher);

    uv_timer_again(&dns->timer);

    if (status >= 0) {
        ares_process_fd(dns->channel,
          events & UV_READABLE ? task->sock : ARES_SOCKET_BAD,
          events & UV_WRITABLE ? task->sock : ARES_SOCKET_BAD);
    } else {
        ares_process_fd(dns->channel, task->sock, task->sock);
    }
}


static void
ares_poll_close_cb(uv_handle_t *watcher) {
    struct query_task *task = container_of(watcher, struct query_task, watcher);
    free(task);
}


static struct query_task *
create_query_task(uv_loop_t *loop, ares_socket_t sock) {
    struct query_task *task = malloc(sizeof *task);

    memset(task, 0, sizeof *task);
    task->loop = loop;
    task->sock = sock;

    uv_poll_init_socket(loop, &task->watcher, sock);

    return task;
}

static void
ares_sockstate_cb(void *data, ares_socket_t sock, int read, int write) {
    struct resolver_context *dns = data;
    struct query_task *task;
    struct query_task lookup_task;

    lookup_task.sock = sock;
    task = RB_FIND(query_task_list, &dns->handles, &lookup_task);

    if (read || write) {
        if (!task) {
            if (!uv_is_active((uv_handle_t*) &dns->timer)) {
                assert(RB_EMPTY(&dns->handles));
                uv_timer_start(&dns->timer, timer_expire, 1000, 1000);
            }

            task = create_query_task(dns->loop, sock);
            RB_INSERT(query_task_list, &dns->handles, task);
        }

        task->watcher.data = dns;
        uv_poll_start(&task->watcher,
          (read ? UV_READABLE : 0) | (write ? UV_WRITABLE : 0), ares_poll_cb);

    } else {
        assert(task);
        RB_REMOVE(query_task_list, &dns->handles, task);
        uv_close((uv_handle_t*) &task->watcher, ares_poll_close_cb);
        if (RB_EMPTY(&dns->handles)) {
            uv_timer_stop(&dns->timer);
        }
    }
}

static void
query_cb(void *arg, int status, int timeouts, struct hostent *hostent) {
    struct resolver_query *query = arg;

    if (query->data == NULL) {
        goto clean;
    }

    if (status == ARES_SUCCESS) {
        struct sockaddr addr;
        memset(&addr, 0, sizeof(addr));
        for (uint32_t i = 0; hostent->h_addr_list[i] != NULL; i++) {
            if (hostent->h_addrtype == AF_INET) {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
                addr4->sin_family = AF_INET;
                addr4->sin_addr = *(const struct in_addr *)hostent->h_addr_list[i];
                addr4->sin_port = query->port;

            } else if (hostent->h_addrtype == AF_INET6) {
                struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
                addr6->sin6_family = AF_INET6;
                addr6->sin6_addr = *(const struct in6_addr *)hostent->h_addr_list[i];
                addr6->sin6_port = query->port;
            }
            break;
        }

        query->callback(&addr, query->data);

    } else {
        query->status = status;
        query->callback(NULL, query->data);
    }

clean:
    free(query);
}

void
resolver_prepare(int nameserver_num) {
    int rc = ares_library_init(ARES_LIB_INIT_ALL);
    assert(rc == ARES_SUCCESS);
}

struct resolver_context *
resolver_init(uv_loop_t *loop, int mode, char **nameservers, int nameserver_num) {
    struct resolver_context *ctx;
    struct ares_options options;
    int optmask;

    ctx = malloc(sizeof(*ctx));
    memset(ctx, 0, sizeof(*ctx));
    ctx->loop = loop;
    uv_timer_init(loop, &ctx->timer);

    memset(&options, 0, sizeof(options));
    options.flags = ARES_FLAG_NOCHECKRESP;
    options.sock_state_cb = ares_sockstate_cb;
    options.sock_state_cb_data = ctx;

    optmask = ARES_OPT_FLAGS | ARES_OPT_SOCK_STATE_CB;

    int rc = ares_init_options(&ctx->channel, &options, optmask);
    if (rc != ARES_SUCCESS) {
        logger_stderr("Cannot create ARES channel for DNS target %s", nameservers);
    }

    if (nameserver_num > 0) {
        struct ares_addr_node *servers = malloc(sizeof(struct ares_addr_node) * nameserver_num);
        struct ares_addr_node *last = NULL;

        for (int i = 0; i < nameserver_num; i++) {
            char *resolver = nameservers[i];
            struct ares_addr_node *cur = &servers[i];
            cur->family = AF_INET;
            rc = ares_inet_pton(AF_INET, resolver, &cur->addr);
            cur->next = NULL;
            if (last != NULL) {
                last->next = cur;
            }
            last = cur;
        }

        rc = ares_set_servers(ctx->channel, &servers[0]);
        if (rc != ARES_SUCCESS) {
            logger_stderr("Cannot select ARES target DNS server %s", nameservers);
        }

        free(servers);
    }

    return ctx;
}

struct resolver_query *
resolver_query(struct resolver_context *ctx, const char *host, uint16_t port, dns_host_callback cb, void *data) {
    struct resolver_query *query = malloc(sizeof(*query));
    memset(query, 0, sizeof(*query));
    query->port = port;
    query->data = data;
    query->callback = cb;
    ares_gethostbyname(ctx->channel, host, AF_INET, &query_cb, query);
    return query;
}

void
resolver_cancel(struct resolver_query *query) {
    query->data = NULL;
}

void
resolver_shutdown(struct resolver_context *ctx) {
    uv_timer_stop(&ctx->timer);
    ares_cancel(ctx->channel);
}

void
resolver_destroy(struct resolver_context *ctx) {
    ares_destroy(ctx->channel);
    ctx->channel = NULL;
    free(ctx);
}

const char *
resolver_error(struct resolver_query *query) {
    return ares_strerror(query->status);
}

#ifndef RESOLVER_H
#define RESOLVER_H

#include <stdint.h>
#include "uv.h"


struct resolver_query;
struct resolver_context;

enum resolver_mode {
    MODE_IPV4,
    MODE_IPV6,
    MODE_IPV4_FIRST,
    MODE_IPV6_FIRST,
};

typedef void (*dns_host_callback)(struct sockaddr *addr, void *data);

void resolver_prepare(int nameserver_num);
struct resolver_context * resolver_init(uv_loop_t *loop, int mode, char **nameservers, int nameserver_num);
struct resolver_query * resolver_query(struct resolver_context *ctx, const char *host, uint16_t port, dns_host_callback cb, void *data);
void resolver_cancel(struct resolver_query *);
void resolver_shutdown(struct resolver_context *ctx);
void resolver_destroy(struct resolver_context *ctx);
const char * resolver_error(struct resolver_query *query);

#endif // for #ifndef RESOLVER_H

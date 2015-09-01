#ifndef _UDPRELAY_C
#define _UDPRELAY_C

static uv_mutex_t mutex;
static struct cache *cache;

int
udprelay_init() {
    uv_mutex_init(&mutex);
    cache_create(&cache, 1024, free_cb);
    return 0;
}

int
udprelay_start(uv_loop_t *loop, struct server_context *server) {
    int rc;

    uv_udp_init(loop, &server->udp);

    if ((rc = uv_udp_open(&server->udp, server->udp_fd))) {
        logger_stderr("udp open error: %s", uv_strerror(rc));
        return 1;
    }

    rc = uv_udp_bind(&server->udp, server->local_addr, UV_UDP_REUSEADDR);
    if (rc) {
        logger_stderr("bind error: %s", uv_strerror(rc));
        return 1;
    }

    uv_udp_recv_start(&server->udp, client_alloc_cb, client_recv_cb);

    return 0;
}

void
udprelay_close(struct server_context *server) {
    uv_close((uv_handle_t *)&server->udp, NULL);
    uv_mutex_lock(&mutex);
    cache_removeall(cache, server->udp.loop, select_cb);
    uv_mutex_unlock(&mutex);
}

void
udprelay_destroy() {
    uv_mutex_destroy(&mutex);
    free(cache);
}
#endif // for #ifndef _UDPRELAY_C

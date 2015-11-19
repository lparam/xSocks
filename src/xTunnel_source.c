#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "xTunnel.h"


struct source_context *
new_source() {
    struct source_context *source = malloc(sizeof(*source));
    memset(source, 0, sizeof(*source));
    return source;
}

static void
free_source(struct source_context *source) {
    source->target = NULL;
    free(source);
}

static void
source_close_cb(uv_handle_t *handle) {
    struct source_context *source = (struct source_context *)handle->data;
    free_source(source);
}

void
close_source(struct source_context *source) {
    source->stage = TUNNEL_STAGE_DEAD;
    source->handle.handle.data = source;
    uv_close(&source->handle.handle, source_close_cb);
}

static void
source_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct source_context *source = handle->data;
    struct packet *packet = &source->packet;

    if (mode == TUNNEL_MODE_CLIENT) {
        buf->base = (char*)(packet->buf + OVERHEAD_BYTES);
        buf->len = sizeof(packet->buf) - OVERHEAD_BYTES;

    } else {
        if (packet->size) {
            buf->base = (char*)packet->buf + packet->offset;
            buf->len = packet->size - packet->offset;
        } else {
            buf->base = (char*)packet->buf + (packet->read ? 1 : 0);
            buf->len = packet->read ? 1 : HEADER_BYTES;
        }
    }
}

static void
source_send_cb(uv_write_t *req, int status) {
    struct source_context *source = req->data;
    struct target_context *target = source->target;

    if (status == 0) {
        /* if (source->stage == TUNNEL_STAGE_FORWARD) { */
            receive_from_target(target);
        /* } */
    } else {
        if (verbose) {
            logger_log(LOG_ERR, "send to source failed: %s", uv_strerror(status));
        }
    }
}

static void
source_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct source_context *source = stream->data;
    struct target_context *target = source->target;

    if (nread > 0) {
        if (mode == TUNNEL_MODE_CLIENT) {
            int clen = nread + PRIMITIVE_BYTES;
            uint8_t *c = source->packet.buf + HEADER_BYTES;
            int rc = crypto_encrypt(c, (uint8_t*)buf->base, nread);
            if (rc) {
                goto error;
            }
            forward_to_target(target, c, clen);

        } else {
            struct packet *packet = &source->packet;
            int rc = packet_filter(packet, buf->base, nread);
            if (rc == PACKET_COMPLETED) {
                uint8_t *m = packet->buf;
                int mlen = packet->size - PRIMITIVE_BYTES;

                int err = crypto_decrypt(m, packet->buf, packet->size);
                if (err) {
                    goto error;
                }

                forward_to_target(target, m, mlen);

            } else if (rc == PACKET_INVALID) {
                goto error;
            }
        }

    } else if (nread < 0){
        close_source(source);
        close_target(target);
    }

    return;

error:
    logger_log(LOG_ERR, "invalid packet");
    close_source(source);
    close_target(target);
}

void
receive_from_source(struct source_context *source) {
    packet_reset(&source->packet);
    source->handle.stream.data = source;
    uv_read_start(&source->handle.stream, source_alloc_cb, source_recv_cb);
}

void
forward_to_source(struct source_context *source, uint8_t *buf, int buflen) {
    uv_read_stop(&source->target->handle.stream);
    source->write_req.data = source;
    if (mode == TUNNEL_MODE_CLIENT) {
        uv_buf_t data = uv_buf_init((char*)buf, buflen);
        uv_write(&source->write_req, &source->handle.stream, &data, 1, source_send_cb);

    } else {
        buf -= HEADER_BYTES;
        write_size(buf, buflen);
        buflen += HEADER_BYTES;
        uv_buf_t data = uv_buf_init((char*)buf, buflen);
        uv_write(&source->write_req, &source->handle.stream, &data, 1, source_send_cb);
    }
}

void
source_accept_cb(uv_stream_t *server, int status) {
    struct source_context *source = new_source();
    struct target_context *target = new_target();

    source->target = target;
    target->source = source;

    uv_tcp_init(server->loop, &source->handle.tcp);
    uv_tcp_init(server->loop, &target->handle.tcp);

    uv_tcp_nodelay(&source->handle.tcp, 0);
    uv_tcp_nodelay(&target->handle.tcp, 0);
    uv_tcp_keepalive(&source->handle.tcp, 1, 60);
    uv_tcp_keepalive(&target->handle.tcp, 1, 60);

    int rc = uv_accept(server, &source->handle.stream);
    if (rc == 0) {
        connect_to_target(target);
    } else {
        logger_log(LOG_ERR, "accept error: %s", uv_strerror(rc));
        close_source(source);
        close_target(target);
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "xTunnel.h"


struct target_context *
new_target() {
    struct target_context *target = malloc(sizeof(*target));
    memset(target, 0, sizeof(*target));
    return target;
}

static void
free_target(struct target_context *target) {
    target->source = NULL;
    free(target);
}

static void
target_close_cb(uv_handle_t *handle) {
    struct target_context *target = (struct target_context *)handle->data;
    free_target(target);
}

void
close_target(struct target_context *target) {
    target->handle.handle.data = target;
    uv_close(&target->handle.handle, target_close_cb);
}

static void
target_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    struct target_context *target = handle->data;
    struct packet *packet = &target->packet;

    if (mode == TUNNEL_MODE_CLIENT) {
        if (packet->size) {
            buf->base = (char*)packet->buf + packet->offset;
            buf->len = packet->size - packet->offset;
        } else {
            buf->base = (char*)packet->buf + (packet->read ? 1 : 0);
            buf->len = packet->read ? 1 : HEADER_BYTES;
        }

    } else {
        buf->base = (char*)(packet->buf + OVERHEAD_BYTES);
        buf->len = sizeof(packet->buf) - OVERHEAD_BYTES;
    }
}

static void
target_send_cb(uv_write_t *req, int status) {
    struct target_context *target = req->data;
    struct source_context *source = target->source;

    if (status == 0) {
        receive_from_source(source);
    } else {
        if (verbose) {
            logger_log(LOG_ERR, "forward to target failed: %s", uv_strerror(status));
        }
    }
}

static void
target_recv_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    struct target_context *target = stream->data;
    struct source_context *source = target->source;

    if (nread > 0) {
        if (mode == TUNNEL_MODE_CLIENT) {
            struct packet *packet = &target->packet;
            int rc = packet_filter(packet, buf->base, nread);
            if (rc == PACKET_COMPLETED) {
                uint8_t *m = packet->buf;
                int mlen = packet->size - PRIMITIVE_BYTES;

                int err = crypto_decrypt(m, packet->buf, packet->size);
                if (err) {
                    goto error;
                }

                forward_to_source(source, m, mlen);

            } else if (rc == PACKET_INVALID) {
                goto error;
            }

        } else {
            int clen = nread + PRIMITIVE_BYTES;
            uint8_t *c = target->packet.buf + HEADER_BYTES;
            int rc = crypto_encrypt(c, (uint8_t*)buf->base, nread);
            if (rc) {
                goto error;
            }
            forward_to_source(source, c, clen);
        }

    } else if (nread < 0) {
        close_source(source);
        close_target(target);
    }

    return;

error:
    logger_log(LOG_ERR, "invalid packet");
    close_source(source);
    close_target(target);
}

static void
target_connect_cb(uv_connect_t *req, int status) {
    struct target_context *target = req->data;

    if (status == 0) {
        receive_from_source(target->source);
        receive_from_target(target);

    } else {
        if (status != UV_ECANCELED) {
            logger_log(LOG_ERR, "connect to target failed: %s", uv_strerror(status));
            close_source(target->source);
            close_target(target);
        }
    }
}

void
connect_to_target(struct target_context *target) {
    target->connect_req.data = target;
    int rc = uv_tcp_connect(&target->connect_req, &target->handle.tcp, &target_addr, target_connect_cb);
    if (rc) {
        logger_log(LOG_ERR, "connect to target error: %s", uv_strerror(rc));
        close_source(target->source);
        close_target(target);
    }
}

void
receive_from_target(struct target_context *target) {
    packet_reset(&target->packet);
    target->handle.stream.data = target;
    uv_read_start(&target->handle.stream, target_alloc_cb, target_recv_cb);
}

void
forward_to_target(struct target_context *target, uint8_t *buf, int buflen) {
    uv_read_stop(&target->source->handle.stream);
    target->write_req.data = target;
    if (mode == TUNNEL_MODE_CLIENT) {
        buf -= HEADER_BYTES;
        write_size(buf, buflen);
        buflen += HEADER_BYTES;
        uv_buf_t data = uv_buf_init((char*)buf, buflen);
        uv_write(&target->write_req, &target->handle.stream, &data, 1, target_send_cb);

    } else {
        uv_buf_t data = uv_buf_init((char*)buf, buflen);
        uv_write(&target->write_req, &target->handle.stream, &data, 1, target_send_cb);
    }
}

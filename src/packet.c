#include <string.h>
#include <assert.h>

#include "util.h"
#include "packet.h"


void
packet_alloc(struct packet *packet, uv_buf_t *buf) {
    if (packet->size) {
        buf->base = (char *) packet->buf + packet->offset;
        buf->len = packet->size - packet->offset;
    } else {
        buf->base = (char *) packet->buf + (packet->read ? 1 : 0);
        buf->len = packet->read ? 1 : HEADER_BYTES;
    }
}

int
packet_filter(struct packet *packet, const char *buf, ssize_t buflen) {
    int rc = PACKET_INVALID;

    if (packet->size == 0) {
        if (packet->read == 0) {
            if (buflen == HEADER_BYTES) {
                packet->size = read_size((uint8_t *) buf);
                if (packet->size > PRIMITIVE_BYTES && packet->size <= packet->max) {
                    rc = PACKET_UNCOMPLETE;
                } else {
                    rc = PACKET_INVALID;
                }

            } else {
                assert(buflen == 1);
                packet->read = 1;
                rc = PACKET_UNCOMPLETE;
            }

        } else {
            assert(packet->read == 1);
            packet->size = read_size((uint8_t *) packet->buf);
            if (packet->size > PRIMITIVE_BYTES && packet->size <= packet->max) {
                rc = PACKET_UNCOMPLETE;
            } else {
                rc = PACKET_INVALID;
            }
        }

    } else {
        if (buflen + packet->offset == packet->size) {
            rc = PACKET_COMPLETED;

        } else {
            assert(buflen + packet->offset < packet->size);
            packet->offset += buflen;
            rc = PACKET_UNCOMPLETE;
        }
    }

    return rc;
}

void
packet_reset(struct packet *packet) {
    packet->read = 0;
    packet->offset = 0;
    packet->size = 0;
    memset(packet->buf, 0, packet->max);
}

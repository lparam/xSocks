#ifndef UDPRELAY_H
#define UDPRELAY_H

#include "uv.h"
#include "common.h"

int udprelay_init();
int udprelay_start(uv_loop_t *loop, struct server_context *server);
void udprelay_close(struct server_context *server);
void udprelay_destroy();

#endif // for #ifndef UDPRELAY_H

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "uv.h"

#define container_of(ptr, type, member) ((type*)(((char*)(ptr)) - offsetof(type, member)))

int resolve_addr(const char *buf, struct sockaddr *addr);
int read_size(uint8_t *buffer);
void write_size(uint8_t *buffer, int len);
int ip_name(const struct sockaddr *ip, char *name, size_t size);
uv_os_sock_t create_socket(int type, int reuse);
void dump_hex(const void *data, uint32_t len, char *title);

#endif // for #ifndef UTIL_H

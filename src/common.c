#include <stdlib.h>
#include <string.h>

#include "uv.h"
#include "socks.h"
#include "util.h"
#include "logger.h"

int
parse_target_address(const struct xSocks_request *req, struct sockaddr *addr, char *host) {
    int addrlen;
    uint16_t portlen = 2; // network byte order port number, 2 bytes
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } dest;

    memset(&dest, 0, sizeof(dest));

    if (req->atyp == ATYP_IPV4) {
        size_t in_addr_len = sizeof(struct in_addr); // 4 bytes for IPv4 address
        dest.addr4.sin_family = AF_INET;
        memcpy(&dest.addr4.sin_addr, req->addr, in_addr_len);
        memcpy(&dest.addr4.sin_port, req->addr + in_addr_len, portlen);
        addrlen = 4 + portlen;

    } else if (req->atyp == ATYP_HOST) {
        uint8_t namelen = *(uint8_t *)(req->addr); // 1 byte of name length
        if (namelen > 0xFF) {
            return -1;
        }
        memcpy(&dest.addr4.sin_port, req->addr + 1 + namelen, portlen);
        memcpy(host, req->addr + 1, namelen);
        host[namelen] = '\0';
        addrlen = 1 + namelen + portlen;

    } else if (req->atyp == ATYP_IPV6) {
        size_t in6_addr_len = sizeof(struct in6_addr); // 16 bytes for IPv6 address
        memcpy(&dest.addr6.sin6_addr, req->addr, in6_addr_len);
        memcpy(&dest.addr6.sin6_port, req->addr + in6_addr_len, portlen);
        addrlen = 16 + portlen;

    } else {
        return 0;
    }

    memcpy(addr, &dest.addr, sizeof(*addr));
    return addrlen;
}

void
cache_log(uint8_t atyp, const struct sockaddr *src_addr, const struct sockaddr *dst_addr,
            const char *host, uint16_t port, int hit) {
    char src[INET6_ADDRSTRLEN + 1] = {0};
    char dst[INET6_ADDRSTRLEN + 1] = {0};
    uint16_t src_port = 0, dst_port = 0;
    char *hint = hit ? "hit" : "miss";
    src_port = ip_name(src_addr, src, sizeof src);
    if (atyp == ATYP_HOST) {
        logger_log(hit ? LOG_INFO : LOG_WARNING, "[udp] cache %s: %s:%d -> %s:%d",
          hint, src, src_port, host, ntohs(port));
    } else {
        dst_port = ip_name(dst_addr, dst, sizeof dst);
        logger_log(hit ? LOG_INFO : LOG_WARNING, "[udp] cache %s: %s:%d -> %s:%d",
          hint, src, src_port, dst, dst_port);
    }
}

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>

#include "util.h"
#include "logger.h"
#include "ancillary.h"


int
protect_socket(int fd) {
    int sock;
    struct sockaddr_un addr;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        logger_log(LOG_ERR, "[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        return -1;
    }

    // Set timeout to 100us
    struct timeval tv;
    tv.tv_sec = 1;  /*  0 Secs Timeout */
    tv.tv_usec = 0;  // Not init'ing this can cause strange errors
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));

    const char path[] = "/data/data/io.github.xSocks/protect_path";

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        logger_log(LOG_ERR, "[android] connect() failed: %s (socket fd = %d)\n", strerror(errno), sock);
        close(sock);
        return -1;
    }

    if (ancil_send_fd(sock, fd)) {
        logger_log(LOG_ERR, "[android] ancil_send_fd: %d", fd);
        close(sock);
        return -1;
    }

    char ret = 0;

    if (recv(sock, &ret, 1, 0) == -1) {
        logger_log(LOG_ERR, "[android] recv");
        close(sock);
        return -1;
    }

    close(sock);
    return ret;
}

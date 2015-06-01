#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#if !defined(_WIN32)
#include <syslog.h>
#endif

#include "uv.h"

#define LOG_MESSAGE_SIZE 256

static int _syslog = 0;
static uv_tty_t _tty;
static uv_loop_t loop;

static char *levels[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"
};

static char *colors[] = {
    "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;33m", "\033[01;33m", "\033[01;32m", "\033[01;36m"
};


#if defined(_WIN32)
static void
syslog(int, const char *, ...) {
}
#endif

static void
log2tty(char *msg) {
    uv_write_t req;

    uv_buf_t buf;
    buf.base = msg;
    buf.len = strlen(buf.base);

    uv_write(&req, (uv_stream_t*)&_tty, &buf, 1, NULL);
}

void
logger_log(uint32_t level, const char *msg, ...) {
    char timestr[20];
    time_t curtime = time(NULL);
    struct tm *loctime = localtime(&curtime);

	char tmp[LOG_MESSAGE_SIZE];

	va_list ap;
	va_start(ap, msg);
	vsnprintf(tmp, LOG_MESSAGE_SIZE, msg, ap);
	va_end(ap);

    if (_syslog) {
        syslog(level, "[%s] %s", levels[level], tmp);
    } else {
        strftime(timestr, 20, "%Y/%m/%d %H:%M:%S", loctime);
        char m[300] = { 0 };
        sprintf(m, "%s%s [%s]\033[0m: %s\n", colors[level], timestr, levels[level], tmp);
        log2tty(m);
    }
}

void
logger_stderr(const char *msg, ...) {
    char timestr[20];
    time_t curtime = time(NULL);
    struct tm *loctime = localtime(&curtime);

	char tmp[LOG_MESSAGE_SIZE];

	va_list ap;
	va_start(ap, msg);
	vsnprintf(tmp, LOG_MESSAGE_SIZE, msg, ap);
	va_end(ap);

    strftime(timestr, 20, "%Y/%m/%d %H:%M:%S", loctime);
    char m[300] = { 0 };
    sprintf(m, "\033[01;31m%s [%s]\033[0m: %s\n", timestr, levels[LOG_ERR], tmp);
    log2tty(m);
}

int
logger_init(int syslog) {
    _syslog = syslog;

    uv_loop_init(&loop);
    uv_tty_init(&loop, &_tty, 2, 0);
    uv_tty_set_mode(&_tty, UV_TTY_MODE_NORMAL);

    return 0;
}

void
logger_exit() {
    uv_tty_reset_mode();
}

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#ifdef _WIN32
#include <io.h>
#else
#include <syslog.h>
#endif

#include "uv.h"
#include "logger.h"

#define LOG_MESSAGE_SIZE 256

static int _syslog = 0;
static uv_tty_t _tty;
static uv_tty_t _ttyerr;
static uv_loop_t _loop;

static char *levels[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"
};

static char *colors[] = {
    "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;33m", "\033[01;33m", "\033[01;32m", "\033[01;36m"
};


#ifdef _WIN32
static void
syslog(int priority, const char *format, ...) {
}
#endif

static void
tty_send_cb(uv_write_t *req, int status) {
    printf("free req\n");
    free(req);
}

static void
log2tty(uv_tty_t *tty, char *msg) {
    uv_write_t req;

    /* uv_buf_t buf;
    buf.base = msg;
    buf.len = strlen(msg); */

	/* uv_tty_t tty;
	uv_loop_t loop;
	uv_loop_init(&loop);
	uv_tty_init(&loop, &tty, 2, 0);
	uv_tty_set_mode(&tty, UV_TTY_MODE_NORMAL); */

    /* uv_write_t *req = malloc(sizeof(*req)); */
    uv_buf_t buf = uv_buf_init(msg, strlen(msg));

	if (uv_guess_handle(1) == UV_TTY) {
		uv_write(&req, (uv_stream_t*)tty, &buf, 1, tty_send_cb);
	}

	//fprintf(stderr, msg);
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
        log2tty(&_tty, m);
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
    log2tty(&_ttyerr, m);
}

int
logger_init(int syslog) {
    int ttyfd;
    int ttyerrfd;

#ifdef _WIN32
   /* HANDLE handle;

	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	assert(handle != INVALID_HANDLE_VALUE);
	ttyfd = _open_osfhandle((intptr_t)handle, 0);

	handle = GetStdHandle(STD_ERROR_HANDLE);
	assert(handle != INVALID_HANDLE_VALUE);
	ttyerrfd = _open_osfhandle((intptr_t)handle, 0);*/
#else
    ttyfd = 1;
    ttyerrfd = 2;
    _syslog = syslog;
#endif

    uv_loop_init(&_loop);
    uv_tty_init(&_loop, &_tty, 1, 0);
    uv_tty_init(&_loop, &_ttyerr, 2, 0);
    uv_tty_set_mode(&_tty, UV_TTY_MODE_NORMAL);
    uv_tty_set_mode(&_ttyerr, UV_TTY_MODE_NORMAL);

    return 0;
}

void
logger_exit() {
    printf("logger exit\n");
    uv_loop_close(&_loop);
    uv_tty_reset_mode();
}

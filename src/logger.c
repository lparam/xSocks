#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <syslog.h>
#endif
#ifdef ANDROID
#include <android/log.h>
#endif

#include "uv.h"
#include "logger.h"


#define LOG_MESSAGE_SIZE 256

static int _syslog = 0;

#ifdef _WIN32
static uv_tty_t _tty;
static uv_tty_t _ttyerr;
#endif

#ifdef _MSC_VER
#define vsnprintf _vsnprintf
#endif

static const char *levels[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"
};

#ifndef ANDROID
static const char *colors[] = {
    "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;33m", "\033[01;33m", "\033[01;32m", "\033[01;36m"
};
#endif


#ifdef _WIN32
static void
syslog(int priority, const char *format, ...) {
}

static void
tty_send_cb(uv_write_t *req, int status) {
    free(req);
}

static void
log2tty(uv_tty_t *tty, char *msg) {
    uv_write_t *req = malloc(sizeof(*req));
    uv_buf_t buf = uv_buf_init(msg, strlen(msg));

	if (uv_guess_handle(1) == UV_TTY) {
		uv_write(req, (uv_stream_t*)tty, &buf, 1, tty_send_cb);
	}
}

#else
static void
log2std(FILE *file, const char *msg) {
    fprintf(file, "%s", msg);
}
#endif

void
logger_log(uint32_t level, const char *msg, ...) {
	char tmp[LOG_MESSAGE_SIZE];

	va_list ap;
	va_start(ap, msg);
	vsnprintf(tmp, LOG_MESSAGE_SIZE, msg, ap);
	va_end(ap);

    if (_syslog) {
        syslog(level, "[%s] %s", levels[level], tmp);

    } else {
#ifdef ANDROID
        if (level <= LOG_ERR) {
            level = ANDROID_LOG_ERROR;
        } else if (level == LOG_WARNING) {
            level = ANDROID_LOG_WARN;
        } else if (level == LOG_DEBUG) {
            level = ANDROID_LOG_DEBUG;
        } else {
            level = ANDROID_LOG_INFO;
        }
        __android_log_print(level, "xSocks", tmp);
#else
        time_t curtime = time(NULL);
        struct tm *loctime = localtime(&curtime);
        char timestr[20];
        strftime(timestr, 20, "%Y/%m/%d %H:%M:%S", loctime);
        char m[300] = { 0 };
        sprintf(m, "%s%s [%s]\033[0m: %s\n", colors[level], timestr, levels[level], tmp);
#ifdef _WIN32
        log2tty(&_tty, m);
#else
        log2std(stdout, m);
#endif
#endif
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

#ifdef _WIN32
    log2tty(&_ttyerr, m);
#else
    log2std(stderr, m);
#endif
}

int
logger_init(int syslog) {
#ifndef _WIN32
    _syslog = syslog;
#else
    uv_tty_init(uv_default_loop(), &_tty, 1, 0);
    uv_tty_init(uv_default_loop(), &_ttyerr, 2, 0);
    uv_tty_set_mode(&_tty, UV_TTY_MODE_NORMAL);
    uv_tty_set_mode(&_ttyerr, UV_TTY_MODE_NORMAL);
#endif

    return 0;
}

void
logger_exit() {
#ifdef _WIN32
    uv_tty_reset_mode();
#endif
}

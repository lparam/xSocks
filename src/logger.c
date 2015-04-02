#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>


#define LOG_MESSAGE_SIZE 256

static int _syslog = 0;

static char *levels[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"
};

static char *colors[] = {
    "\e[01;31m", "\e[01;31m", "\e[01;31m", "\e[01;31m", "\e[01;33m", "\e[01;33m", "\e[01;32m", "\e[01;36m"
};


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
        fprintf(stderr, "%s%s [%s]\e[0m: %s\n", colors[level], timestr, levels[level], tmp);
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
    fprintf(stderr, "\e[01;31m%s [%s]\e[0m: %s\n", timestr, levels[LOG_ERR], tmp);
}

int
logger_init(int syslog) {
    _syslog = syslog;
    return 0;
}

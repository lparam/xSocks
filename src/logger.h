#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdint.h>
#include <syslog.h>

int logger_init(int syslog);
void logger_stderr(const char *msg, ...);
void logger_log(uint32_t level, const char *msg, ...);

#endif // for #ifndef _LOGGER_H

#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h>

#if !defined(_WIN32)
#include <syslog.h>
#else
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */
#endif

int logger_init(int syslog);
void logger_exit(void);
void logger_stderr(const char *msg, ...);
void logger_log(uint32_t level, const char *msg, ...);

#endif // for #ifndef LOGGER_H

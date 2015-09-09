#ifndef DAEMON_H
#define DAEMON_H

int daemonize(void);
int already_running(const char *pidfile);
void create_pidfile(const char *pidfile);
void delete_pidfile(const char *pidfile);

#endif // for #ifndef DAEMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "logger.h"


#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)


static int
lockfile(int fd) {
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	return(fcntl(fd, F_SETLK, &fl));
}

int
already_running(const char *pidfile) {
	int	  fd;
    char  buf[16];

    fd = open(pidfile, O_RDWR | O_CREAT, LOCKMODE);
	if (fd < 0) {
		logger_stderr("open \"%s\" failed (%d: %s)", pidfile, errno, strerror(errno));
		exit(1);
	}
	if (lockfile(fd) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			close(fd);
			return(1);
		}
		logger_stderr("can't lock %s: %s", pidfile, strerror(errno));
		exit(1);
	}

    /*
     * create pid file
     */
    if (ftruncate(fd, 0)) {
		logger_stderr("can't truncate %s: %s", pidfile, strerror(errno));
		exit(1);
    }
    sprintf(buf, "%ld\n", (long)getpid());
    if (write(fd, buf, strlen(buf)+1) == -1) {
		logger_stderr("can't write %s: %s", pidfile, strerror(errno));
		exit(1);
    }

	return(0);
}

void
create_pidfile(const char *pidfile) {
    FILE  *fp = fopen(pidfile, "w");
    if (fp) {
        fprintf(fp, "%ld\n", (long)getpid());
        fclose(fp);
    }
}

void
delete_pidfile(const char *pidfile) {
    unlink(pidfile);
}

int
daemonize(void) {
    int    fd;
    pid_t  pid;

    switch (pid = fork()) {
    case -1:
        fprintf(stderr, "fork() failed.\n");
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }

    setsid();

    if ((fd = open("/dev/null", O_RDWR, 0)) == -1) {
		logger_stderr("open [/dev/null] failed (%d: %s)", errno, strerror(errno));
        return -1;

    } else {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        /* dup2(fd, STDERR_FILENO); */
    }

    return 0;
}


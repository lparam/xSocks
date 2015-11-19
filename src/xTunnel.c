#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>

#include "uv.h"
#include "util.h"
#include "logger.h"
#include "common.h"
#include "crypto.h"
#include "daemon.h"
#include "xTunnel.h"


static int daemon_mode = 1;
static int concurrency;
static char *tunnel_mode;
static char *source_addr = "0.0.0.0:1222";
static char *dest_addr;
static char *password = NULL;
static char *pidfile = "/var/run/xSocks/xTunnel.pid";
static char *xsignal;
#ifndef _WIN32
static struct signal_ctx signals[3];
#endif

static const char *_optString = "nm:l:t:k:c:p:Vvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'm' },
    { "",        required_argument,   NULL, 'l' },
    { "",        required_argument,   NULL, 't' },
    { "",        required_argument,   NULL, 'k' },
    { "",        required_argument,   NULL, 'c' },
    { "",        required_argument,   NULL, 'p' },
    { "signal",  required_argument,   NULL,  0  },
    { "",        no_argument,   NULL, 'n' },
    { "version", no_argument,   NULL, 'v' },
    { "help",    no_argument,   NULL, 'h' },
    { "",        no_argument,   NULL, 'V' },
    { NULL,      no_argument,   NULL,  0  }
};

static void
print_usage(const char *prog) {
    printf("xTunnel Version: %s Maintained by lparam\n", TUNNEL_VER);
    printf("Usage: %s <-m mode> <-l local> <-t target> <-k password>\n", prog);
    printf("\t[-c concurrency] [-p pidfile] [-nVhv]\n\n");
    printf("Options:\n");
    puts(""
         "  -m <mode>\t\t : client, server\n"
         "  -l <local>\t\t : local address:port (default: 0.0.0.0:1222)\n"
         "  -t <target>\t\t : target address:port\n"
         "  -k <password>\t\t : password of server\n"
#ifndef _WIN32
         "  [-p pidfile]\t\t : pid file path (default: /var/run/xSocks/xTunnel.pid)\n"
         "  [-c concurrency]\t : worker threads\n"
         "  [--signal <signal>]\t : send signal to xTunnel: quit, stop\n"
	     "  [-n]\t\t\t : non daemon mode\n"
#endif
         "  [-V] \t\t\t : verbose mode\n"
         "  [-h, --help]\t\t : this help\n"
         "  [-v, --version]\t : show version\n");

    exit(1);
}

static void
parse_opts(int argc, char *argv[]) {
    int opt = 0, longindex = 0;

    while ((opt = getopt_long(argc, argv, _optString, _lopts, &longindex)) != -1) {
        switch (opt) {
        case 'v':
            printf("xTunnel version: %s \n", TUNNEL_VER);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
		case 'n':
            daemon_mode = 0;
			break;
        case 'c':
            concurrency = strtol(optarg, NULL, 10);
            break;
        case 'm':
            tunnel_mode = optarg;
            if (strcasecmp("client", optarg) == 0) {
                mode = TUNNEL_MODE_CLIENT;
            }
            if (strcasecmp("server", optarg) == 0) {
                mode = TUNNEL_MODE_SERVER;
            }
            break;
        case 'l':
            source_addr = optarg;
            break;
        case 't':
            dest_addr = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 'V':
            verbose = 1;
            break;
		case 0: /* long option without a short arg */
            if (strcmp("signal", _lopts[longindex].name) == 0) {
                xsignal = optarg;
                if (strcmp(xsignal, "stop") == 0
                  || strcmp(xsignal, "quit") == 0) {
                    break;
                }
                fprintf(stderr, "invalid option: --signal %s\n", xsignal);
                print_usage(argv[0]);
            }
			break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
}

static void
close_walk_cb(uv_handle_t *handle, void *arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

void
close_loop(uv_loop_t *loop) {
    uv_walk(loop, close_walk_cb, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}

#ifndef _WIN32
static void
close_signal() {
    for (int i = 0; i < 2; i++) {
        uv_signal_stop(&signals[i].sig);
    }
}

static void
signal_cb(uv_signal_t *handle, int signum) {
    if (signum == SIGINT || signum == SIGQUIT) {
        char *name = signum == SIGINT ? "SIGINT" : "SIGQUIT";
        logger_log(LOG_INFO, "Received %s, scheduling shutdown...", name);

        close_signal();

        if (concurrency > 1) {
            struct server_context *servers = handle->data;
            for (int i = 0; i < concurrency; i++) {
                struct server_context *server = &servers[i];
                uv_async_send(&server->async_handle);
            }

        } else {
            struct server_context *ctx = handle->data;
            uv_close((uv_handle_t *)&ctx->tcp, NULL);
        }

    }
    if (signum == SIGTERM) {
        logger_log(LOG_INFO, "Received SIGTERM, scheduling shutdown...");
        if (daemon_mode) {
            delete_pidfile(pidfile);
        }
        exit(0);
    }
}

void
setup_signal(uv_loop_t *loop, uv_signal_cb cb, void *data) {
    signals[0].signum = SIGINT;
    signals[1].signum = SIGQUIT;
    signals[2].signum = SIGTERM;
    for (int i = 0; i < 2; i++) {
        signals[i].sig.data = data;
        uv_signal_init(loop, &signals[i].sig);
        uv_signal_start(&signals[i].sig, cb, signals[i].signum);
    }
}
#endif

static int
init(void) {
    logger_init(daemon_mode);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#ifndef _WIN32
    signal(SIGABRT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
#endif

    if (crypto_init(password)) {
        logger_log(LOG_ERR, "crypto init failed");
        return 1;
    }

    return 0;
}

int
main(int argc, char *argv[]) {
    int rc;
    uv_loop_t *loop;
    struct sockaddr bind_addr;

    parse_opts(argc, argv);

#ifndef _WIN32
    if (xsignal) {
        return signal_process(xsignal, pidfile);
    }
#endif

    if (!tunnel_mode || !dest_addr || !password) {
        print_usage(argv[0]);
        return 1;
    }

#ifndef _WIN32
    if (daemon_mode) {
        if (daemonize()) {
            return 1;
        }
        if (already_running(pidfile)) {
            logger_stderr("xTunnel already running.");
            return 1;
        }
    }
#endif

    if (init()) {
        return 1;
    }

    loop = uv_default_loop();

    rc = resolve_addr(source_addr, &bind_addr);
    if (rc) {
        logger_stderr("invalid local address");
        return 1;
    }

    rc = resolve_addr(dest_addr, &target_addr);
    if (rc) {
        logger_stderr("invalid target address");
        return 1;
    }

    if (concurrency <= 1) {
        struct server_context ctx;
        uv_tcp_init(loop, &ctx.tcp);
        rc = uv_tcp_bind(&ctx.tcp, &bind_addr, 0);
        if (rc) {
            logger_stderr("bind error: %s", uv_strerror(rc));
            return 1;
        }
        rc = uv_listen((uv_stream_t*)&ctx.tcp, SOMAXCONN, source_accept_cb);
        if (rc == 0) {
            logger_log(LOG_INFO, "listening on %s", source_addr);

#ifndef _WIN32
            setup_signal(loop, signal_cb, &ctx);
#endif

            uv_run(loop, UV_RUN_DEFAULT);

            close_loop(loop);

        } else {
            logger_stderr("listen error: %s", uv_strerror(rc));
        }

    } else {
#ifndef _WIN32
        struct server_context *servers = calloc(concurrency, sizeof(servers[0]));
        for (int i = 0; i < concurrency; i++) {
            struct server_context *ctx = servers + i;
            ctx->index = i;
            ctx->tcp_fd = create_socket(SOCK_STREAM, 1);
            ctx->accept_cb = source_accept_cb;
            ctx->local_addr = &bind_addr;
            rc = uv_sem_init(&ctx->semaphore, 0);
            rc = uv_thread_create(&ctx->thread_id, consumer_start, ctx);
        }

        logger_log(LOG_INFO, "listening on %s", source_addr);

        setup_signal(loop, signal_cb, servers);

        uv_run(loop, UV_RUN_DEFAULT);

        close_loop(loop);

        for (int i = 0; i < concurrency; i++) {
            uv_sem_wait(&servers[i].semaphore);
        }
        free(servers);
#else
        logger_stderr("don't support multithreading.");
        return 1;
#endif
    }

#ifndef _WIN32
    if (daemon_mode) {
        delete_pidfile(pidfile);
    }
#endif

    logger_exit();

    return 0;
}

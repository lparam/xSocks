#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>

#include "uv.h"

#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "daemon.h"
#include "udprelay.h"
#include "xTproxy.h"


static int daemon_mode = 1;
static int concurrency = 0;
static char *local_addrbuf = "0.0.0.0:1070";
static char *server_addrbuf;
static char *pidfile = "/var/run/xSocks/xTproxy.pid";
static char *password = NULL;
static char *xsignal;
static struct signal_ctx signals[3];

static const char *_optString = "l:c:d:p:t:k:s:nVvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'p' },
    { "",        required_argument,   NULL, 'c' },
    { "",        required_argument,   NULL, 'd' },
    { "",        required_argument,   NULL, 'l' },
    { "",        required_argument,   NULL, 's' },
    { "",        required_argument,   NULL, 'k' },
    { "",        required_argument,   NULL, 't' },
    { "signal",  required_argument,   NULL,  0  },
    { "",        no_argument,   NULL, 'n' },
    { "version", no_argument,   NULL, 'v' },
    { "help",    no_argument,   NULL, 'h' },
    { "",        no_argument,   NULL, 'V' },
    { NULL,      no_argument,   NULL,  0  }
};

static void
print_usage(const char *prog) {
    printf("xTproxy Version: %s Maintained by lparam\n", XTPROXY_VER);
    printf("Usage: %s <-l local> <-s server> <-k password> [-p pidfile] [-c concurrency] [-nhvV]\n\n", prog);
    printf("Options:\n");
    puts("  -h, --help\t\t : this help\n"
         "  -l <bind address>\t : bind address:port (default: 0.0.0.0:1070)\n"
         "  -s <server address>\t : server address:port\n"
         "  -k <password>\t\t : password of server\n"
         "  -c <concurrency>\t : worker threads\n"
         "  -p <pidfile>\t\t : pid file path (default: /var/run/xSocks/xTproxy.pid)\n"
         "  -t <timeout>\t\t : connection timeout in senconds\n"
         "  [--signal <signal>]\t : send signal to xTproxy: quit, stop\n"
         "  -n\t\t\t : non daemon mode\n"
         "  -v, --version\t\t : show version\n"
         "  -V \t\t\t : verbose mode\n");

    exit(1);
}

static void
parse_opts(int argc, char *argv[]) {
    int opt = 0, longindex = 0;

    while ((opt = getopt_long(argc, argv, _optString, _lopts, &longindex)) != -1) {
        switch (opt) {
        case 'v':
            printf("xTproxy version: %s \n", XTPROXY_VER);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
        case 'l':
            local_addrbuf = optarg;
            break;
        case 's':
            server_addrbuf = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'c':
            concurrency = strtol(optarg, NULL, 10);
            break;
        case 'p':
            pidfile = optarg;
            break;
        case 'n':
            daemon_mode = 0;
            break;
        case 't':
            idle_timeout = strtol(optarg, NULL, 10);
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

void
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
            struct server_context *server = handle->data;
            uv_close((uv_handle_t *)&server->tcp, NULL);
            udprelay_close(server);
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

static void
init(void) {
    logger_init(daemon_mode);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    signal(SIGPIPE, SIG_IGN);

    if (crypto_init(password)) {
        logger_stderr("crypto init failed");
        exit(1);
    }

    if (idle_timeout == 0) {
        idle_timeout = 60;
    }
}

int
main(int argc, char *argv[]) {
    int rc;
    uv_loop_t *loop;
    struct sockaddr local_addr, server_addr;

    parse_opts(argc, argv);

    if (xsignal) {
        return signal_process(xsignal, pidfile);
    }

    if (!password) {
        print_usage(argv[0]);
        return 1;
    }

    if (daemon_mode) {
        if (daemonize()) {
            return 1;
        }
        if (already_running(pidfile)) {
            logger_stderr("xTproxy already running.");
            return 1;
        }
    }

    init();

    loop = uv_default_loop();

    rc = resolve_addr(local_addrbuf, &local_addr);
    if (rc) {
        logger_stderr("invalid local address");
        return 1;
    }

    rc = resolve_addr(server_addrbuf, &server_addr);
    if (rc) {
        logger_stderr("invalid server address");
        return 1;
    }

    udprelay_init();

    if (concurrency <= 1) {
        struct server_context ctx;
        ctx.local_addr = &local_addr;
        ctx.server_addr = &server_addr;
        ctx.udp_fd = create_socket(SOCK_DGRAM, 0);
        ctx.udprelay = 1;

        uv_tcp_init(loop, &ctx.tcp);
        rc = uv_tcp_bind(&ctx.tcp, &local_addr, 0);
        if (rc) {
            logger_stderr("bind error: %s", uv_strerror(rc));
            return 1;
        }
        rc = uv_listen((uv_stream_t *)&ctx.tcp, 128, client_accept_cb);
        if (rc == 0) {
            logger_log(LOG_INFO, "listening on %s", local_addrbuf);

            setup_signal(loop, signal_cb, &ctx);

            udprelay_start(loop, &ctx);

            uv_run(loop, UV_RUN_DEFAULT);

            close_loop(loop);

        } else {
            logger_stderr("listen error: %s", uv_strerror(rc));
        }

    } else {
        struct server_context *servers = calloc(concurrency, sizeof(servers[0]));
        for (int i = 0; i < concurrency; i++) {
            struct server_context *ctx = servers + i;
            ctx->index = i;
            ctx->tcp_fd = create_socket(SOCK_STREAM, 1);
            ctx->udp_fd = create_socket(SOCK_DGRAM, 1);
            ctx->udprelay = 1;
            ctx->accept_cb = client_accept_cb;
            ctx->local_addr = &local_addr;
            ctx->server_addr = &server_addr;
            rc = uv_sem_init(&ctx->semaphore, 0);
            rc = uv_thread_create(&ctx->thread_id, consumer_start, ctx);
        }

        logger_log(LOG_INFO, "listening on %s", local_addrbuf);

        setup_signal(loop, signal_cb, servers);

        uv_run(loop, UV_RUN_DEFAULT);

        close_loop(loop);

        for (int i = 0; i < concurrency; i++) {
            uv_sem_wait(&servers[i].semaphore);
        }
        free(servers);
    }

    udprelay_destroy();

    if (daemon_mode) {
        delete_pidfile(pidfile);
    }

    return 0;
}

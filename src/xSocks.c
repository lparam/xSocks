#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_MSC_VER)
#include "getopt-win.h"
#else
#include <getopt.h>
#endif

#include "uv.h"

#include "acl.h"
#include "util.h"
#include "logger.h"
#include "crypto.h"
#include "daemon.h"
#include "udprelay.h"
#include "xSocks.h"

static int daemon_mode = 1;
static int concurrency = 0;
static char *local_addr = "0.0.0.0:1080";
static char *server_addr_buf;
static char *pidfile = "/var/run/xSocks/xSocks.pid";
static char *password = NULL;
static char *acl_file;
static char *xsignal;

#ifndef _WIN32
static struct signal_ctx signals[3];
#endif

static const char *_optString = "l:c:p:t:k:s:nVvh";
static const struct option _lopts[] = {
    { "",        required_argument,   NULL, 'p' },
    { "",        required_argument,   NULL, 'c' },
    { "",        required_argument,   NULL, 'd' },
    { "",        required_argument,   NULL, 'k' },
    { "",        required_argument,   NULL, 'l' },
    { "",        required_argument,   NULL, 't' },
    { "",        required_argument,   NULL, 's' },
    { "",        no_argument,         NULL, 'n' },
#ifdef ANDROID
    { "vpn",     no_argument,         NULL,  0  },
#endif
    { "acl",     required_argument,   NULL,  0  },
    { "signal",  required_argument,   NULL,  0  },
    { "version", no_argument,         NULL, 'v' },
    { "help",    no_argument,         NULL, 'h' },
    { "",        no_argument,         NULL, 'V' },
    { NULL,      no_argument,         NULL,  0  }
};

static void
print_usage(const char *prog) {
    printf("xSocks Version: %s Maintained by lparam\n", XSOCKS_VER);
#ifdef _WIN32
    printf("Usage: %s [-l local] <-s server> <-k password> [-hvV]\n\n", prog);
#else
    printf("Usage: %s [-l local] <-s server> <-k password> [-p pidfile] [-c concurrency] [-s signal] [-nhvV]\n\n", prog);
#endif
    printf("Options:\n");
    puts("  -s <server address>\t : server address:port\n"
         "  -k <password>\t\t : password of server\n"
         "  [-l <bind address>]\t : bind address:port (default: 0.0.0.0:1080)\n"
         "  [-t <timeout>]\t : connection timeout in senconds\n"
#ifndef _WIN32
         "  [-c <concurrency>]\t : worker threads\n"
         "  [-p <pidfile>]\t : pid file path (default: /var/run/xSocks/xSocks.pid)\n"
#endif
         "  [--acl <aclfile>]\t : ACL (Access Control List) file path\n"
#ifdef ANDROID
         "  [--vpn]\t : protect vpn socket\n"
#endif
#ifndef _WIN32
         "  [--signal <signal>]\t : send signal to xSocks: quit, stop\n"
         "  [-n]\t\t\t : non daemon mode\n"
#endif
         "  [-h, --help]\t\t : this help\n"
         "  [-v, --version]\t : show version\n"
         "  [-V] \t\t\t : verbose mode\n");

    exit(1);
}

static void
parse_opts(int argc, char *argv[]) {
    int opt = 0, longindex = 0;

    while ((opt = getopt_long(argc, argv, _optString, _lopts, &longindex)) != -1) {
        switch (opt) {
        case 'v':
            printf("xSocks version: %s \n", XSOCKS_VER);
            exit(0);
            break;
        case 'h':
        case '?':
            print_usage(argv[0]);
            break;
        case 'l':
            local_addr = optarg;
            break;
        case 's':
            server_addr_buf = optarg;
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
#ifdef ANDROID
            if (strcmp("vpn", _lopts[longindex].name) == 0) {
                vpn = 1;
            }
#endif
            if (strcmp("acl", _lopts[longindex].name) == 0) {
                acl_file = optarg;
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

#if !defined(_WIN32)
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
            udprelay_close(ctx);
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

static void
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

static void
init(void) {
#ifdef ANDROID
    logger_init(0);
#else
    logger_init(daemon_mode);
#endif

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

#if !defined(_WIN32)
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    if (crypto_init(password)) {
        logger_stderr("crypto init failed");
        exit(1);
    }

    if (idle_timeout == 0) {
        idle_timeout = 60;
    }

    if (acl_file != NULL) {
        acl = !acl_init(acl_file);
    }
}

int
main(int argc, char *argv[]) {
    int rc;
    uv_loop_t *loop;

    parse_opts(argc, argv);

#if !defined(_WIN32)
    if (xsignal) {
        return signal_process(xsignal, pidfile);
    }
#endif

    if (!password || !server_addr_buf) {
        print_usage(argv[0]);
        return 1;
    }

#if !defined(_WIN32)
    if (daemon_mode) {
        if (daemonize()) {
            return 1;
        }
        if (already_running(pidfile)) {
            logger_stderr("xSocks already running.");
            return 1;
        }
    }
#endif

    init();

    loop = uv_default_loop();

    rc = resolve_addr(local_addr, &bind_addr);
    if (rc) {
        logger_stderr("invalid local address");
        return 1;
    }

    rc = resolve_addr(server_addr_buf, &server_addr);
    if (rc) {
        logger_stderr("invalid server address");
        return 1;
    }

    udprelay_init();

    if (concurrency <= 1) {
        struct server_context ctx;
        ctx.udprelay = 1;
        ctx.udp_fd = create_socket(SOCK_DGRAM, 0);
        ctx.local_addr = &bind_addr;
        ctx.server_addr = &server_addr;

        uv_tcp_init(loop, &ctx.tcp);
        rc = uv_tcp_bind(&ctx.tcp, &bind_addr, 0);
        if (rc) {
            logger_stderr("bind error: %s", uv_strerror(rc));
            return 1;
        }
        rc = uv_listen((uv_stream_t*)&ctx.tcp, 128, client_accept_cb);
        if (rc == 0) {
            logger_log(LOG_INFO, "listening on %s", local_addr);

#if !defined(_WIN32)
            setup_signal(loop, signal_cb, &ctx);
#endif

            udprelay_start(loop, &ctx);

            uv_run(loop, UV_RUN_DEFAULT);

            close_loop(loop);

        } else {
            logger_stderr("listen error: %s", uv_strerror(rc));
        }

    } else {
#if !defined(_WIN32)
        struct server_context *servers = calloc(concurrency, sizeof(servers[0]));
        for (int i = 0; i < concurrency; i++) {
            struct server_context *ctx = servers + i;
            ctx->index = i;
            ctx->tcp_fd = create_socket(SOCK_STREAM, 1);
            ctx->udp_fd = create_socket(SOCK_DGRAM, 1);
            ctx->udprelay = 1;
            ctx->accept_cb = client_accept_cb;
            ctx->local_addr = &bind_addr;
            ctx->server_addr = &server_addr;
            rc = uv_sem_init(&ctx->semaphore, 0);
            rc = uv_thread_create(&ctx->thread_id, consumer_start, ctx);
        }

        logger_log(LOG_INFO, "listening on %s", local_addr);

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

    udprelay_destroy();

#if !defined(_WIN32)
    if (daemon_mode) {
        delete_pidfile(pidfile);
    }
#endif

    if (acl_file != NULL) {
        acl_free();
    }
    logger_exit();

    return 0;
}

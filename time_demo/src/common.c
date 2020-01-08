#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include "common.h"

volatile sig_atomic_t terminated = 0;

// Register an empty signal handler for SIGUSR1.
// Replaces the default action for SIGUSR1
// which is to terminate the process.
// This application uses SIGUSR1 to wakeup threads
// that are blocked on system calls.
static void siguser_handler(int signo) {
    (void)signo;
}

int gaps_app_run(gaps_app_t *ctx) {
    sigset_t mask;
    struct sigaction saction;

    // Block the SIGINT and SIGTERM signals in the parent thread.
    // A new thread inherits a copy of its creator's signal mask.
    // The main thread will wait on signalfd() to handle
    // SIGINT and SIGTERM signals.
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror("sigprocmask");
        return -1;
    }

    // Register the empty signal handler for SIGUSR1
    // This application uses SIGUSR1 to wakeup threads
    // that are blocked on system calls.
    memset(&saction, 0, sizeof(struct sigaction));
    saction.sa_handler = &siguser_handler;
    if (sigaction(SIGUSR1, &saction, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    ctx->signal_fd = signalfd(-1, &mask, 0);
    if (ctx->signal_fd < 0) {
        perror("signalfd");
        return -1;
    }

    // Initialize and open GAPS channels
    for (int i = 0; i < MAX_APP_GAPS_CHANNELS; i++) {
        gaps_channel_ctx_t *c = &ctx->ch[i];
        if (c->num == -1) {
            break;
        }

        if (pirate_set_channel_type(CLIENT_TO_PROXY, GAPS_CH_TYPE)) {
            fprintf(stderr, "Failed to set channel type for %s\n", c->desc);
            return -1;
        }

        if ((c->fd = pirate_open(c->num, c->flags)) == -1) {
            fprintf(stderr, "Failed to open channel type for %s\n", c->desc);
            return -1;
        }
    }

    // Start threads
    for (int i = 0; i < MAX_APP_THREADS; i++) {
        thread_ctx_t *t = &ctx->threads[i];
        if (t->func == NULL) {
            break;
        }

        if (pthread_create(&t->tid, NULL, t->func, t->arg) != 0) {
            fprintf(stderr, "Failed to start '%s' thread\n", t->name);
            return -1;
        }

        if (pthread_setname_np(t->tid, t->name) != 0) {
            fprintf(stderr, "Failed to set thread name '%s'\n", t->name);
            return -1;
        }
    }

    return 0;
}

int gaps_app_wait_exit(gaps_app_t *ctx) {
    int rv = 0;
    struct signalfd_siginfo siginfo;

    if (read(ctx->signal_fd, &siginfo, sizeof(siginfo)) < 0) {
        perror("read signal file descriptor");
        rv = -1;
    }

    gaps_terminate();

    // Close GAPS channels
    for (int i = 0; i < MAX_APP_GAPS_CHANNELS; i++) {
        gaps_channel_ctx_t *c = &ctx->ch[i];
        if (c->num == -1) {
            break;
        }

        if (c->fd != -1) {
            pirate_close(c->fd, c->flags);
            c->fd = -1;
        }
    }
    
    // Stop worker threads
    for (int i = 0; i < MAX_APP_THREADS; i++) {
        thread_ctx_t *t = &ctx->threads[i];
        if (t->func == NULL) {
            break;
        }

        if (pthread_kill(t->tid, SIGUSR1) < 0) {
            fprintf(stderr, "pthread_kill '%s'", t->name);
            rv = -1;
        }
    }

    for (int i = 0; i < MAX_APP_THREADS; i++) {
        thread_ctx_t *t = &ctx->threads[i];
        if (t->func == NULL) {
            break;
        }

        if (pthread_join(t->tid, NULL) < 0) {
            fprintf(stderr, "pthread_join '%s'", t->name);
            rv = -1;
        }
    }

    return rv;
}

void gaps_terminate() {
    terminated = 1;
    kill(getpid(), SIGTERM);
}

int gaps_running() {
    return terminated == 0;
}


#define LINE_LEN 32
static void print_hex_str(const char *msg, const uint8_t *data, uint32_t len) {
    static const char digits[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    uint32_t remain = len;
    uint32_t off = 0;

    fprintf(stdout, "%s\n", msg);
    do {
        char buf[(LINE_LEN << 1) + 11];
        char *buf_p = buf;
        const uint32_t chunk_len = remain > LINE_LEN ? LINE_LEN : remain;
        const uint8_t *data_p = data + off;

        buf_p += sprintf(buf_p, "   %04X : ", off);

        for (uint32_t i = 0; i < chunk_len; i++) {
            *buf_p++ = digits[data_p[i] >> 4];
            *buf_p++ = digits[data_p[i] & 0xF];
        }
        buf[buf_p - buf] = '\0';
        fprintf(stdout, "%s\n", buf);
        remain -= chunk_len;
        off += chunk_len;
    } while(remain > 0);
}


const char *ts_status_str(ts_status_t sts) {
    static const char *ret = "UNKNOWN";

    switch (sts) {
    case OK:
        ret = "OK";
        break;
    case BUSY:
        ret = "BUSY";
        break;
    case ERR:
        ret = "ERROR";
        break;
    case UNKNOWN:
    default:
        break;
    }

    return ret;
}


void print_proxy_request(const proxy_request_t *req) {
    fprintf(stdout, "Proxy Sign Request\n");
    print_hex_str("SHA-256", req->digest, sizeof(req->digest));
    fflush(stdout);
}


void print_tsa_request(const tsa_request_t *req) {
    fprintf(stdout, "Timestamp Service Request:\n");
    print_hex_str("REQUEST", req->req, req->len);
    fflush(stdout);
}


void print_tsa_response(const tsa_response_t *rsp) {
    fprintf(stdout, "Timestamp Sign Response:\n");
    fprintf(stdout, " STATUS: %s\n", ts_status_str(rsp->status));
    if (rsp->status == OK) {
        fprintf(stdout, " LENGTH: %u\n", rsp->len);
        if ((rsp->len != 0) && (rsp->len <= MAX_TS_LEN)) {
            print_hex_str("TS", rsp->ts, rsp->len);
        }
    }
    fflush(stdout);
}

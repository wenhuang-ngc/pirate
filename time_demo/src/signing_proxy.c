#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/queue.h>
#include "gaps_packet.h"
#include "common.h"
#include "ts_crypto.h"

/* Default values */
#define DEFAULT_POLL_PERIOD_MS      1000
#define DEFAULT_REQUEST_QUEUE_LEN   16
#define TSA_REQ_RAND_LEN            32

typedef struct proxy_request_entry_s {
    proxy_request_t req;
    uint32_t simulated;
    STAILQ_ENTRY(proxy_request_entry_s) entry;
} proxy_request_entry_t;

typedef struct {
    pthread_mutex_t lock;
    STAILQ_HEAD(queuehead, proxy_request_entry_s) head;
} request_queue_t;

typedef struct {
    volatile int running;
    pthread_t tid;
} work_thread_t;

typedef struct {
    uint32_t poll_period_ms;
    uint32_t queue_len;
    verbosity_level_t verbosity;

    struct {
        work_thread_t sim;
        work_thread_t rx;
    } threads;

    struct {
        request_queue_t free;
        request_queue_t req;
    } queue;

    struct {
        gaps_channel_pair_t client;
        gaps_channel_pair_t signer;
    } gaps;
} proxy_t;

/* Command-line options */
const char *argp_program_version = DEMO_VERSION;
static struct argp_option options[] = {
    { "period",    'p', "MS",  0, "Request polling period",      0 },
    { "queue-len", 'q', "LEN", 0, "Request queue length",        0 },
    { "verbose",   'v', NULL,  0, "Increase verbosity level",    0 },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    proxy_t *proxy = (proxy_t *) state->input;

    switch (key) {

    case 'p':
        proxy->poll_period_ms = strtol(arg, NULL, 10);
        break;

    case 'q':
        proxy->queue_len = strtol(arg, NULL, 10);
        break;

    case 'v':
        if (proxy->verbosity < VERBOSITY_MAX) {
            proxy->verbosity++;
        }
        break;

    default:
        break;

    }

    return 0;
}

static void parse_args(int argc, char *argv[], proxy_t *proxy) {
    struct argp argp  = {
        .options = options,
        .parser = parse_opt,
        .args_doc = NULL,
        .doc = "Proxy between the client and timestamp signing service",
        .children = NULL,
        .help_filter = NULL,
        .argp_domain = NULL
    };

    proxy->poll_period_ms = DEFAULT_POLL_PERIOD_MS;
    argp_parse(&argp, argc, argv, 0, 0, proxy);
}


/* Initialize GAPS channels */
static int gaps_init(proxy_t *proxy) {
    proxy->gaps.client.wr = proxy->gaps.client.rd = -1;
    proxy->gaps.signer.wr = proxy->gaps.signer.rd = -1;

    if ((pirate_set_channel_type(CLIENT_TO_PROXY, GAPS_CH_TYPE) != 0) ||
        (pirate_set_channel_type(PROXY_TO_CLIENT, GAPS_CH_TYPE) != 0) ||
        (pirate_set_channel_type(PROXY_TO_SIGNER, GAPS_CH_TYPE) != 0) ||
        (pirate_set_channel_type(SIGNER_TO_PROXY, GAPS_CH_TYPE) != 0)) {
        perror("Failed to set GAPS channel type\n");
        return -1;
    }
   
    proxy->gaps.client.rd = pirate_open(CLIENT_TO_PROXY, O_RDONLY);
    if (proxy->gaps.client.rd == -1) {
        perror("Failed to open client to proxy GAPS RD channel\n");
        return -1;
    }

    proxy->gaps.client.wr = pirate_open(PROXY_TO_CLIENT, O_WRONLY);
    if (proxy->gaps.client.wr == -1) {
        perror("Failed to open proxy to client GAPS WR channel\n");
        return -1;
    }

    proxy->gaps.signer.wr = pirate_open(PROXY_TO_SIGNER, O_WRONLY);
    if (proxy->gaps.signer.wr == -1) {
        perror("Failed to open proxy to timestamp service GAPS WR channel\n");
        return -1;
    }

    proxy->gaps.signer.rd = pirate_open(SIGNER_TO_PROXY, O_RDONLY);
    if (proxy->gaps.signer.rd == -1) {
        perror("Failed to open timestamp service to #endifproxy GAPS RD channel\n");
        return -1;
    }

    return 0;
}

/* Close GAPS channels */
static void gaps_term(proxy_t *proxy) {
    if (proxy->gaps.client.rd != -1) {
        pirate_close(proxy->gaps.client.rd, O_RDONLY);
        proxy->gaps.client.rd = -1;
    }

    if (proxy->gaps.client.wr != -1) {
        pirate_close(proxy->gaps.client.wr, O_WRONLY);
        proxy->gaps.client.wr = -1;
    }

    if (proxy->gaps.signer.wr != -1) {
        pirate_close(proxy->gaps.signer.wr, O_WRONLY);
        proxy->gaps.signer.wr = -1;
    }

    if (proxy->gaps.signer.rd != -1) {
        pirate_close(proxy->gaps.signer.rd, O_RDONLY);
        proxy->gaps.signer.rd = -1;
    }
}


/* Push an intem on a queue */
static void request_queue_push(request_queue_t *queue, 
    proxy_request_entry_t *entry) {
    pthread_mutex_lock(&queue->lock);
    STAILQ_INSERT_TAIL(&queue->head, entry, entry);
    pthread_mutex_unlock(&queue->lock);
}

/* Pop an item from a queue */
static proxy_request_entry_t *request_queue_pop(request_queue_t *queue) {
    proxy_request_entry_t *entry = NULL;
    pthread_mutex_lock(&queue->lock);
    entry = STAILQ_FIRST(&queue->head);
    if (entry != NULL) {
        STAILQ_REMOVE_HEAD(&queue->head, entry);
    }
    pthread_mutex_unlock(&queue->lock);
    return entry;
}

/* Initialize a request queue */
static int request_queue_init(request_queue_t *queue, uint32_t num) {
    STAILQ_INIT(&queue->head);
    pthread_mutex_init(&queue->lock, NULL);

    /* Allocate queue entries */
    for (uint32_t i = 0; i < num; i++) {
        proxy_request_entry_t *entry = (proxy_request_entry_t*)
            calloc(1, sizeof(proxy_request_entry_t));
        if (entry == NULL) {
            perror("Failed to allocate memory for a signing request\n");
            return -1;
        }

        request_queue_push(queue, entry);
    }

    return 0;
}

/* Cleanup a request queue */
static void request_queue_term(request_queue_t *queue) {
    proxy_request_entry_t *entry = NULL;
    while ((entry = request_queue_pop(queue)) != NULL) {
        free(entry);
    }
    pthread_mutex_destroy(&queue->lock);
}


/* Thread for generating simulated requests */
static void *sim_request_gen(void *argp) {
    proxy_t *proxy = (proxy_t *)argp;
    
    /* Generate simulated requests at 1/2 * poll period */
    const uint64_t gen_period_ns = proxy->poll_period_ms * (10000000 / 2);
    const struct timespec ts = {
        .tv_sec  = gen_period_ns / 1000000000,
        .tv_nsec = gen_period_ns % 1000000000
    };

    while (proxy->threads.sim.running) {
        nanosleep(&ts, NULL);

        proxy_request_entry_t *entry = NULL;
        pthread_mutex_lock(&proxy->queue.req.lock);
        entry = STAILQ_FIRST(&proxy->queue.req.head);
        pthread_mutex_unlock(&proxy->queue.req.lock);
        
        if (entry != NULL) {
            continue;
        }

        /* Generate simulated request and place it on the request queue */
        if ((entry = request_queue_pop(&proxy->queue.free)) == NULL) {
            fprintf(stderr, "Failed to pop a request entry\n");
            return NULL;
        }

        if (ts_create_request(NULL, &entry->req) != 0) {
            perror("Failed to generate random request data\n");
            return NULL;
        }

        entry->simulated = 1;
        request_queue_push(&proxy->queue.req, entry);

        if (proxy->verbosity >= VERBOSITY_MAX) {
            print_proxy_request("Simulated request added", &entry->req);
        }
    }

    return NULL;
}


/* Sign request receive thread */
static void *request_receive(void *argp) {
    proxy_t *proxy = (proxy_t*) argp;
    ssize_t len;
    proxy_request_t req;
    proxy_request_entry_t *entry = NULL;

    while (proxy->threads.rx.running) {
        len = gaps_packet_read(proxy->gaps.client.rd, &req, sizeof(req));
        if (len != sizeof(req)) {
            fprintf(stderr, "Failed to receive request\n");
            return NULL;
        }

        if (proxy->verbosity >= VERBOSITY_MAX) {
            print_proxy_request("Client request received", &req);
        }

        if ((entry = request_queue_pop(&proxy->queue.free)) == NULL) {
            tsa_response_t rsp = {
                .status = BUSY,
                .len = 0,
                .ts = { 0 }
            };

            if (gaps_packet_write(PROXY_TO_CLIENT, &rsp, sizeof(rsp)) != 0) {
                perror("Failed to send busy response\n");
                return NULL;
            }

            if (proxy->verbosity >= VERBOSITY_MIN) {
                fprintf(stdout, "BUSY\n");
                fflush(stdout);
            }
        }

        entry->req = req;
        entry->simulated = 0;
        request_queue_push(&proxy->queue.req, entry);
    }

    return NULL;
}

/* Start a worker thread */
static int start_thread(work_thread_t *t, void *(*func) (void *), void *arg) {
    t->running = 1;
    int sts = pthread_create(&t->tid, NULL, func, arg);
    if (sts != 0) {
        perror("Failed to start thread\n");
        t->running = 0;
        return -1;
    }

    return 0;
}

/* Stop a worker thread */
static void stop_thread(work_thread_t *t) {
    if (t->running == 0) {
        return;
    }

    t->running = 0;
    pthread_join(t->tid, NULL);
}


/* Proxy request polling and signing */
static int proxy_run(proxy_t *proxy) {
    int sts;
    ssize_t len;
    tsa_request_t req = TSA_REQUEST_INIT;
    tsa_response_t rsp = TSA_RESPONSE_INIT;
    proxy_request_entry_t *entry = NULL;

    const struct timespec ts = {
        .tv_sec  = proxy->poll_period_ms / 1000,
        .tv_nsec = (proxy->poll_period_ms % 1000) * 1000000
    };

    while (1) {
        /* Periodically poll */
        nanosleep(&ts, NULL);

        /* Get a request, there always should be one */
        if ((entry = request_queue_pop(&proxy->queue.req)) == NULL) {
            fprintf(stderr, "Request queue empty\n");
            return -1;
        }

        if (proxy->verbosity >= VERBOSITY_MIN) {
            print_proxy_request("Processing next request", &entry->req);
        }
        
        /* Use the timestamp service to sign */
        if (ts_create_query(&entry->req, &req) != 0) {
            fprintf(stderr, "Failed to generate timestamp sign query\n");
            return -1;
        }

        if (proxy->verbosity >= VERBOSITY_MIN) {
            print_tsa_request("Sent TSA request", &req);
        }

        request_queue_push(&proxy->queue.free, entry);
        sts = gaps_packet_write(proxy->gaps.signer.wr, &req, sizeof(req));
        if (sts != 0) {
            fprintf(stderr, "Failed to send timestamp request\n");
            return -1;
        }

        len = gaps_packet_read(proxy->gaps.signer.rd, &rsp, sizeof(rsp));
        if (len != sizeof(rsp)) {
            fprintf(stderr, "Failed to receive timestamp response\n");
            return -1;
        }
        
        if (proxy->verbosity >= VERBOSITY_MIN) {
            print_tsa_response("TSA response received", &rsp);
        }

        if (entry->simulated != 0) {
            continue;
        }

        sts = gaps_packet_write(proxy->gaps.client.wr, &rsp, sizeof(rsp));
        if (sts != 0) {
            perror("Failed to send response");
            return -1;
        }
    }

    return 0;   /* Should never get here */
}

/* Start the proxy */
static int proxy_init(proxy_t *proxy) {
    /* Initialize GAPS channels */
    if (gaps_init(proxy) != 0) {
        fprintf(stderr, "Failed to initialize GAPS channels\n");
        return -1;
    }

    /* Initialize request queues */
    if ((request_queue_init(&proxy->queue.free, 4) != 0) ||
        (request_queue_init(&proxy->queue.req, 0) != 0)) {
        fprintf(stderr, "Failed to initialize request queues\n");
        return -1;
    }

    /* Start worker threads */
    if ((start_thread(&proxy->threads.sim, sim_request_gen, proxy) != 0) ||
        (start_thread(&proxy->threads.rx, request_receive, proxy) != 0)) {
        fprintf(stderr, "Failed to start worker threads\n");
        return -1;
    }

    return 0;
}

/* Release proxy resources */
static void proxy_term(proxy_t *proxy) {
    /* Close GAPS channels */
    gaps_term(proxy);

    /* Stop worker threads */ 
    stop_thread(&proxy->threads.sim);
    stop_thread(&proxy->threads.rx);

    /* Release request queues */
    request_queue_term(&proxy->queue.free);
    request_queue_term(&proxy->queue.req);
}


int main(int argc, char *argv[]) {
    /* Parse command-line options */
    proxy_t proxy;
    memset(&proxy, 0, sizeof(proxy));
    parse_args(argc, argv, &proxy);

    /* Initialize the proxy */
    if (proxy_init(&proxy) != 0) {
        fprintf(stderr, "Failed to start the signing proxy\n");
        proxy_term(&proxy);
        return -1;
    }

    /* Run the proxy */
    if (proxy_run(&proxy) != 0) {
        fprintf(stderr, "Proxy error\n");
        proxy_term(&proxy);
        return -1;
    }

    /* Cleanup */
    proxy_term(&proxy);
    return 0;
}

#include <argp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "gaps_packet.h"

#include "common.h"

#define MAX_INPUT_COUNT 16

typedef struct {
    struct {
        char path[PATH_MAX];
        uint8_t* buf;
        uint32_t len;
    } data;

    proxy_request_t req;
    proxy_sign_response_t rsp;
} block_t;

typedef struct {
    uint32_t validate;
    uint32_t save;
    uint32_t request_delay_ms;
    verbosity_level_t verbosity;

    block_t data[MAX_INPUT_COUNT];
    uint32_t count;

    gaps_channel_pair_t gaps;
} client_t;

/* Command-line options */
const char* argp_program_version = DEMO_VERSION;
static struct argp_option options[]  = {
    { "validate",  'V', NULL, 0, "Validate timestamp signatures", 0 },
    { "save",      's', NULL, 0, "Save timestamp signatures",     0 },
    { "req_delay", 'd', "MS", 0, "Request delay in milliseconds", 0 },
    { "verbose",   'v', NULL, 0, "Increase verbosity level",      0 },
    { 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    client_t* client = (client_t*) state->input;

    switch (key) {

    case 'V':
        client->validate = 1;
        break;

    case 's':
        client->save = 1;
        break;

    case 'd':
        client->request_delay_ms = strtol(arg, NULL, 10);
        break;

    case 'v':
        if (client->verbosity < VERBOSITY_MAX) {
            client->verbosity++;
        }
        break;

    case ARGP_KEY_ARG:
        if (client->count >=  MAX_INPUT_COUNT) {
            argp_failure(state, 1, 0, "exceeded input limit");
        }

        if (realpath(arg, client->data[client->count++].data.path) == NULL) {
            argp_failure(state, 1, 0, "failed to resolve %s path\n", arg);
        }
        break;

    case ARGP_KEY_END:
        if (client->count == 0) {
            argp_failure(state, 1, 0, "no input files");
        }

        if (client->verbosity >= VERBOSITY_MAX) {
            fprintf(stdout, "%2u input test files\n", client->count);
            for (uint32_t i = 0; i < client->count; i++) {
                fprintf(stdout, "%s\n", client->data[i].data.path);
            }
            fflush(stdout);
        }
        break;

    default:
        break;
    }
    
    return 0;
}


static void parse_args(int argc, char* argv[], client_t* client) {
    struct argp argp = {
        .options = options,
        .parser = parse_opt,
        .args_doc = "[FILE] [FILE] ...",
        .doc = "Sign files with the trusted timestamp service",
        .children = NULL,
        .help_filter  = NULL,
        .argp_domain = NULL
    };

    argp_parse(&argp, argc, argv, 0, 0, client);
}


/* Initialize GAPS channels */
static int gaps_init(client_t* client) {
    client->gaps.wr = client->gaps.rd = -1;

    if ((pirate_set_channel_type(CLIENT_TO_PROXY, GAPS_CH_TYPE) != 0) || 
        (pirate_set_channel_type(PROXY_TO_CLIENT, GAPS_CH_TYPE) != 0)) {
        perror("Failed to set GAPS channel type\n");
        return -1;
    }

    client->gaps.wr = pirate_open(CLIENT_TO_PROXY, O_WRONLY);
    if (client->gaps.wr == -1 ) {
        perror("Failed to open client to proxy WR channel\n");
        return -1;
    }

    client->gaps.rd = pirate_open(PROXY_TO_CLIENT, O_RDONLY);
    if (client->gaps.rd == -1) {
        perror("Failed to open proxy to client RD channel\n");
        return -1;
    }

    return 0;
}

/* Close GAPS channels */
static void gaps_term(client_t* client) {
    if (client->gaps.wr != -1) {
        pirate_close(client->gaps.wr, O_WRONLY);
        client->gaps.wr = -1;
    }
    
    if (client->gaps.rd != -1) {
        pirate_close(client->gaps.rd, O_RDONLY);
        client->gaps.rd = -1;
    }
}


/* Read test data */
static int data_init(client_t* client) {
    for (uint32_t i = 0; i < client->count; i++) {
        block_t* entry = &client->data[i];
        struct stat sb;

        /* Read test data */
        if (stat(entry->data.path, &sb) !=0) {
            fprintf(stderr, "Failed to stat %s\n", entry->data.path);
            return -1;
        }

        entry->data.len = sb.st_size;
        entry->data.buf = (uint8_t* ) malloc(entry->data.len);
        if (entry->data.buf == NULL) {
            fprintf(stderr, "Failed to allocate %d bytes\n", entry->data.len);
            return -1;
        }

        int fd = open(entry->data.path, O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "Failed to open %s\n", entry->data.path);
            return -1;
        }

        ssize_t rd = read(fd, entry->data.buf, entry->data.len);
        if (rd != entry->data.len) {
            fprintf(stderr, "Failed to read %d bytes of data from %s\n", 
                    entry->data.len, entry->data.path);
            return -1;
        }

        /* Generate random iv */
        if (RAND_bytes(entry->req.n, REQ_ID_LEN) != 1) {
            fprintf(stderr, "Failed to generate init data of %u bytes\n",
                    REQ_ID_LEN);
            return -1;
        }

        /* Compute hash */
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, entry->req.n, sizeof(entry->req.n));
        SHA256_Update(&sha256, entry->data.buf, entry->data.len);
        SHA256_Final(entry->req.h_d, &sha256);
    }

    return 0;
}

/* Release test data */
static void data_term(client_t* client) {
    for (uint32_t i = 0; i < client->count; i++) {
        block_t* entry = &client->data[i];
        if (entry->data.buf != NULL) {
            free(entry->data.buf);
            entry->data.buf = NULL;
        }
    }
}


/* Acquire trusted timestamps */
static int client_run(client_t* client) {
    const struct timespec ts = {
        .tv_sec = client->request_delay_ms / 1000,
        .tv_nsec = (client->request_delay_ms % 1000) * 1000000
    };
    
    for (uint32_t i = 0; i < client->count; i++) {
        if (client->request_delay_ms != 0) {
            nanosleep(&ts, NULL);
        }

        /* Send request */
        block_t* b = &client->data[i];
        proxy_request_t* req = &b->req;
        if (client->verbosity >= VERBOSITY_MIN) {
            print_proxy_req("Sending request", req);
            fprintf(stdout, "%7s : %s\n", "PATH", b->data.path);
            fprintf(stdout, "%7s : %u\n\n", "LENGTH", b->data.len);
        }

        int sts = gaps_packet_write(client->gaps.wr, req, sizeof(*req));
        if (sts == -1) {
            fprintf(stderr, "Failed to send signing request to proxy\n");
            return -1;
        }

        /* Get response */
        sts = gaps_packet_read(client->gaps.rd, &b->rsp, sizeof(b->rsp));
        if (sts != sizeof(b->rsp)) {
            fprintf(stderr, "Failed to receive response\n");
            return -1;
        }

        if (client->verbosity >= VERBOSITY_MIN) {
            print_proxy_sign_response(&b->rsp);
        }

        /* Optionally validate the signature */
        if (client->validate != 0) {
            fprintf(stdout, "Validate: TODO\n");
        }

        /* Optionally save the timestamp signature */
        if (client->save != 0) {
            fprintf(stdout, "Save: TODO\n");
        }
    }

    return 0;
}


/* Initialize client resources */
static int client_init(client_t* client) {
    /* Initialize GAPS channels */
    if (gaps_init(client) != 0) {
        fprintf(stderr, "Failed to initialize GAPS channels\n");
        return -1;
    }

    /* Read in test data */
    if (data_init(client) != 0) {
        fprintf(stderr, "Failed to read test data\n");
        return -1;
    }

    return 0;
}

/* Release client resources */
static void client_term(client_t* client) {
    /* Release test data */
    data_term(client);

    /* Close GAPS channels */
    gaps_term(client);
}


int main(int argc, char* argv[]) {
    /* Parse command-line options */
    client_t client;
    memset(&client, 0, sizeof(client));
    parse_args(argc, argv, &client);

    /* Initialize client resources */
    if (client_init(&client) != 0) {
        fprintf(stderr, "Failed to initialize client resources\n");
        client_term(&client);
        return -1;
    }

    /* Acquire trusted timestamps */
    if (client_run(&client) != 0) {
        fprintf(stderr, "Failed to acquire trusted timestamps\n");
        client_term(&client);
        return -1;
    }

    /* Release client resources */
    client_term(&client);
    return 0;
}

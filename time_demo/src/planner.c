#include <argp.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "gaps_packet.h"
#include "ts_crypto.h"
#include "common.h"

#define MAX_INPUT_COUNT 128

typedef struct {
    char path[PATH_MAX];
    uint32_t len;

    proxy_request_t req;
    tsa_response_t rsp;
} client_data_t;

typedef struct {
    uint32_t validate;
    uint32_t save;
    uint32_t request_delay_ms;
    verbosity_level_t verbosity;

    client_data_t data[MAX_INPUT_COUNT];
    uint32_t count;

    gaps_channel_pair_t gaps;
} client_t;

static client_t client_g;

static struct argp_option options[]  = {
    { "validate",  'V', NULL, 0, "Validate timestamp signatures", 0 },
    { "save",      's', NULL, 0, "Save timestamp signatures",     0 },
    { "req_delay", 'd', "MS", 0, "Request delay in milliseconds", 0 },
    { "verbose",   'v', NULL, 0, "Increase verbosity level",      0 },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    client_t *client = (client_t*) state->input;
    

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
    {
        struct stat sb;
        client_data_t *d = NULL;
        if (client->count >=  MAX_INPUT_COUNT) {
            argp_failure(state, 1, 0, "exceeded input limit");
        }

        d = &client->data[client->count++];
        if (realpath(arg, d->path) == NULL) {
            argp_failure(state, 1, 0, "failed to resolve %s path\n", arg);
        }

        if (stat(d->path, &sb) != 0) {
            argp_failure(state, 1, 0, "Failed to stat %s\n", d->path);
        }

        d->len = sb.st_size;
    }
        break;

    case ARGP_KEY_END:
        if (client->count == 0) {
            argp_failure(state, 1, 0, "no input files");
        }
        break;

    default:
        break;
    }
    
    return 0;
}


static void parse_args(int argc, char *argv[], client_t *client) {
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
static int gaps_init(client_t *client) {
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
static void gaps_term(client_t *client) {
    if (client->gaps.wr != -1) {
        pirate_close(client->gaps.wr, O_WRONLY);
        client->gaps.wr = -1;
    }
    
    if (client->gaps.rd != -1) {
        pirate_close(client->gaps.rd, O_RDONLY);
        client->gaps.rd = -1;
    }
}


/* Save timestamp sign response to a file */
static int client_save_ts_response(const client_data_t *data, uint32_t idx) {
    char path[PATH_MAX];

    if ((data->rsp.status) != OK || (data->rsp.len == 0)) {
        return 0;
    }

    snprintf(path, sizeof(path)-1, "%s_%02u.tsr", data->path, idx);

    fprintf(stdout, " === SAVE === %s\n", path);
    return 0;
}


/* Acquire trusted timestamps */
static int client_run(client_t *client) {
    const struct timespec ts = {
        .tv_sec = client->request_delay_ms / 1000,
        .tv_nsec = (client->request_delay_ms % 1000) * 1000000
    };
    
    for (uint32_t i = 0; i < client->count; i++) {
        client_data_t *d = &client->data[i];

        if (client->request_delay_ms != 0) {
            nanosleep(&ts, NULL);
        }

        /* Compose a request */
        if (ts_create_request(d->path, &d->req) != 0) {
            fprintf(stderr, "Failed to generate TS request\n");
            return -1;
        }

        /* Send request */
        int sts = gaps_packet_write(client->gaps.wr, &d->req, sizeof(d->req));
        if (sts == -1) {
            fprintf(stderr, "Failed to send signing request to proxy\n");
            return -1;
        }

        if (client->verbosity >= VERBOSITY_MIN) {
            print_proxy_request("SENT", &d->req);
            fprintf(stdout, "%7s : %s\n", "PATH", d->path);
            fprintf(stdout, "%7s : %u\n\n", "LENGTH", d->len);
        }

        /* Get response */
        sts = gaps_packet_read(client->gaps.rd, &d->rsp, sizeof(d->rsp));
        if (sts != sizeof(d->rsp)) {
            fprintf(stderr, "Failed to receive response\n");
            return -1;
        }

        if (client->verbosity >= VERBOSITY_MIN) {
            print_tsa_response("RECEIVED", &d->rsp);
        }

        /* Optionally validate the signature */
        if (client->validate != 0) {
            if (ts_validate(d->path, &d->rsp) == 0) {
                fprintf(stdout, "Timestamp VALIDATED\n");
            } else {
                fprintf(stdout, "FAILED to validate the timestamp\n");
            }
            fflush(stdout);
        }

        /* Optionally save the timestamp signature */
        if (client->save != 0) {
            if (client_save_ts_response(d, i) != 0) {
                fprintf(stderr, "Failed to save timestamp response\n");
            }
        }
    }

    return 0;
}


int main(int argc, char *argv[]) {
    /* Parse command-line options */
    parse_args(argc, argv, &client_g);

    /* Initialize client resources */
    if (gaps_init(&client_g) != 0) {
        fprintf(stderr, "Failed to initialize GAPS resources\n");
        gaps_term(&client_g);
        return -1;
    }

    /* Acquire trusted timestamps */
    if (client_run(&client_g) != 0) {
        fprintf(stderr, "Failed to acquire trusted timestamps\n");
        gaps_term(&client_g);
        return -1;
    }

    /* Release client resources */
    gaps_term(&client_g);
    return 0;
}

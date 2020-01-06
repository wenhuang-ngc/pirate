#include <argp.h>
#include <stdio.h>
#include "gaps_packet.h"
#include "common.h"
#include "ts_crypto.h"

typedef struct {
    verbosity_level_t verbosity;

    struct {
        const char *conf_file;
        const char *conf_sect;
        void *tsa;
    } ts;

    gaps_channel_pair_t gaps;
} signer_t;

signer_t signer_g;

/* Command-line options */
const char *argp_program_version = DEMO_VERSION;
static struct argp_option options[] = {
    { "conf",      'c', "PATH",    0, "Configuration file path",    0 },
    { "conf_sect", 's', "SECTION", 0, "Configuration section",      0 },
    { "verbose",   'v', NULL,      0, "Increase verbosity level",   0 },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    signer_t *signer = (signer_t *) state->input;

    switch (key) {

    case 'c':
        signer->ts.conf_file = arg;
        break;

    case 's':
        signer->ts.conf_sect = arg;
        break;

    case 'v':
        if (signer->verbosity < VERBOSITY_MAX) {
            signer->verbosity++;
        }
        break;

    default:
        break;

    }

    return 0;
}


static void parse_args(int argc, char *argv[], signer_t *signer) {
    struct argp argp = {
        .options = options,
        .parser = parse_opt,
        .args_doc = NULL,
        .doc = "Timestamp signing service",
        .children = NULL,
        .help_filter = NULL,
        .argp_domain = NULL
    };

    /* Default values */
    signer->ts.conf_file = DEFAULT_CONF_PATH;
    signer->ts.conf_sect = DEFAULT_CONF_SECTION;
    argp_parse(&argp, argc, argv, 0, 0, signer);
}


/* Initialize GAPS channels */
static int gaps_init(signer_t *signer) {
    signer->gaps.wr = signer->gaps.rd = -1;

    if ((pirate_set_channel_type(PROXY_TO_SIGNER, GAPS_CH_TYPE) != 0) ||
        (pirate_set_channel_type(SIGNER_TO_PROXY, GAPS_CH_TYPE) != 0)) {
        perror("Failed to set GAPS channel type\n");
        return -1;
    }

    signer->gaps.rd = pirate_open(PROXY_TO_SIGNER, O_RDONLY);
    if (signer->gaps.rd == -1) {
        perror("Failed to open proxy to timestamp service GAPS RD channel\n");
        return -1;
    }

    signer->gaps.wr = pirate_open(SIGNER_TO_PROXY, O_WRONLY);
    if (signer->gaps.wr == -1) {
        perror("Failed to open timestamp service to proxy GAPS WR channel\n");
        return -1;
    }

    return 0;
}

/* Close GAPS channels */
static void gaps_term(signer_t *signer) {
    if (signer->gaps.rd != -1) {
        pirate_close(signer->gaps.rd, O_RDONLY);
        signer->gaps.rd = -1;
    }

    if (signer->gaps.wr != -1) {
        pirate_close(signer->gaps.wr, O_WRONLY);
        signer->gaps.wr = -1;
    }
}


/* Run the signer */
static int signer_run(signer_t *signer) {
    ssize_t len;
    tsa_request_t req;
    tsa_response_t rsp;

    while (1) {
        /* Receive sign request */
        len = gaps_packet_read(signer->gaps.rd, &req, sizeof(req));
        if (len != sizeof(req)) {
            fprintf(stderr, "Failed to receive sign request\n");
            return -1;
        }

        if (signer->verbosity >= VERBOSITY_MIN) {
            fprintf(stdout, "TSA request received\n");
            if (signer->verbosity >= VERBOSITY_MAX) {
                print_tsa_request(&req);
            }
            fflush(stdout);
        }

        /* Sign with a timestamp */
        ts_sign(signer->ts.tsa, &req, &rsp);

        /* Reply */
        if (gaps_packet_write(signer->gaps.wr, &rsp, sizeof(rsp)) != 0) {
            fprintf(stderr, "Failed to send sign response\n");
            return -1;
        }

        if (signer->verbosity >= VERBOSITY_MIN) {
            fprintf(stdout, "TSA response sent\n");
            if (signer->verbosity >= VERBOSITY_MAX) {
                print_tsa_response(&rsp);
            }
            fflush(stdout);
        }
    }

    return 0;  /* Should never get here */
}

/* Initialize the signer */
static int signer_init(signer_t *signer) {
    /* Initialize GAPS channels */
    if (gaps_init(signer) != 0) {
        fprintf(stderr, "Failed to initialize GAPS channels\n");
        return -1;
    }

    /* Initialize the timestamp authority */
    signer->ts.tsa = ts_init(signer->ts.conf_file, signer->ts.conf_sect);
    if (signer->ts.tsa == NULL) {
        fprintf(stderr, "Failed to initialize timestamp context\n");
        return -1;
    }

    return 0;
}

/* Release signer resources */
static void signer_term(signer_t *signer) {
    /* Terminate the timestamp authority */
    ts_term(signer->ts.tsa);
    signer->ts.tsa = NULL;

    /* Close GAPS channels */
    gaps_term(signer);
}


int main(int argc, char *argv[]) {
    /* Parse command-line options */
    parse_args(argc, argv, &signer_g);

    /* Initialize the signer */
    if (signer_init(&signer_g) != 0) {
        fprintf(stderr, "Failed to initialize the signer\n");
        signer_term(&signer_g);
        return -1;
    }

    /* Run the signer */
    if (signer_run(&signer_g) != 0) {
        fprintf(stderr, "Failed to run the signer\n");
        signer_term(&signer_g);
        return -1;
    }

    /* Release signer resources */
    signer_term(&signer_g);
    return 0;
}

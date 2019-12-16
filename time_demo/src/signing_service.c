#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

#include "gaps_packet.h"
#include "common.h"

typedef struct {
    struct {
        char path[PATH_MAX];
        char sect[32];
        CONF* conf;
    } conf;

    TS_RESP_CTX* ctx;
} tsa_t;

typedef struct {
    verbosity_level_t verbosity;
    tsa_t tsa;
    gaps_channel_pair_t gaps;
} signer_t;

/* Command-line options */
const char* argp_program_version = DEMO_VERSION;
static struct argp_option options[] = {
    { "conf",      'c', "PATH",    0, "Configuration file path",    0 },
    { "conf_sect", 's', "SECTION", 0, "Configuration section",      0 },
    { "verbose",   'v', NULL,      0, "Increase verbosity level",   0 },
    { 0 }
};

/* Default values */
#define DEFAULT_CONF_PATH    "pki/tsa.conf"
#define DEFAULT_CONF_SECTION "tsa"
#define OID_SECTION          "oids"

static error_t parse_opt(int key, char* arg, struct argp_state* state) {
    signer_t* signer = (signer_t *) state->input;

    switch (key) {

    case 'c':
        strncpy(signer->tsa.conf.path, arg, sizeof(signer->tsa.conf.path));
        break;

    case 's':
        strncpy(signer->tsa.conf.sect, arg, sizeof(signer->tsa.conf.sect));
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


static void parse_args(int argc, char* argv[], signer_t* signer) {
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
    tsa_t* tsa = &signer->tsa;
    strncpy(tsa->conf.path, DEFAULT_CONF_PATH, sizeof(tsa->conf.path));
    strncpy(tsa->conf.sect, DEFAULT_CONF_SECTION, sizeof(tsa->conf.sect));
    argp_parse(&argp, argc, argv, 0, 0, signer);
}


/* Initialize GAPS channels */
static int gaps_init(signer_t* signer) {
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
static void gaps_term(signer_t* signer) {
    if (signer->gaps.rd != -1) {
        pirate_close(signer->gaps.rd, O_RDONLY);
        signer->gaps.rd = -1;
    }

    if (signer->gaps.wr != -1) {
        pirate_close(signer->gaps.wr, O_WRONLY);
        signer->gaps.wr = -1;
    }
}


/* Load configuration file */
static int tsa_load_config_file(tsa_t* tsa) {
    BIO* f_in = BIO_new_file(tsa->conf.path, "rb");
    if (f_in == NULL) {
        fprintf(stderr, "Failed to open %s\n", tsa->conf.path);
        return -1;
    }

    if ((tsa->conf.conf = NCONF_new(NULL)) == NULL) {
        perror("Failed to create new CONF");
        return -1;
    }

    long err_line = -1;
    int sts = NCONF_load_bio(tsa->conf.conf, f_in, &err_line);
    if (sts <= 0) {
        if (err_line <= 0) {
            fprintf(stderr, "Cannot load %s\n", tsa->conf.path);
        } else {
            fprintf(stderr, "%s: error on line %lu", tsa->conf.path, err_line);
        }

        NCONF_free(tsa->conf.conf);
        tsa->conf.conf = NULL;
        return -1;
    }

    /* Add object identifiers */
    STACK_OF(CONF_VALUE)* oids = NULL;
    if ((oids = NCONF_get_section(tsa->conf.conf, OID_SECTION)) == NULL) {
        fprintf(stderr, "Failed to load config section %s\n", OID_SECTION);
        return -1;
    }

    for (int i = 0; i < sk_CONF_VALUE_num(oids); i++) {
        CONF_VALUE* c = sk_CONF_VALUE_value(oids, i);
        if (OBJ_create(c->value, c->name, c->name) == NID_undef) {
            fprintf(stderr, "Error creating object %s=%s\n", c->name, c->value);
            return -1;
        }
    }

    return 0;
}

/* Release configuration file */
static void tsa_release_config_file(tsa_t* tsa) {
    if (tsa->conf.conf != NULL) {
        NCONF_free(tsa->conf.conf);
        tsa->conf.conf = NULL;
    }
}

/* Build a random 160-bit number for each request */
static ASN1_INTEGER* tsa_serial_cb() {
    unsigned char rand_bytes[20] = { 0 };
    BIGNUM* big_num = NULL;
    ASN1_INTEGER* ret = NULL;

    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        perror("Failed to generate random bytes");
        return NULL;
    }

    if ((big_num = BN_new()) == NULL) {
        perror("Failed to create a new BIGNUM");
        return NULL;
    }

    BN_bin2bn(rand_bytes, sizeof(rand_bytes), big_num);
    
    if ((ret = ASN1_INTEGER_new()) == NULL) {
        perror("Failed to create a new ASN1_INTEGER");
        BN_free(big_num);
        return NULL;
    }

    BN_to_ASN1_INTEGER(big_num, ret);

    BN_free(big_num);
    return ret;
}

/* Print last OpenSSL error */
static void tsa_print_err(const char* err) {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    BIO_get_mem_data(bio, &buf);
    fprintf(stderr, "%s : %s\n", err, buf);
    BIO_free(bio);
}

/* Create and initialize the OpenSSL Time-Stamp Response Context */
static int tsa_create_ctx(tsa_t* tsa) {
    CONF* conf = tsa->conf.conf;
    const char* sect = tsa->conf.sect;

    if ((tsa->ctx = TS_RESP_CTX_new()) == NULL) {
        tsa_print_err("Failed to allocate new TimeStamp Response Context");
        return -1;
    }

    TS_RESP_CTX_set_serial_cb(tsa->ctx, tsa_serial_cb, NULL);

    if (TS_CONF_set_crypto_device(conf, sect, NULL) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_crypto_device");
        return -1;
    }

    if (TS_CONF_set_signer_cert(conf, sect, NULL, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_signer_cert");
        return -1;
    }

    if (TS_CONF_set_certs(conf, sect, NULL, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_certs");
        return -1;
    }

    if (TS_CONF_set_signer_key(conf, sect, NULL, NULL, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_signer_key");
        return -1;
    }

    if (TS_CONF_set_def_policy(conf, sect, NULL, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_def_policy");
        return -1;
    }

    if (TS_CONF_set_policies(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_policies");
        return -1;
    }

    if (TS_CONF_set_digests(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_digests");
        return -1;
    }

    if (TS_CONF_set_accuracy(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_accuracy");
        return -1;
    }

    if (TS_CONF_set_clock_precision_digits(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_clock_precision_digits");
        return -1;
    }

    if (TS_CONF_set_ordering(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_ordering");
        return -1;
    }

    if (TS_CONF_set_tsa_name(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_tsa_name");
        return -1;
    }

    if (TS_CONF_set_ess_cert_id_chain(conf, sect, tsa->ctx) == 0) {
        tsa_print_err("FAIL:TS_CONF_set_ess_cert_id_chain");
        return -1;
    }

    tsa_print_err("Context OK");
    printf("LINE: %d\n", __LINE__);

    return 0;
}

/* Release the OpenSSL Time-Stamp Response Context */
static void tsa_release_ctx(tsa_t* tsa) {
    if (tsa->ctx != NULL) {
        TS_RESP_CTX_free(tsa->ctx);
        tsa->ctx = NULL;
    }
}

/* Timestamp-sign the message TODO*/
static int tsa_sign(tsa_t* tsa, tsa_request_t* req, tsa_response_t* rsp) {
    (void) rsp;

    BIO* q_bio = BIO_new_mem_buf(req->h_r, sizeof(req->h_r));
    if (q_bio == NULL) {
        tsa_print_err("Failed to parse query");
        return -1;
    }

    TS_RESP* ts_rsp = TS_RESP_create_response(tsa->ctx, q_bio);
    if (ts_rsp == NULL) {
        tsa_print_err("Failed to create TS response");
        return -1;
    }

    char** rsp_buf = NULL;
    size_t rsp_len = 0;
    FILE* stream  = open_memstream(rsp_buf, &rsp_len);
    if (stream == NULL) {
        fprintf(stderr, "Failed to create memory stream\n");
        return -1;
    }
    int sts =  i2d_TS_RESP_fp(stream, ts_rsp);
    //fflush(stream);
    //fclose(stream);


    //BIO* bio_rsp = BIO_new_mem_buf(test, sizeof(test));
    //sts = i2d_TS_RESP_bio(bio_rsp, ts_rsp);

    BIO_free_all(q_bio);

    printf("\n\n === SIGNED STS = %d=== \n\n", sts);

    return 0;
}


/* Initialize the timestamp authority */
static int tsa_init(tsa_t* tsa) {
    /* Load configuration file */
    if (tsa_load_config_file(tsa) != 0) {
        fprintf(stderr, "Failed to load configuration file\n");
        return -1;
    }

    /* Create and initialize the OpenSSL Time-Stamp Response Context */
    if (tsa_create_ctx(tsa) != 0) {
        fprintf(stderr, "Failed to create OpenSSL timestamp context\n");
        return -1;
    }

    return 0;
}

/* Release timestamp authority resources */
static void tsa_term(tsa_t* tsa) {
    /* Release the configuration file */
    tsa_release_config_file(tsa);

    /* Release the OpenSSL Time-Stamp Response Context */
    tsa_release_ctx(tsa);
}


/* Run the signer */
static int signer_run(signer_t* signer) {
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
            print_tsa_request("Request received", &req);
        }

        /* Sign with a timestamp */
        if (tsa_sign(&signer->tsa, &req, &rsp) != 0) {
            fprintf(stderr, "Failed to timestamp-sign the message\n");
            return -1;
        }

        /* Reply */
        rsp.status = OK;
        if (gaps_packet_write(signer->gaps.wr, &rsp, sizeof(rsp)) != 0) {
            fprintf(stderr, "Failed to send sign response\n");
            return -1;
        }

        if (signer->verbosity >= VERBOSITY_MIN) {
            print_tsa_response("TSA response sent", &rsp);
        }
    }

    return 0;  /* Should never get here */
}

/* Initialize the signer */
static int signer_init(signer_t* signer) {
    /* Initialize GAPS channels */
    if (gaps_init(signer) != 0) {
        fprintf(stderr, "Failed to initialize GAPS channels\n");
        return -1;
    }

    /* Initialize the timestamp authority */
    if (tsa_init(&signer->tsa) != 0) {
        fprintf(stderr, "Failed to initialize timestamp authority\n");
        return -1;
    }

    return 0;
}

/* Release signer resources */
static void signer_term(signer_t* signer) {
    /* Terminate the timestamp authority */
    tsa_term(&signer->tsa);

    /* Close GAPS channels */
    gaps_term(signer);
}


int main(int argc, char* argv[]) {
    /* Parse command-line options */
    signer_t signer;
    memset(&signer, 0, sizeof(signer));
    parse_args(argc, argv, &signer);

    /* Initialize the signer */
    if (signer_init(&signer) != 0) {
        fprintf(stderr, "Failed to initialize the signer\n");
        signer_term(&signer);
        return -1;
    }

    /* Run the signer */
    if (signer_run(&signer) != 0) {
        fprintf(stderr, "Failed to run the signer\n");
        signer_term(&signer);
        return -1;
    }

    /* Release signer resources */
    signer_term(&signer);
    return 0;
}

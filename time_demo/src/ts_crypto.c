#include <stdio.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include "ts_crypto.h"

typedef struct {
    CONF *conf;
    TS_RESP_CTX *ctx;
} tsa_t;

static void print_err(const char *msg) {
    char *err_str = NULL;
    BIO *err_bio = BIO_new(BIO_s_mem());
    if (err_bio == NULL) {
        fprintf(stderr, "%s: failed to allocate error buffer\n", msg);
        return;
    }

    ERR_print_errors(err_bio);

    if (BIO_get_mem_data(err_bio, &err_str) != 1) {
        fprintf(stderr, "%s: failed to get error data\n", msg);
        goto end;
    }

    fprintf(stderr, "%s : %s\n", msg, err_str);
end:
    BIO_free(err_bio);
}



/* Load configuration file */
static int ts_load_config(tsa_t *tsa, const char *path) {
    long err_line = -1;
    BIO *f_in = NULL;
    STACK_OF(CONF_VALUE) *oids = NULL;

    if ((f_in = BIO_new_file(path, "rb")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        return -1;
    }

    if ((tsa->conf = NCONF_new(NULL)) == NULL) {
        print_err("Failed to create new CONF");
        return -1;
    }

    if (NCONF_load_bio(tsa->conf, f_in, &err_line) <= 0) {
        if (err_line <= 0) {
            fprintf(stderr, "Cannot load %s\n", path);
        } else {
            fprintf(stderr, "%s: error on line %lu", path, err_line);
        }

        NCONF_free(tsa->conf);
        tsa->conf = NULL;
        return -1;
    }

    /* Add object identifiers */
    if ((oids = NCONF_get_section(tsa->conf, OID_SECTION)) == NULL) {
        fprintf(stderr, "Failed to load config section %s\n", OID_SECTION);
        return -1;
    }

    for (int i = 0; i < sk_CONF_VALUE_num(oids); i++) {
        CONF_VALUE *c = sk_CONF_VALUE_value(oids, i);
        if (OBJ_create(c->value, c->name, c->name) == NID_undef) {
            fprintf(stderr, "Error creating object %s=%s\n", c->name, c->value);
            return -1;
        }
    }

    return 0;
}

/* Release configuration file */
static void ts_release_config(tsa_t *tsa) {
    if (tsa->conf != NULL) {
        NCONF_free(tsa->conf);
        tsa->conf = NULL;
    }
}


static ASN1_INTEGER *next_serial(const char *serial_file) {
    int ret = -1;
    (void) serial_file;

    ASN1_INTEGER *serial = NULL;

    if ((serial = ASN1_INTEGER_new()) == NULL) {
        print_err("Failed to allocate new ASN1 integer");
        goto end;
    }

    if (ASN1_INTEGER_set(serial, 1) != 1) {
        print_err("Failed to set ASN1 integer value");
        goto end;
    }

    ret = 0;
end:
    if (ret != 0) {
        ASN1_INTEGER_free(serial);
        serial = NULL;
    }
    return serial;
}

// TODO
static int save_ts_serial(const char *serial_file, ASN1_INTEGER *serial) {
    (void) serial_file;
    (void) serial;
#if 0
    int ret = -1;
    BIO* out = NULL;
    (void) serial;

    if ((out = BIO_new_file(serial_file, "w")) == NULL) {
        print_err("Failed to create new serial file");
        goto end;
    }

    if (i2d_ASN1_INTEGER(out, serial) <= 0) {
        print_err("Failed to place serial number into BIO");
        goto end;
    }

    if (BIO_puts(out, "\n") <= 0) {
        print_err("Failed to write newline to the serial file");
        goto end;
    }

    ret = 0;
end:
    BIO_free_all(out);
    return ret;
#endif
    return 0;
}


static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data) {
    const char *serial_file = (const char *)data;
    ASN1_INTEGER *serial = next_serial(serial_file);

    if (serial == NULL) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
            "Error during serial number generation.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
    } else {
        save_ts_serial(serial_file, serial);
    }

    return serial;
}


/* Create and initialize the OpenSSL Time-Stamp Response Context */
static int ts_ctx_init(tsa_t *tsa, const char *sect) {
    const char *section;

    if ((section = TS_CONF_get_tsa_section(tsa->conf, sect)) == NULL) {
        print_err("Failed to locate TSA configuration section");
        return -1;
    }

    if ((tsa->ctx = TS_RESP_CTX_new()) == NULL) {
        print_err("Failed to allocate new TimeStamp Response Context");
        return -1;
    }

    if ((TS_CONF_set_serial(tsa->conf, section, serial_cb, tsa->ctx)) != 1) {
        print_err("Failed to set TSA serial callback");
        return -1;
    }

    if (TS_CONF_set_crypto_device(tsa->conf, section, NULL) == 0) {
        print_err("FAIL:TS_CONF_set_crypto_device");
        return -1;
    }

    if (TS_CONF_set_signer_cert(tsa->conf, section, NULL, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_signer_cert");
        return -1;
    }

    if (TS_CONF_set_certs(tsa->conf, section, NULL, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_certs");
        return -1;
    }

    if (TS_CONF_set_signer_key(tsa->conf, section, NULL, NULL, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_signer_key");
        return -1;
    }

    if (TS_CONF_set_signer_digest(tsa->conf, section, NULL, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_signer_digest");
        return -1;
    }

    if (TS_CONF_set_ess_cert_id_digest(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_ess_cert_id_digest");
        return -1;
    }

    if (TS_CONF_set_def_policy(tsa->conf, section, NULL, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_def_policy");
        return -1;
    }

    if (TS_CONF_set_policies(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_policies");
        return -1;
    }

    if (TS_CONF_set_digests(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_digests");
        return -1;
    }

    if (TS_CONF_set_accuracy(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_accuracy");
        return -1;
    }

    if (TS_CONF_set_clock_precision_digits(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_clock_precision_digits");
        return -1;
    }

    if (TS_CONF_set_ordering(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_ordering");
        return -1;
    }

    if (TS_CONF_set_tsa_name(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_tsa_name");
        return -1;
    }

    if (TS_CONF_set_ess_cert_id_chain(tsa->conf, section, tsa->ctx) == 0) {
        print_err("FAIL:TS_CONF_set_ess_cert_id_chain");
        return -1;
    }

    printf(" === CONTEXT OK ===\n");
    return 0;
}


/* Release the OpenSSL Time-Stamp Response Context */
static void ts_ctx_term(tsa_t *tsa) {
    if (tsa->ctx != NULL) {
        TS_RESP_CTX_free(tsa->ctx);
        tsa->ctx = NULL;
    }
}

void *ts_init(const char *path, const char *sect) {
    tsa_t *tsa = NULL;

    /* Allocate the TSA handle */
    tsa = calloc(1, sizeof(*tsa));
    if (tsa == NULL) {
        perror("Failed to allocate TSA context");
        return NULL;
    }

    /* Load configuration file */
    if (ts_load_config(tsa, path) != 0) {
        fprintf(stderr, "Failed to load configuration file %s", path);
        free(tsa);
        return NULL;  
    }

    /* Initialize the context */
    if (ts_ctx_init(tsa, sect) != 0) {
        fprintf(stderr, "Failed to load configuration file %s", path);
        free(tsa);
        return NULL;  
    }

    return tsa;
}

void ts_term(void *ctx) {
    tsa_t *tsa = (tsa_t*)ctx;

    if (tsa == NULL) {
        return;
    }

    /* Release the context */
    ts_ctx_term(tsa);

    /* Release the configuration file */
    ts_release_config(tsa);

    /* Free the TSA handle */
    free(tsa);
}


/*
 * Generate SHA256 digest from the content of a file.
 * If path is NULL, then the output digest is filled with random data
 */
int ts_create_request(const char *path, proxy_request_t *req) {
    FILE *f = NULL;
    SHA256_CTX sha256;
    unsigned char buf[4096];
    int rd;
    int ret = -1;

    if (path == NULL) {
        if (RAND_bytes(req->digest, SHA256_DIGEST_LENGTH) != 1) {
            print_err("Failed to generate random digest");
            return -1;
        }

        return 0;
    }

    if ((f = fopen(path, "rb")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        return -1;
    }

    if (SHA256_Init(&sha256) != 1) {
        print_err("Failed to initialize SHA-256 context");
        goto end;
    }

    while ((rd = fread(buf, 1, sizeof(buf), f)) != 0) {
        if (SHA256_Update(&sha256, buf, rd) != 1) {
            print_err("Failed to update SHA-256 context");
            goto end;
        }
    }

    if (SHA256_Final(req->digest, &sha256) != 1) {
        print_err("Failed to finalize SHA-256 context");
        goto end;
    }

    ret = 0;
end:
    fclose(f);
    return ret;
}


static ASN1_INTEGER *create_nonce(unsigned len) {
    ASN1_INTEGER *nonce = NULL;
    unsigned char buf[32];
    unsigned off = 0;   // Offset of the first non-zero byte of the random data

    if (len >sizeof(buf)) {
        fprintf(stderr, "Max nonce size is %lu\n", sizeof(buf));
        goto err;
    }

    if (RAND_bytes(buf, len) != 1) {
        print_err("Failed to generate random nonce data");
        goto err;
    }

    for (off = 0; (off < len) && (buf[off] == 0); ++off) {
        continue;
    }

    if ((nonce = ASN1_INTEGER_new()) == NULL) {
        print_err("Failed to create ASN1 integer");
        goto err;
    }

    OPENSSL_free(nonce->data);
    nonce->length = len - off;
    if ((nonce->data = OPENSSL_malloc(nonce->length)) == NULL) {
        print_err("Failed to allocate nonce buffer");
        goto err;
    }

    memcpy(nonce->data, buf + off, nonce->length);

    printf(" === CREATE NONCE %u===\n", nonce->length);

    return nonce;
err:
    ASN1_INTEGER_free(nonce);
    return NULL;
}


int ts_create_query(const proxy_request_t *req, tsa_request_t *tsa_req) {
    int ret = -1;
    const EVP_MD *md = NULL;
    TS_REQ *ts_req = NULL;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    ASN1_INTEGER *nonce = NULL;
    BIO *ts_req_bio = NULL;
    unsigned char *ts_req_bio_raw = NULL;

    if ((md = EVP_get_digestbyname("sha256")) == NULL) {
        print_err("Failed to get SHA-256 hash by name");
        goto end;
    }

    if ((ts_req = TS_REQ_new()) == NULL) {
        print_err("Failed to create new TS request");
        goto end;
    }

    if (TS_REQ_set_version(ts_req, 1) != 1) {
        print_err("Failed to set TS version");
        goto end;  
    }

    if ((msg_imprint = TS_MSG_IMPRINT_new()) == NULL) {
        print_err("Failed to crate new message imprint");
        goto end;
    }

    if ((algo = X509_ALGOR_new()) == NULL) {
        print_err("Failed to create new x509 algorithm context");
        goto end;
    }

    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(md))) == NULL) {
        print_err("Failed to set the x509 algorithm");
        goto end;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL) {
        print_err("Failed to create ASN1 algorithm parameter");
        goto end;
    }
    algo->parameter->type = V_ASN1_NULL;

    if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1) {
        print_err("Failed to the algorithm in the message imprint");
        goto end;
    }

    if (TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)req->digest,
                                sizeof(req->digest)) != 1) {
        print_err("Failed to set message digest in the TS message");
        goto end;
    }

    if (TS_REQ_set_msg_imprint(ts_req, msg_imprint) != 1) {
        print_err("Failed to set message imprint in the request");
        goto end;
    }

    if ((nonce = create_nonce(NONCE_LENGTH)) == NULL) {
        fprintf(stderr, "Failed to generate nonce");
        goto end;
    }

    if ((TS_REQ_set_nonce(ts_req, nonce)) != 1) {
        print_err("Failed to set nonce in the TS request");
        goto end;
    }

    if (TS_REQ_set_cert_req(ts_req, 1) != 1) {
        print_err("Failed to set cert field in the TS request");
        goto end;
    }

    if ((ts_req_bio = BIO_new(BIO_s_mem())) == NULL) {
        print_err("Failed to create memory BIO");
        goto end;
    }

    if (i2d_TS_REQ_bio(ts_req_bio, ts_req) != 1) {
        print_err("Failed to get BIO from the TS request");
        goto end;
    }

    if ((tsa_req->len = BIO_get_mem_data(ts_req_bio, &ts_req_bio_raw)) <= 0) {
        print_err("Failed to get BIO memory");
        goto end;
    }

    if (tsa_req->len > sizeof(tsa_req->req)) {
        fprintf(stderr, "TS REQ exceeds size of %lu\n", sizeof(tsa_req->req));
        tsa_req->len = 0;
        goto end;
    }

    memcpy(tsa_req->req, ts_req_bio_raw, tsa_req->len);
    ret = 0;
end:
    TS_REQ_free(ts_req);
    TS_MSG_IMPRINT_free(msg_imprint);
    X509_ALGOR_free(algo);
    ASN1_INTEGER_free(nonce);
    BIO_free_all(ts_req_bio);

    return ret;
}


int ts_sign(void *ctx, const tsa_request_t *req, tsa_response_t *rsp) {
    (void) rsp;

    BIO *q_bio = NULL;
#if 0
    TS_RESP *ts_rsp = NULL;
#endif

    if ((q_bio = BIO_new_mem_buf(req->req, req->len)) == NULL) {
        print_err("Failed to create new BIO from a memory buffer");
        return -1;
    }

#if 0 // TODO: Fix
    ts_rsp = TS_RESP_create_response(ctx, q_bio);
    if (ts_rsp == NULL) {
        print_err("Failed to create TS response");
        return -1;
    }
#endif

#if 0
    char* *rsp_buf = NULL;
    size_t rsp_len = 0;
    FILE *stream  = open_memstream(rsp_buf, &rsp_len);
    if (stream == NULL) {
        fprintf(stderr, "Failed to create memory stream\n");
        return -1;
    }
    int sts =  i2d_TS_RESP_fp(stream, ts_rsp);
    //fflush(stream);
    //fclose(stream);


    //BIO *bio_rsp = BIO_new_mem_buf(test, sizeof(test));
    //sts = i2d_TS_RESP_bio(bio_rsp, ts_rsp);

    BIO_free_all(q_bio);

    printf("\n\n === SIGNED STS = %d=== \n\n", sts);
#endif

    // TODO
    for (uint32_t i = 0; i < 32; i++) {
        rsp->ts[i] = i & 0xFF;
    }
    rsp->len = 32;
    rsp->status = OK;

    BIO_free_all(q_bio);

    printf("=== SIGN %p ===\n", ctx);
    return 0;
}


int ts_validate(const char *path, tsa_response_t *rsp) {
    (void) path;
    (void) rsp;
    printf("=== VALIDATE ===\n");
    return 0;
}

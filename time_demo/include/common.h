#ifndef _COMMON_H_
#define _COMMON_H_

#include "primitives.h"
#include <openssl/sha.h>

/* GAPS channel assignments */
typedef enum {
    CLIENT_TO_PROXY = 0,
    PROXY_TO_CLIENT = 1,
    PROXY_TO_SIGNER = 2,
    SIGNER_TO_PROXY = 3
} demo_channel_t;

typedef struct {
    int wr;
    int rd;
} gaps_channel_pair_t;

typedef enum {
    OK,
    BUSY,
    ERR,
    UNKNOWN
} status_t;

const char *ts_status_str(status_t sts);

/* Verbosity levels */
typedef enum {
    VERBOSITY_NONE = 0,
    VERBOSITY_MIN  = 1,
    VERBOSITY_MAX  = 2
} verbosity_level_t;

/* GAPS channel type used for the demo */
#define GAPS_CH_TYPE PIPE

#define NONCE_LENGTH    8
#define MAX_REQ_LEN     128
#define MAX_TS_LEN      (8 << 10)

/* Structure passed from the client to the proxy */
typedef struct {
    unsigned char digest[SHA256_DIGEST_LENGTH];
} proxy_request_t;

/* Structure passed from the proxy to the signing service */
typedef struct {
    uint32_t len;
    unsigned char req[MAX_REQ_LEN];
} tsa_request_t;
#define TSA_REQUEST_INIT { .len = 0, .req = { 0 }}

/* Timestamp response */
typedef struct {
    status_t status;
    uint32_t len;
    uint8_t ts[MAX_TS_LEN];
} tsa_response_t;
#define TSA_RESPONSE_INIT { .status = UNKNOWN, .len = 0, .ts = { 0 } }

void print_proxy_request(const proxy_request_t *req);
void print_tsa_request(const tsa_request_t *req);
void print_tsa_response( const tsa_response_t* rsp);

#endif /* _COMMON_H_ */

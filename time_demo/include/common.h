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
    ERR
} status_t;

/* Verbosity levels */
typedef enum {
    VERBOSITY_NONE = 0,
    VERBOSITY_MIN  = 1,
    VERBOSITY_MAX  = 2
} verbosity_level_t;

/* GAPS channel type used for the demo */
#define GAPS_CH_TYPE PIPE

/* Structure passed from the client to the proxy */
#define REQ_ID_LEN 32
typedef struct {
    unsigned char n[REQ_ID_LEN];
    unsigned char h_d[SHA256_DIGEST_LENGTH];
} proxy_request_t;

/* Structure passed from the proxy to the signing service */
typedef struct {
    unsigned char h_r[SHA256_DIGEST_LENGTH];
} tsa_request_t;

/* Structure passed from the signing service back to the proxy */
#define REQ_RAND_LEN  REQ_ID_LEN
#define CR_LEN        32
typedef struct {
    status_t status;
    unsigned char c_r[CR_LEN];
} tsa_response_t;

/* Structure passed from the signing proxy back to the client */
typedef struct {
    status_t status;
    unsigned char n[REQ_ID_LEN];
    unsigned char r[REQ_RAND_LEN];
    unsigned char foo[CR_LEN];
} proxy_sign_response_t;

/* Helper printing routines */
void print_hex_str(const char* msg, const uint8_t* data, uint32_t len);
void print_proxy_req(const char* msg, const proxy_request_t* req);
void print_tsa_request(const char* msg, const tsa_request_t* req);
void print_tsa_response(const char* msg, const tsa_response_t* rsp);
void print_proxy_sign_response(const proxy_sign_response_t* rsp);

#endif /* _COMMON_H_ */

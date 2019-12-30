#ifndef _TS_CRYPTO_H_
#define _TS_CRYPTO_H_

#include "common.h"

#define DEFAULT_CONF_PATH    "pki/tsa.conf"
#define DEFAULT_CONF_SECTION "tsa"
#define OID_SECTION          "oids"

void *ts_init(const char *path, const char *sect);
void ts_term(void *ctx);
int ts_sign(void *ctx, const tsa_request_t *req, tsa_response_t *rsp);

int ts_create_request(const char *path, proxy_request_t *req);
int ts_create_query(const proxy_request_t *req, tsa_request_t *tsa_req);
int ts_validate(const char *path, tsa_response_t *rsp);

#endif /* _TS_CRYPTO_H_ */

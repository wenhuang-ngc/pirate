#include <stdio.h>
#include "common.h"

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


const char *ts_status_str(status_t sts) {
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

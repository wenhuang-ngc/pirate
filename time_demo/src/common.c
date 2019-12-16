#include <stdio.h>
#include "common.h"


void print_hex_str(const char* msg, const uint8_t* data, uint32_t len) {
    char str[1024];
    static char digits[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    
    if ((len << 1) + 1 > sizeof(str)) {
        fprintf(stderr, "Buffer %u too long\n", len);
        return;
    }

    for (uint32_t i = 0; i < len; i++) {
        const uint32_t off = i << 1;
        str[off + 1] = digits[data[i] & 0xF];
        str[off] = digits[data[i] >> 4];
    }
    str[len << 1] = '\0';

    fprintf(stdout, "%7s : %s\n", msg, str);
}


void print_proxy_req(const char* msg, const proxy_request_t* req) {
    fprintf(stdout, "\n%s\nProxy Sign Request:\n", msg);
    print_hex_str("N", req->n, sizeof(req->n));
    print_hex_str("H_D", req->h_d, sizeof(req->h_d));
    fflush(stdout);
}


void print_tsa_request(const char* msg, const tsa_request_t* req) {
    fprintf(stdout, "\n%s\nTimestamp Service Sign Request:\n", msg);
    print_hex_str("H_R", req->h_r, sizeof(req->h_r));
    fflush(stdout);
}


void print_tsa_response(const char* msg, const tsa_response_t* rsp) {
    fprintf(stdout, "\n%s\nTimestamp Service Sign Response:\n", msg);
    print_hex_str("C_R", rsp->c_r, sizeof(rsp->c_r));
    fflush(stdout);
}


void print_proxy_sign_response(const proxy_sign_response_t* rsp) {
    (void) rsp;
    fprintf(stdout, "Proxy Sign Response:\n");
    // TODO
    fflush(stdout);
}

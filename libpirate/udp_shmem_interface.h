/*
 * This work was authored by Two Six Labs, LLC and is sponsored by a subcontract
 * agreement with Galois, Inc.  This material is based upon work supported by
 * the Defense Advanced Research Projects Agency (DARPA) under Contract No.
 * HR0011-19-C-0103.
 *
 * The Government has unlimited rights to use, modify, reproduce, release,
 * perform, display, or disclose computer software or computer software
 * documentation marked with this legend. Any reproduction of technical data,
 * computer software, or portions thereof marked with this legend must also
 * reproduce this marking.
 *
 * Copyright 2020 Two Six Labs, LLC.  All rights reserved.
 */

#ifndef __PIRATE_CHANNEL_UDP_SHMEM_INTERFACE_H
#define __PIRATE_CHANNEL_UDP_SHMEM_INTERFACE_H

#include "shmem_buffer.h"

#define DEFAULT_UDP_SHMEM_PACKET_COUNT  1000
#define DEFAULT_UDP_SHMEM_PACKET_SIZE   1024

typedef struct {
    char path[PIRATE_SHMEM_LEN_NAME];
    unsigned buffer_size;
    size_t packet_size;
    size_t packet_count;
} pirate_udp_shmem_param_t;

typedef struct {
    int flags;
    shmem_buffer_t *buf;
    pirate_udp_shmem_param_t param;
} pirate_udp_shmem_ctx_t;

int pirate_udp_shmem_init_param(int gd, int flags,
                            pirate_udp_shmem_param_t *param);
int pirate_udp_shmem_parse_param(int gd, int flags, char *str, 
                                    pirate_udp_shmem_param_t *param);
int pirate_udp_shmem_set_param(pirate_udp_shmem_ctx_t *ctx,
                            const pirate_udp_shmem_param_t *param);
int pirate_udp_shmem_get_param(const pirate_udp_shmem_ctx_t *ctx, 
                            pirate_udp_shmem_param_t *param);
int pirate_udp_shmem_open(int gd, int flags, pirate_udp_shmem_ctx_t *ctx);
int pirate_udp_shmem_close(pirate_udp_shmem_ctx_t *ctx);
ssize_t pirate_udp_shmem_read(pirate_udp_shmem_ctx_t *ctx, void *buf,
                            size_t count);
ssize_t pirate_udp_shmem_write(pirate_udp_shmem_ctx_t *ctx, const void *buf,
                            size_t count);
#endif /* __PIRATE_CHANNEL_UDP_SHMEM_INTERFACE_H */
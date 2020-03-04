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

#ifndef __PIRATE_CHANNEL_DEVICE_H
#define __PIRATE_CHANNEL_DEVICE_H

#include <sys/types.h>

#define PIRATE_DEVICE_LEN_NAME 64

typedef struct {
    char path[PIRATE_DEVICE_LEN_NAME];
    unsigned iov_len;
} pirate_device_param_t;

typedef struct {
    int fd;
    pirate_device_param_t param;
} pirate_device_ctx_t;

int pirate_device_init_param(int gd, int flags, pirate_device_param_t *param);
int pirate_device_parse_param(int gd, int flags, char *str,
                                pirate_device_param_t *param);
int pirate_device_set_param(pirate_device_ctx_t *ctx,
                            const pirate_device_param_t *param);
int pirate_device_get_param(const pirate_device_ctx_t *ctx,
                            pirate_device_param_t *param);
int pirate_device_open(int gd, int flags, pirate_device_ctx_t *ctx);
int pirate_device_close(pirate_device_ctx_t *ctx);
ssize_t pirate_device_read(pirate_device_ctx_t *ctx, void *buf, size_t count);
ssize_t pirate_device_write(pirate_device_ctx_t *ctx, const void *buf, 
                            size_t count);

#endif /*__PIRATE_CHANNEL_DEVICE_H */
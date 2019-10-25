#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "primitives.h"

typedef struct {
    int fd;             // pipe file descriptor
} pirate_channel_t;

static pirate_channel_t readers[PIRATE_NUM_CHANNELS] = {0};
static pirate_channel_t writers[PIRATE_NUM_CHANNELS] = {0};

extern pirate_channel_desc_t pirate_channels[];

void __attribute__ ((destructor(PIRATE_DTOR_PRIO))) pirate_channel_term() {
    pirate_channel_desc_t* ch;
    for (ch = pirate_channels; ch->num != PIRATE_INVALID_CHANNEL; ch++) {
        if (ch->gd < 0) {
            continue;
        }

        pirate_close(ch->num, ch->flags);
        ch->gd = -1;

        printf("TERM: %s (%s) channel closed: CH %d\n", ch->desc, 
            ch->flags == O_RDONLY ? "RD" : 
            ch->flags == O_WRONLY ? "WR" : "ERR",
            ch->num);        
    }
}

void __attribute__ ((constructor(PIRATE_CTOR_PRIO)))
pirate_channel_init(int argc, char* argv[], char* envp[]) {
    (void) argc, (void)argv, (void) envp;
    pirate_channel_desc_t* ch;

    /*
     * The destructor will only be called when main returns, ensure that other
     * cases are covered
     */
    if (atexit(pirate_channel_term) != 0) {
        perror("Failed to add at exit code\n");
        exit(-1);
    }

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = pirate_channel_term;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Failed to register SIGINT handler\n");
        exit(-1);
    }

    /* Open configured channels */
    for (ch = pirate_channels; ch->num != PIRATE_INVALID_CHANNEL; ch++)
    {
        ch->gd = pirate_open(ch->num, ch->flags);
        if (ch->gd == -1) {
            printf("Failed to open write channel\n");
            exit(-1);
        }

        printf("INIT: %s (%s) channel created: CH %d\n", ch->desc, 
            ch->flags == O_RDONLY ? "RD" : 
            ch->flags == O_WRONLY ? "WR" : "ERR",
            ch->num);
    }
}

// gaps descriptors must be opened from smallest to largest
int pirate_open(int gd, int flags) {
    pirate_channel_t* channels;
    int fd, rv;
    char pathname[PIRATE_LEN_NAME];

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    if ((flags != O_RDONLY) && (flags != O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }

    if (flags == O_RDONLY) {
        channels = readers;
    } else {
        channels = writers;
    }

    fd = channels[gd].fd;
    if (fd > 0) {
        return gd;
    }

    /* Create a named pipe, if one does not exist */
    snprintf(pathname, sizeof(pathname) - 1, PIRATE_FILENAME, gd);
    rv = mkfifo(pathname, 0660);
    if ((rv == -1) && (errno != EEXIST)) {
        return -1;
    }

    fd = open(pathname, flags);
    if (fd < 0) {
        return -1;
    }

    /* Success */
    channels[gd] = (pirate_channel_t){fd};
    return gd;
}

int pirate_close(int gd, int flags) {
    pirate_channel_t* channels;
    int fd;

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    if ((flags != O_RDONLY) && (flags != O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }

    if (flags == O_RDONLY) {
        channels = readers;
    } else {
        channels = writers;
    }

    fd = channels[gd].fd;
    if (fd <= 0) {
        errno = ENODEV;
        return -1;
    }

    channels[gd].fd = 0;
    return close(fd);
}

ssize_t pirate_read(int gd, void *buf, size_t count) {
    int fd;

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    fd = readers[gd].fd;
    if (fd <= 0) {
        errno = EBADF;
        return -1;
    }

    return read(fd, buf, count);
}

ssize_t pirate_write(int gd, const void *buf, size_t count) {
    int fd;

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    fd = writers[gd].fd;
    if (fd <= 0) {
        errno = EBADF;
        return -1;
    }

    return write(fd, buf, count);
}

int pirate_fcntl0(int gd, int flags, int cmd) {
    pirate_channel_t* channels;
    int fd;

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    if ((flags != O_RDONLY) && (flags != O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }

    if (flags == O_RDONLY) {
        channels = readers;
    } else {
        channels = writers;
    }

    fd = channels[gd].fd;
    if (fd <= 0) {
        errno = ENODEV;
        return -1;
    }

    return fcntl(fd, cmd);
}

int pirate_fcntl1(int gd, int flags, int cmd, int arg) {
    pirate_channel_t* channels;
    int fd;

    if (gd < 0 || gd >= PIRATE_NUM_CHANNELS) {
        errno = EBADF;
        return -1;
    }

    if ((flags != O_RDONLY) && (flags != O_WRONLY)) {
        errno = EINVAL;
        return -1;
    }

    if (flags == O_RDONLY) {
        channels = readers;
    } else {
        channels = writers;
    }

    fd = channels[gd].fd;
    if (fd <= 0) {
        errno = ENODEV;
        return -1;
    }

    return fcntl(fd, cmd, arg);
}
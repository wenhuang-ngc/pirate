#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "greatest.h"

GREATEST_MAIN_DEFS();

static char *devicepath;

TEST open_invalid() {
  int rv;
  pid_t ch_pid = fork();
  switch (ch_pid) {
  case -1: // Error
    perror("fork failed");
    FAIL();
  case 0: // Child
    rv = open(devicepath, O_RDWR);
    ASSERT_EQ_FMT(-1, rv, "%d");
    exit(0);
    break;
  default: // Parent
    waitpid(ch_pid, NULL, 0);
  }
  PASS();
}

TEST open_valid(int child_mode, int parent_mode) {
  struct timespec start, stop, pause;
  long delta;
  int rv, fd;

  pid_t ch_pid = fork();
  switch (ch_pid) {
  case -1: // Error
    perror("fork failed");
    FAIL();
  case 0: // Child
    clock_gettime(CLOCK_MONOTONIC, &start);
    fd = open(devicepath, child_mode);
    clock_gettime(CLOCK_MONOTONIC, &stop);
    ASSERT(fd > 0);
    // test that open() waits for the matching parent open()
    delta = ((stop.tv_sec - start.tv_sec) * ((long)1e9)) +
            (stop.tv_nsec - start.tv_nsec);
    ASSERT(delta > 5e7);
    // no close()
    // test cleanup of file descriptor on process exit
    exit(0);
    break;
  default: // Parent
    pause.tv_sec = 0;
    pause.tv_nsec = (long)1e8;
    nanosleep(&pause, NULL);
    fd = open(devicepath, parent_mode);
    ASSERT(fd > 0);
    waitpid(ch_pid, NULL, 0);
    rv = close(fd);
    ASSERT_EQ_FMT(0, rv, "%d");
  }
  PASS();
}

TEST open_valid_read_write() { return open_valid(O_RDONLY, O_WRONLY); }

TEST open_valid_write_read() { return open_valid(O_WRONLY, O_RDONLY); }

int gaps_ops(int fd, int mode, int value) {
  int buffer, rv;
  if (mode == O_RDONLY) {
    rv = read(fd, &buffer, sizeof(int));
    ASSERT_EQ_FMT(value, buffer, "%d");
  } else {
    rv = write(fd, &value, sizeof(value));
  }
  return rv;
}

TEST gaps_valid_ops(int child_mode, int parent_mode, int value) {
  struct timespec pause;
  int rv, fd;

  pause.tv_sec = 0;
  pause.tv_nsec = (long)1e8;

  pid_t ch_pid = fork();
  switch (ch_pid) {
  case -1: // Error
    perror("fork failed");
    FAIL();
  case 0: // Child
    fd = open(devicepath, child_mode);
    ASSERT(fd > 0);
    rv = gaps_ops(fd, child_mode, value);
    ASSERT_EQ_FMT((int)sizeof(int), rv, "%d");
    nanosleep(&pause, NULL);
    rv = close(fd);
    ASSERT_EQ_FMT(0, rv, "%d");
    exit(0);
    break;
  default: // Parent
    fd = open(devicepath, parent_mode);
    ASSERT(fd > 0);
    nanosleep(&pause, NULL);
    rv = gaps_ops(fd, parent_mode, value);
    ASSERT_EQ_FMT((int)sizeof(int), rv, "%d");
    waitpid(ch_pid, NULL, 0);
    rv = close(fd);
    ASSERT_EQ_FMT(0, rv, "%d");
  }
  PASS();
}

TEST gaps_valid_read_write() {
  return gaps_valid_ops(O_RDONLY, O_WRONLY, 1234);
}

TEST gaps_valid_write_read() {
  return gaps_valid_ops(O_WRONLY, O_RDONLY, 5678);
}

SUITE(gaps_open) {
  struct stat statbuf;
  stat(devicepath, &statbuf);

  if (!S_ISFIFO(statbuf.st_mode)) {
    RUN_TEST(open_invalid);
  }
  RUN_TEST(open_valid_read_write);
  RUN_TEST(open_valid_write_read);
}

SUITE(gaps_read_write) {
  RUN_TEST(gaps_valid_read_write);
  RUN_TEST(gaps_valid_write_read);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("usage: cusegaps.test [device path]\n");
    return 1;
  }
  devicepath = argv[1];

  GREATEST_MAIN_BEGIN();

  RUN_SUITE(gaps_open);
  RUN_SUITE(gaps_read_write);

  GREATEST_MAIN_END();
}
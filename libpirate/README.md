# libpirate

Pirate primitives layer. The PIRATE core primitives layer
will provide a series of capabilities for executing PIRATE executables
on TA1 hardware. At minimum, there are four basic primitives that must
be supported: configuring TA1 hardware, loading code and data onto the
appropriate CPU, implementing channel send and receive calls, and resource
cleanup / data wipe on termination.

## Usage

See [libpirate.h](/libpirate/libpirate.h) for additional documentation.

Reader:

```
  pirate_channel_param_t param
  pirate_init_channel_param(PIPE, &param);

  int data;
  if (pirate_open(1, O_RDONLY) < 0) {
    perror("reader open error");
    exit(1);
  }
  if (pirate_read(1, &data, sizeof(data)) != sizeof(data)) {
    perror("read error");
    exit(2);
  }
  pirate_close(1, RD_ONLY);
```

Writer:

```
  pirate_channel_param_t param
  pirate_init_channel_param(PIPE, &param);

  int data = 1234;
  if (pirate_open(1, O_WRONLY) < 0) {
    perror("writer open error");
    exit(1);
  }
  if (pirate_write(1, &data, sizeof(data)) != sizeof(data)) {
    perror("write error");
    exit(2);
  }
  pirate_close(1, O_WRONLY);
```

## Channel types

### PIPE type

Linux named pipes are the default channel type. A pipe file is
created at `/tmp/gaps.channel.%d` if one does not exist.

### DEVICE type

The pathname to the character device must be specified using
`pirate_set_pathname(int, char *)` prior to opening the channel.

### UNIX_SOCKET type

Unix domain socket communication. A unix socket file is
created at `/tmp/gaps.channel.%d.sock` if one does not exist.

### TCP_SOCKET type

TCP socket communication. The port number is (26427 + d)
where d is the gaps descriptor.

### UDP_SOCKET type

UDP socket communication. The port number is (26427 + d)
where d is the gaps descriptor.

### SHMEM type

Uses a POSIX shared memory region to communicate. Support
for the SHMEM type requires the librt.so POSIX real-time extensions
library. This support is not included by default. Set
the PIRATE_SHMEM_FEATURE flag in [CMakeLists.txt](/libpirate/CMakeLists.txt)
to enable support for shared memory.

If the reader or writer process is killed while blocked
on pirate_open() then you must delete the file
`/dev/shm/gaps.channel.%d` prior to launching another reader or writer.

The SHMEM type is intended for benchmarking purposes only.
The size of the shared memory buffer can be specified using
`pirate_set_shmem_size(int, int)` prior to opening the channel.

### UIO_DEVICE type

Uses shared memory provided by the kernel from a Userspace IO
device driver. The [uio-device](/devices/uio-device/README.md) kernel module
must be loaded.

## Benchmarks

`primitives_bench_thr` and `primitives_bench_lat` are throughput
and latency benchmarks for the library. `bench.py` is a wrapper
script that can be used to run the benchmarks across a range
of message sizes. Benchmarks are compiled using the command
`make bench`.

Example usage:

```
# throughput benchmarks
./bench.py thr unix-pipe >> throughput.results
./bench.py thr device /dev/foobar >> throughput.results
./bench.py thr shmem shmem >> throughput.results

# latency benchmarks
./bench.py lat unix-pipe >> latency.results
./bench.py lat device /dev/foo /dev/bar >> latency.results
./bench.py lat shmem shmem shmem >> latency.results
```

## Tests

### Dependencies

[Google Test](https://github.com/google/googletest)

```
$ git clone https://github.com/google/googletest.git
$ cd googletest
$ git checkout v1.10.x
$ cmake -DCMAKE_BUILD_TYPE=Release googletest-release-1.10.x .
$ sudo cmake --build . --target install
```

### Build
Enable **PIRATE_UNIT_TEST** option:
```
$ mkdir build
$ cd build
$ cmake -DPIRATE_UNIT_TEST=ON ..
$ make
```

### Run
```
$ cd build
$ ./libpirate/gaps_channels_test
```

### Run with [valgrind](https://valgrind.org/)

```
$ cd build
$ make valgrind
```

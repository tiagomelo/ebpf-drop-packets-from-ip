# eBPF Drop Packets from IP

![banner](ebpfWithGolang.png)

This project demonstrates how to use eBPF to drop packets from a specified IP address. The project includes an eBPF program written in C and a Go application to load and manage the eBPF program.

## Files

- `drop.c`: The eBPF program that drops packets from a specified IP address.
- `main.go`: The Go application that loads the eBPF program and manages the blocked IP address.
- `Makefile`: Makefile to build and run the project.

## Prerequisites

- Go (version 1.16 or later)
- Clang/LLVM (for compiling the eBPF program)
- bpftool (for tracing the eBPF program)
- Linux kernel with eBPF support

## Dependencies

This project uses the [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf) library for interacting with eBPF programs in Go.

## Usage

### Build and Run

1. **Generate eBPF Code**: Generate the eBPF code using `go generate`.

    ```sh
    make generate
    ```

2. **Build the Application**: Build the Go application.

    ```sh
    make build
    ```

3. **Run the Application**: Run the application with the specified blocked IP address and optional network interface.

    ```sh
    sudo make run BLOCKED_IP=<blocked-ip> [INTERFACE=<interface>]
    ```

    Example:

    ```sh
    sudo make run BLOCKED_IP=192.168.1.1 INTERFACE=eth0
    ```

### Trace the eBPF Program

To trace the eBPF program and see the logs, use the following command:

```sh
make trace-pipe
```
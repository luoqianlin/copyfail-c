# copyfail-c

A minimal C reproduction for researching Copy Fail (CVE-2026-31431).

This repository contains a compact C implementation built around the Linux kernel `AF_ALG` interface for vulnerability research, behavior analysis, and controlled reproduction.

## Build

```bash
make
```

The resulting binary is `./copyfail`.

## Run

The program requires one input file path argument. For example:

```bash
./copyfail "$(which su)"
```

`<input_path>` is opened read-only and used as the `splice()` source on each iteration, always starting from file offset `0`. A common choice is a readable SUID-root ELF such as `/usr/bin/su`.

## Scope

- This code is intended for authorized research and reproducible testing only.
- Run it only in environments you own or are explicitly permitted to assess.
- The implementation is intentionally small to make review and experiment setup easier.

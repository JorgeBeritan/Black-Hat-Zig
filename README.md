# Black Hat Zig

Offensive security research implementing Linux attack primitives using Zig with direct syscalls — zero libc dependency.

> **WARNING:** This repository contains tools and techniques intended **exclusively** for authorized security testing, research, and educational purposes. See [DISCLAIMER](DISCLAIMER) before using any code in this repository.

## Overview

Black Hat Zig explores the Linux kernel's syscall interface as a foundation for offensive tooling. Every exercise uses `std.os.linux.syscallN` directly, bypassing libc entirely. This eliminates detection surfaces like `LD_PRELOAD` hooks, `ltrace`, and PLT-based instrumentation.

The research is documented in detail at [jorgeberitan.github.io/black-hat-zig](https://jorgeberitan.github.io/black-hat-zig/).

## Structure

```
chapter-12-linux-internals/
├── 01-direct-syscalls/         # Raw syscall wrappers: write, uname, getpid, openat, read
│   └── src/main.zig            # System info + /proc/self/maps parser via direct syscalls
│
├── 02-mprotect-exec/           # Dynamic shellcode execution
│   └── src/main.zig            # mmap RW → write shellcode → mprotect RX → execute
│
├── 03-memfd_create/            # Fileless ELF execution
│   ├── payload/src/main.zig    # Sample ELF payload (prints a message)
│   └── loader/src/main.zig     # Creates memfd, writes embedded ELF, execve from /proc/self/fd/N
│
├── 04-ptrace-injection/        # Process injection via ptrace
│   ├── victim/src/main.zig     # Target process (heartbeat loop)
│   └── injector/src/main.zig   # ATTACH → GETREGS → POKETEXT shellcode → CONT → restore → DETACH
│
└── 05-fileless-implant/        # Full implant with C2 and migration
    ├── src/main.zig            # Implant core: reverse TCP, command dispatch, ptrace migration
    ├── loader/main.zig         # memfd_create loader with process name masquerading
    └── payload_embed.zig       # Compile-time embed of implant binary
```

## Requirements

- **Zig 0.17.0** (uses `std.process.Init` main signature)
- **Linux x86_64** (direct syscall numbers are architecture-specific)
- Root or `CAP_SYS_PTRACE` for exercises 04 and 05

## Building

Each exercise is a standalone Zig project:

```bash
cd chapter-12-linux-internals/01-direct-syscalls
zig build

# For 03-memfd_create, build the payload first:
cd chapter-12-linux-internals/03-memfd_create/payload
zig build
cd ../loader
zig build

# For 05-fileless-implant, build the implant then the loader:
cd chapter-12-linux-internals/05-fileless-implant
zig build          # builds implant
# loader embeds the implant binary at compile time
zig build loader 
# update the loader with the implant
```


## Exercises

### 01 — Direct Syscalls
Demonstrates raw syscall invocation without libc. Reads PID, UID, hostname, and parses `/proc/self/maps` to display the process memory layout, marking executable and RWX regions.

### 02 — mprotect Shellcode Execution
Allocates memory with `mmap` (RW), writes position-independent shellcode, transitions permissions to RX with `mprotect`, and executes via function pointer cast. Demonstrates the W^X bypass primitive.

### 03 — memfd_create Fileless Execution
A loader embeds an ELF binary at compile time with `@embedFile`, creates an anonymous in-memory file with `memfd_create`, writes the ELF to it, and executes via `execve("/proc/self/fd/N")`. The payload never touches disk.

### 04 — ptrace Process Injection
Attaches to a running process, saves its register state and memory at RIP, writes shellcode via `POKETEXT`, resumes execution, then restores the original state and detaches. The victim process continues running unaware.

### 05 — Fileless Implant
Composes all previous primitives into a functional implant:
- **Loader:** memfd_create + execve with process name masquerading (`[kworker/0:1]`)
- **Implant:** Reverse TCP shell over direct socket syscalls, command set (`info`, `maps`, `pwd`, `ls`, `exec`, `migrate`, `exit`), 30-minute killswitch
- **Migration:** ptrace-based injection of reverse shell shellcode into a target process (port 4445)

## Legal

This project is licensed under the [MIT License](LICENSE) with an additional disclaimer. See [DISCLAIMER](DISCLAIMER) for the full authorized-use policy.

**You are solely responsible for ensuring that your use of this code complies with all applicable laws and regulations.** Unauthorized use of these techniques against systems you do not own or do not have explicit written permission to test is illegal.

## Author

Jorge Beritan — [@JorgeBeritan](https://github.com/JorgeBeritan)

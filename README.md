# Mole-Open

This is the repository for paper "Mole: Breaking GPU TEE with GPU-Embedded MCU"

There are mainly the following components in this repository:

- `parser`: The parser for the GPU MCU firmware.
- `mcu_hacker`: The kernel module to launch the attack on GPU TEE.
- `gpu-program`: The userland hook to the OpenCL program, capturing the OpenCL system calls.
- `shell`: The shellcode to inject into the firmware.
- `benchmark`: The benchmarks tested in the paper.

## Requirements
You need the following dependencies to run the code:

- [Rust toolchain](https://rustup.rs/)
- [Arm toolchain](https://developer.arm.com/Tools%20and%20Software/GNU%20Toolchain)
- [Arm OpenCL](https://www.khronos.org/opencl/)

## Instructions

### `shell`
To modify the firmware, we first need to run the `shell` to compile the
shellcode to be injected into the firmware. It contains two sources: `fw.c` and
`reset.c`. By default, `fw.c` will be executed on *every* firmware interrupts
and `reset.c` will be executed when the firmware is reset.

```bash
cd shell
make
```

### `parser`
The parser parses the firmware and inject the previous compiled shellcode into 
the firmware. 

```bash
cargo run
```

The above command shall generate a `new_csf.bin` file in the `parser`
directory, which is the tampered firmware.

### `mcu_hacker`
This is the kernel module for the untrusted kernel to communicate with the GPU,
please compile it within the kernel source tree.

### `gpu-program`
This is a userland program to hook the OpenCL system calls. It is used to
capture the OpenCL system calls and send them to the kernel module. It needs
to be compiled on the *victim* machine

```bash
make
LD_PRELOAD=hook_ocl.so ./<victim_program>
```

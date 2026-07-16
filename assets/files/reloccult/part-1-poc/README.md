# Reloccult Part 1: AAW + AAC PoC

This PoC demonstrates two x86-64 ELF relocation primitives in one PIE binary:

1. `R_X86_64_64` changes an initialized global from
   `0x1111111111111111` to `0x2222222222222222`.
2. `R_X86_64_GLOB_DAT` resolves a crafted local `STT_GNU_IFUNC` symbol, causing
   `ld.so` to call `relocation_time_printer()` before the executable entry point.

The relocation-time function prints the modified global with a direct `write`
syscall. `main()` then prints a separate message after the entry point, making
the execution order visible.

## Run

```sh
./host
./relocation-poc
```

Expected output:

```text
[ENTRY] This is main(), running after the executable entry point.
[AAC] Called by ld.so before the entry point; initialized_global = 0x2222222222222222
[ENTRY] This is main(), running after the executable entry point.
```

Both binaries target Linux x86-64. They were tested on Ubuntu 24.04 with
glibc 2.39.

## Inspect the crafted metadata

Show only the two relocations used by this PoC:

```sh
readelf -Wr relocation-poc | grep -E 'Offset|sym0|sym1'
```

Show only their dynamic-symbol entries:

```sh
readelf -W --dyn-syms relocation-poc 2>/dev/null | grep -E 'Num:|sym0|sym1'
```

## Files

- `host.c`: the initialized global, relocation-time printer, and `main()`.
- `host`: the original binary, before the crafted relocations are added.
- `relocation-poc`: the final binary containing the AAW and AAC primitives.

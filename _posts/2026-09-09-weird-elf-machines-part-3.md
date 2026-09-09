---
title: "Weird ELF Machines (Part 3): Reloccult, a Load-Time ELF Packer"
date: 2026-09-09 00:00:00 +0900
description: How Reloccult turns ELF relocation metadata into a load-time packer that reconstructs a payload and replaces the host before its entry point.
read_time: 15
image:
  path: /assets/img/post-covers/weird-elf-machines-part-1.png
  alt: Minimal ELF file and hammer illustration for the Weird ELF Machines series
  no_bg: true
categories: [Tech Articles, Reloccult]
tags: [weird-machine, elf, relocation]
comment: true
---

## Overview

[Reloccult](https://github.com/JiminChip/Reloccult) is a load-time ELF packer I built for Linux x86-64. It takes a dynamically linked ELF as its host and another ELF as its payload, then produces a single packed ELF. Unlike a conventional packer, which runs an unpacking stub from host code, Reloccult uses the relocation-based weird machine developed in Parts 1 and 2 so that **the dynamic linker's relocation pass drives both payload preparation and the transition to it.**

The original host entry point remains in a Reloccult-packed ELF. Control never reaches it, however, because the following sequence completes while the kernel maps the host and its ELF interpreter and `ld.so` processes relocations:

1. The relocation stream reconstructs a loader stub and the payload bytes in memory.
2. The final relocation invokes the reconstructed stub as an `STT_GNU_IFUNC` resolver.
3. The stub writes the payload into an anonymous in-memory file.
4. `execveat(AT_EMPTY_PATH)` replaces the current process image with the payload ELF.

The payload is never entered as code inside the host. In the packed file, its bytes are distributed across relocation addends rather than stored as a contiguous executable body in the host's `.text`. During loading, relocations reconstruct those bytes in a temporary loader image, but the stub does not branch into them. It copies them into a `memfd`, and only after `execveat()` replaces the entire host image does the payload begin executing.

By the time the payload's first instruction runs, the original host mappings and the temporary loader image are gone. **Reloccult injects its loader into the host ELF, but it never executes the payload as host code.**

[Part 1](https://mini-chip.kr/posts/weird-elf-machines-part-1/) modeled relocation as a loader-driven memory write and showed how self-modifying relocations and `GLOB_DAT + STT_GNU_IFUNC` can provide writes and calls before the entry point. [Part 2](https://mini-chip.kr/posts/weird-elf-machines-part-2/) composed those primitives into a dataflow program expressed entirely through relocation metadata.

This post examines the next construction: encoding a payload as a relocation stream, running a loader stub before the host entry point, and replacing the current process image with the payload ELF. Reloccult is the concrete ELF packer built around that design.

> **Reloccult does not run the payload inside the host.** Before the host entry point, `ld.so` prepares the payload and `execveat()` replaces the process image itself.

## What Reloccult Builds

Reloccult takes two ELF files as input:

- **host**: the dynamically linked x86-64 ELF to transform
- **payload**: the x86-64 ELF that should ultimately run

The output preserves the host's existing dynamic-linking machinery while adding four components:

- a zero-initialized loader image in which the loader stub and payload bytes will be reconstructed
- a relocation stream that fills that image eight bytes at a time
- an `STT_GNU_IFUNC` symbol and an `R_X86_64_GLOB_DAT` relocation that invoke the stub during relocation processing
- dynamic metadata that directs `ld.so` to the added relocations and symbols

The injected loader image is not the payload's final execution region. It is temporary staging space in which Reloccult assembles the ELF that will be passed to `execveat()`. Only the small loader stub executes there; the payload remains data.

The full path, divided into pack time and load time, looks like this:

```text
[pack time]

dynamic host ELF + payload ELF
  -> create a position-independent loader stub
  -> encode the stub and payload as qword relocations
  -> add a zero-filled loader image and dynamic metadata to the host
  -> place the IFUNC trigger last
  -> emit the packed ELF

[load time]

kernel
  -> map the host and ld.so
  -> ld.so applies the host's original relocations
  -> crafted relocations reconstruct the stub and payload
  -> GLOB_DAT invokes the stub as an IFUNC resolver
  -> memfd_create
  -> write(payload)
  -> execveat(fd, "", argv, envp, AT_EMPTY_PATH)
  -> replace the host process image with the payload ELF
```

The success path contains no return to the host entry point. A successful `execveat()` does not return; the kernel begins executing the new payload ELF instead.

## The Loader Image as a Staging Area

The injected loader image is temporary staging space for a new ELF image, not an execution region for the payload. Relocations reconstruct a position-independent loader stub and the payload bytes side by side:

```text
+----------------------------------+
| position-independent loader stub |
+----------------------------------+
| payload bytes (data only)        |
+----------------------------------+
```

The relocation stream fills this initially zeroed image. The stub locates its data relative to its own position, so it performs the same job regardless of the load bias applied to the image.

Even after reconstruction, the stub never branches into the payload area. It uses that area only as the source buffer for `write()`, copies the complete payload ELF into a `memfd`, and asks `execveat()` to execute the ELF referenced by that file descriptor as a new process image. The loader image is therefore a bridge from the host to a new ELF, not a place where the payload runs inside the host.

## Encoding Bytes as Relocations

Reloccult reconstructs data with the `R_X86_64_64` semantics introduced in Part 1. Conceptually, a symbol-based absolute relocation on x86-64 performs this write:

```text
R_X86_64_64:
    *P = S + A

P = base + r_offset
S = resolved symbol value
A = r_addend
```

Reloccult references a local absolute symbol whose value makes `S = 0`, reducing the result to the addend:

```text
*P = 0 + A = A
```

### One Qword, Two Relocation Entries

Each qword `Q` is represented by two consecutive relocations:

| Entry | `r_offset` | Type | Symbol | `r_addend` |
| --- | --- | --- | --- | --- |
| A: patch | `&B.r_addend` | `R_X86_64_64` | zero absolute symbol | `Q` |
| B: write | destination | `R_X86_64_64` | zero absolute symbol | initially `0` |

When `ld.so` processes A, it writes `Q` into the `r_addend` field of the next entry, B:

```text
B.r_addend = Q
```

When the loader advances to B, it reads the modified addend and writes the same value to the final destination:

```text
*destination = 0 + B.r_addend = Q
```

The relocation table is no longer just a static list of fixups. One entry constructs an operand for an entry that has not yet executed, and the later entry applies that operand to the loader image:

```text
patch future addend
  -> consume patched addend
  -> reconstruct one qword
```

Reloccult repeats this pair for every qword that must be reconstructed in the loader stub and payload. The resulting relocation pairs describe the byte sequence of the loader image.

### Why `.rela.dyn` Must Be Writable

The destination of entry A is not ordinary application data. It is the `Elf64_Rela.r_addend` field of an entry that the loader has not processed yet. The runtime relocation table used by `ld.so` must therefore reside in a writable mapping.

Reloccult places its crafted relocation stream where it can be modified during the relocation pass. The host's original relocations run first, the qword-write stream reconstructs the loader image, and the final IFUNC trigger invokes the completed stub. This sequence relies on two properties: **the loader processes these relocation entries in order, and an earlier entry can modify an entry that has not yet been processed.**

## Calling the Reconstructed Stub

Once every byte has been reconstructed, Reloccult must execute the loader stub before control reaches the host entry point. The call target is not the payload itself. It is the small stub that copies the payload into a `memfd` and invokes `execveat()`.

Reloccult creates a local `STT_GNU_IFUNC` symbol that points to the beginning of the reconstructed stub, then makes the final `R_X86_64_GLOB_DAT` relocation reference that symbol. In glibc's x86-64 relocation path, an `STT_GNU_IFUNC` symbol is not used directly as the final address. The loader calls that address as a resolver function. The final relocation therefore creates this path:

```text
all loader bytes reconstructed
  -> resolve local IFUNC
  -> call reconstructed stub
  -> execveat replaces the process image
```

If `execveat()` succeeds, the stub enters a new process image. If an earlier syscall or `execveat()` fails, the stub terminates the process. It never returns to the resolver call on either path. Because the `GLOB_DAT` entry appears after all qword writes, the stub and payload are complete before `ld.so` invokes the resolver. The call still occurs inside dynamic relocation processing, so it precedes the host entry point.

## The `memfd_create` to `execveat` Stub

The reconstructed stub has three essential steps:

```text
fd = memfd_create("reloccult", 0)
write_all(fd, payload, payload_size)
execveat(fd, "", argv, envp, AT_EMPTY_PATH)
```

`memfd_create()` returns a file descriptor for an anonymous in-memory file. The stub writes the complete reconstructed payload ELF into that file, then passes the descriptor to `execveat()` with an empty path and `AT_EMPTY_PATH`.

On success, `execveat()` replaces the current process image with the payload ELF and never returns. No temporary payload file needs to appear in the filesystem. This transition is what keeps the payload from executing in the host's loader image: it starts from its own entry point only after the host address space has been replaced.

## Extending the Runtime Relocation Stream

For `ld.so` to execute Reloccult's relocation program, the packed ELF's dynamic metadata must refer to the crafted stream and the symbols it uses. At runtime, the relocation stream follows this order:

```text
original host relocations
  -> loader image reconstruction
  -> IFUNC execution trigger
```

Keeping the host relocations at the front allows ordinary dynamic linking to finish first. The reconstruction stream then builds the loader image, and the final trigger invokes the completed stub. The host contributes no unpacking logic; normal relocation processing in `ld.so` carries the construction through to the execution transition.

## Permission Design: RWX, TEXTREL, and the Unbuilt Alternative

Relocations must write the loader stub and payload bytes into the loader image, while the final IFUNC relocation must execute the stub from that same image. The loader segment therefore needs write permission during reconstruction and execute permission when the resolver is invoked. Reloccult's permission design evolved through different ways of satisfying those two requirements.

### First Design: a Persistent RWX Segment

The first version used the most direct arrangement:

1. Add a loaded segment with `PF_R | PF_W | PF_X` to the host.
2. Let relocations write the stub and payload into that segment.
3. Let the IFUNC trigger execute the reconstructed stub from the same segment.

This design is straightforward because the loader never has to change permissions. The resulting ELF, however, retains a permanent RWE mapping. Such mappings are unusual in modern ELF files, easy to notice, and undesirable under W^X.

Reloccult retains this design as a legacy mode for reproducing the original construction and comparing it with the current one.

### Current Default: an RX Segment with `TEXTREL`

The current default marks the loader section as `PF_R | PF_X`, removes the write flag, and adds `DT_TEXTREL` and `DF_TEXTREL` to the ELF.

When glibc's relocation path sees `DT_TEXTREL`, it temporarily adds write permission to otherwise non-writable `PT_LOAD` ranges. After relocation processing, it restores the original protections.

```text
file/program headers: loader segment is R-X

ld.so relocation phase:
  temporarily permit writes
  -> reconstruct stub and payload
  -> call stub through IFUNC
  -> restore original protection if relocation returns
```

The output ELF no longer contains a permanent RWE segment. `TEXTREL` is nevertheless discouraged by modern toolchains and hardening policies, and the loader must permit text relocations. Reloccult accepts that trade-off in exchange for a raw-syscall loader that does not depend on specific libc functions or gadget addresses.

### A TEXTREL-Free ROP Design Considered, but Not Implemented

I also considered a third design. [The xless-elf construction from Part 2](https://github.com/JiminChip/xless-elf) gives the main image no executable `PT_LOAD`. Its relocation dataflow writes a ROP chain onto the loader stack and reuses code from the existing `ld.so` and libc mappings to invoke syscalls.

The same approach could express Reloccult's final execution stage as follows:

```text
relocations recover loader/libc runtime bases
  -> relocations write a ROP chain onto the loader stack
  -> chain invokes memfd_create
  -> chain writes the embedded payload
  -> chain invokes execveat(AT_EMPTY_PATH)
```

This design would require neither a new executable segment nor `TEXTREL` writes into that segment. Part 2's relocation-time address discovery and computed stack stores show why the construction is possible in principle.

It would, however, couple the packer tightly to a particular runtime. A working chain would have to reproduce all of the following:

- the exact `ld.so` and libc builds and their mapping relationship
- the offsets of the selected functions and ROP gadgets
- the order required to reach the desired objects through `link_map`
- the loader stack layout and control flow at the end of relocation processing

`xless-elf` makes these relationships reproducible by pinning a matching `ld.so` and libc pair in a Docker image. That is appropriate for demonstrating a specific artifact, but it becomes a severe restriction for a general-purpose packer that must handle different hosts and deployment environments. A loader or libc update would require gadget and internal-offset analysis again, along with renewed validation of the stack handoff assumptions.

For Reloccult, I judged those library and runtime dependencies to be a larger cost than using `TEXTREL`. The ROP-based variant therefore remains a design alternative and **is not implemented in the public repository**. The default RX+TEXTREL mode still depends on a loader that permits text relocation, but its payload execution path is not tied to one exact libc build or gadget set.

The three designs can be summarized as follows:

| Design | New loader mapping | How execution begins | Main cost |
| --- | --- | --- | --- |
| legacy `rwx` | permanent RWE | IFUNC calls injected code | conspicuous RWE mapping |
| default `rx` | R-X, written via `TEXTREL` | IFUNC calls injected code | depends on TEXTREL support and policy |
| considered ROP variant | no injected executable code required | loader return enters library ROP | exact loader, libc, and gadget dependency |

## A Reproducible Example

Rather than vendoring system binaries, the repository includes small fixture sources that reproduce the same host-and-payload relationship. The following commands build the `ls_to_whoami` host and payload locally, produce both the RX and RWX artifacts, and run them:

```bash
git clone https://github.com/JiminChip/Reloccult.git
cd Reloccult

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

python scripts/build_examples.py \
  --example ls_to_whoami \
  --mode both \
  --run
```

Both outputs print the payload fixture's message rather than the host fixture's message:

```text
reloccult payload fixture: ls_to_whoami payload=whoami argc=1
```

`strace` makes both the syscall path and the fact that the host entry point never runs visible:

```bash
strace -f \
  -e trace=memfd_create,write,execveat,exit_group \
  ./examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rx
```

The relevant sequence appears as follows:

```text
memfd_create("reloccult", 0) = 3
write(3, <payload ELF>, <payload size>) = <payload size>
execveat(3, "", ["packed"], [], AT_EMPTY_PATH) = 0
write(1, "reloccult payload fixture: ...", ...) = ...
```

The first `memfd_create`, `write`, and `execveat` calls come from the loader stub before the host entry point. The `write` after `execveat()` comes from the replacement payload ELF. The message that the host fixture would print never appears.

The permission modes can be distinguished directly through the program headers and dynamic tags:

```bash
readelf -lW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rx
readelf -dW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rx | grep -E 'TEXTREL|FLAGS'

readelf -lW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rwx
readelf -dW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rwx | grep -E 'TEXTREL|FLAGS'
```

The RX artifact has no RWE `PT_LOAD` and contains both `TEXTREL` and `DF_TEXTREL`. The RWX artifact has a new RWE `PT_LOAD` and no `TEXTREL` tag.

The added dynamic symbols and relocation stream can also be inspected directly:

```bash
readelf -sW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rx
readelf -rW \
  examples/ls_to_whoami/output_bin/ls_to_whoami_packed.rx
```

Near the end of the output are the zero-valued absolute symbol and a GNU IFUNC symbol that points to the loader section. They are followed by the repeated `R_X86_64_64` pairs and the final `R_X86_64_GLOB_DAT` trigger.

## Current Scope

The public implementation currently assumes:

- Linux x86-64 little-endian ELF64
- a dynamically linked host whose relocations are processed by `ld.so`
- an x86-64 payload, which may be either dynamically or statically linked
- glibc-compatible `TEXTREL` handling for the default RX mode

The current implementation focuses on connecting relocation writes and an IFUNC call into a packer pipeline that replaces the process image with a complete payload ELF before the host entry point.

The public implementation and reproducible fixtures demonstrate that this construction works in practice.

## Closing Notes

Part 1 showed that a relocation can act as a write or call primitive before the executable entry point. Part 2 composed multiple relocations into a program that discovers runtime state and prepares a new control-flow path.

Reloccult turns those ideas into an ELF packer:

```text
host ELF + payload ELF
  -> encode payload bytes as relocation metadata
  -> ld.so reconstructs the loader image
  -> IFUNC invokes the loader stub before the host entry point
  -> memfd_create + write + execveat
  -> replace the host image with the payload ELF
```

In a conventional packer, an unpacking stub in host code reads metadata and eventually transfers control to the payload. In Reloccult, **relocation metadata is both the payload encoding and the unpacker's instruction stream**, and its interpreter is `ld.so`, not host code.

The dynamic linker completes the loader image and invokes the stub as an IFUNC resolver before relocation processing ends. The stub never branches directly to the payload. It writes the payload into an anonymous in-memory file and calls `execveat()`. The host entry point consequently never runs, and neither the old host image nor the temporary loader image remains in the process address space when payload execution begins.

Whether the execution-permission strategy is RWX, TEXTREL, or library ROP, the underlying idea stays the same. Reloccult uses the host ELF as a carrier without executing the payload as host code. Relocation semantics prepare the payload and replace the complete process image before the host entry point, turning the relocation table from a list of address corrections into **a load-time program**.

## References

- [Weird ELF Machines (Part 1): Relocation Abuse for Arbitrary Writes and Calls](https://mini-chip.kr/posts/weird-elf-machines-part-1/)
- [Weird ELF Machines (Part 2): Can an ELF Run Without Executable Segments?](https://mini-chip.kr/posts/weird-elf-machines-part-2/)
- [JiminChip/Reloccult](https://github.com/JiminChip/Reloccult)
- [JiminChip/xless-elf](https://github.com/JiminChip/xless-elf)
- Rebecca Shapiro, Sergey Bratus, Sean W. Smith, [“Weird Machines” in ELF: A Spotlight on the Underappreciated Metadata](https://www.usenix.org/system/files/conference/woot13/woot13-shapiro.pdf), WOOT'13
- [System V AMD64 ABI / x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build)
- glibc dynamic linker source: [`elf/dl-reloc.c`](https://codebrowser.dev/glibc/glibc/elf/dl-reloc.c.html), [`sysdeps/x86_64/dl-machine.h`](https://codebrowser.dev/glibc/glibc/sysdeps/x86_64/dl-machine.h.html)
- Linux man-pages: [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html), [`execveat(2)`](https://man7.org/linux/man-pages/man2/execveat.2.html)

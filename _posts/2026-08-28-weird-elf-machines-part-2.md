---
title: "Weird ELF Machines (Part 2): Can an ELF Run Without Executable Segments?"
date: 2026-08-28 00:00:00 +0900
description: How ELF relocation metadata can recover runtime state, write a ROP chain onto the loader stack, and invoke syscalls without executable segments.
read_time: 15
image:
  path: /assets/img/post-covers/weird-elf-machines-part-1.png
  alt: Diagram of ELF relocation metadata producing arbitrary writes and calls
  no_bg: true
categories: [Tech Articles, Reloccult]
tags: [weird-machine, elf, relocation]
comment: true
---

## Overview

[Part 1](https://mini-chip.kr/posts/weird-elf-machines-part-1/) established the basic weird-machine model: before the executable entry point, `ld.so` interprets relocation metadata, and crafted relocations can provide controlled writes and relocation-time calls. This post takes that foundation as given rather than re-deriving `Elf64_Rela` or the individual relocation equations.

Part 2 asks what happens when the write primitive is no longer used once, but **composed as a program**.

Can relocation metadata recover randomized runtime addresses, follow pointers maintained by the loader, write a control-flow program onto the process stack, and ultimately invoke arbitrary syscalls—even when the main ELF has no executable load segment?

This post develops one answer to that question. The main image contributes no executable load segment; instead, the computation that would normally live in its instruction stream is assembled from relocation semantics interpreted by `ld.so`, ultimately driving the loader toward arbitrary syscall behavior.

I implemented this construction for Linux x86-64 and published the code as [JiminChip/xless-elf](https://github.com/JiminChip/xless-elf). Starting from the write primitive in Part 1, let us follow how relocation processing grows into runtime address discovery, stack programming, and finally syscall invocation.

## The Target Property

An ELF program normally contributes at least one executable `PT_LOAD` segment. The kernel maps that segment with execute permission, and the ELF entry point refers to code inside it.

This construction removes that assumption from the main image:

- no `PT_LOAD` segment has `PF_X`
- no section has `SHF_EXECINSTR`
- the main entry-point bytes are therefore not mapped executable

The binary still has `PT_INTERP`, so the kernel maps the requested ELF interpreter and transfers control to it. This creates the window needed by the construction: `ld.so` must process the main object's dynamic metadata before it can hand control to the main entry point.

The target execution path is:

```text
kernel maps the main ELF and ld.so
  -> ld.so reads the main object's .dynamic entries
  -> ld.so processes crafted .dynsym and .rela.dyn tables
  -> relocations recover runtime state
  -> relocations write a control-flow program onto the loader stack
  -> loader return flow enters that program
  -> the main ELF entry point is never reached
```

The construction uses code already available to the loader as its continuation. Its challenge is to prepare that continuation entirely through relocation processing before `ld.so` attempts to enter the main ELF.

## From a Write Primitive to a Dataflow Machine

Part 1 showed that a relocation describes a loader-performed write. To compose many such writes, the construction needs three things:

1. **mutable state** that survives from one relocation to the next
2. **pointer dereferences** that turn a discovered address into the value stored there
3. **indirect stores** whose destinations can be chosen at runtime

The crafted dynamic metadata supplies all three.

### Redirecting the Tables Used by `ld.so`

The `.dynamic` array tells the loader where the runtime symbol and relocation tables are located. Two entries are central here:

```text
DT_SYMTAB -> runtime address of Elf64_Sym entries
DT_RELA   -> runtime address of Elf64_Rela entries
```

The construction points these entries at crafted copies of `.dynsym` and `.rela.dyn`. Both copies are placed in writable load segments. This matters because the loader is not merely going to read static inputs: earlier relocations will modify symbol values and future relocation records while the same relocation pass is still in progress.

Conceptually, the two tables now have different roles:

- crafted `Elf64_Sym.st_value` fields are **state cells**
- crafted `Elf64_Rela` entries are **operations on those cells**

The result is closer to a small dataflow machine than to a normal relocation table.

### Dynamic Symbols as Register-Like State

Suppose several local dynamic symbols are reserved as scratch values:

```text
reg0 = dynsym[s0].st_value
reg1 = dynsym[s1].st_value
reg2 = dynsym[s2].st_value
```

An `R_X86_64_64` relocation normally writes the referenced symbol value plus an addend:

```text
*target = S + A
```

If `target` is the address of another scratch symbol's `st_value`, the same relocation behaves like a register update:

```text
reg_dst = reg_src + immediate
```

The next relocation that references `reg_dst` observes the updated `st_value`. This gives the relocation stream persistent, mutable state without introducing a normal instruction stream.

### `R_X86_64_COPY` as a Pointer Load

Arithmetic on pointers is not enough. To traverse loader data structures, the machine must also read the memory *at* a computed address.

`R_X86_64_COPY` normally copies the contents of a symbol into storage owned by the main executable. In simplified form:

```text
memcpy(relocation_target, resolved_symbol_address, symbol_size)
```

Now let a scratch symbol's mutable `st_value` hold an address, and give the referenced source symbol a size of eight bytes. If the copy destination is another scratch `st_value`, the observable effect is:

```text
reg_dst = *(uint64_t *)reg_src
```

That is a qword pointer dereference performed by the loader. Together, `R_X86_64_64` and `R_X86_64_COPY` provide the two operations needed for pointer chasing:

```text
ADD  reg_dst, reg_src, immediate
LOAD reg_dst, [reg_src]
```

This is the first important step beyond Part 1. Relocations are no longer only writing constants or resolved symbol addresses. They can preserve intermediate values, derive new addresses, and load the objects stored at those addresses.

## Discovering Runtime State Under ASLR

At this point, the relocation stream can preserve values, add offsets, and dereference pointers. The remaining stages need those operations to act on concrete runtime objects. Building the ROP chain requires libc addresses for gadgets and an existing `syscall` instruction. Reaching loader-owned state requires the `ld.so` base. Placing the chain and redirecting execution require an address on the active loader stack.

ASLR means none of those addresses are known when the ELF file is created. The relocation program must therefore bootstrap them from state that the loader has already initialized before it can write the final control-flow program.

The construction follows a chain of loader-provided anchors:

```text
DT_PLTGOT
  -> main object's link_map
  -> link_map chain
  -> libc and ld.so load biases
  -> __libc_stack_end
  -> initial process stack
```

Each arrow is implemented using the register-like symbol state and pointer-load operation described above.

### Starting from the PLT GOT

On x86-64 glibc, the loader initializes a reserved slot in the PLT GOT with a pointer to the main object's `link_map`. The address of the PLT GOT itself is available through `DT_PLTGOT`, so the relocation program begins from a value already present in the main ELF's dynamic metadata:

```text
reg_map_slot = DT_PLTGOT + sizeof(void *)
reg_map      = *(uint64_t *)reg_map_slot
```

After the dereference, `reg_map` holds the runtime address of the main object's `link_map`.

### Walking `link_map`

The dynamic loader maintains one `link_map` for each loaded ELF object. The fields relevant to this construction can be viewed as:

```c
struct link_map {
    Elf64_Addr       l_addr;   /* load bias */
    char            *l_name;
    Elf64_Dyn       *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
};
```

Two fields matter:

- `l_next` points to the next loaded object
- `l_addr` contains that object's load bias

The relocation program can therefore repeat the same two operations:

```text
reg_tmp = reg_map + offset(l_next)
reg_map = *(uint64_t *)reg_tmp

reg_base = reg_map + offset(l_addr)
reg_base = *(uint64_t *)reg_base
```

The public PoC pins its loader and libc, so the relevant objects appear in a known `link_map` order. Following the chain reaches libc and the ELF interpreter, and reading each object's `l_addr` recovers both randomized bases. No absolute libc or loader address needs to be embedded in the ELF.

This is an important distinction: the relocation stream contains **relationships between runtime objects**, not their final addresses.

### Recovering the Initial Stack Pointer

Once the `ld.so` base is known, the relocation program can address loader-owned objects by their offsets within that image. The construction uses the exported `__libc_stack_end` object. Its stored value points back into the initial process stack supplied at program startup.

The same arithmetic-and-load pair is enough:

```text
reg_stack_object = reg_ld_base + offset(__libc_stack_end)
reg_stack        = *(uint64_t *)reg_stack_object
```

At this point, the metadata program has recovered three categories of randomized state:

- the libc base, used to form code and function addresses
- the loader base, used to locate loader-maintained state
- an initial-stack reference, used to target the active loader stack

Relocation has become an address-discovery mechanism. The values were not known at link time, but they can be reconstructed while `ld.so` is interpreting the crafted tables.

## Self-Modifying Relocations as Indirect Stores

Recovering the stack address still does not immediately allow a normal relocation to write there. The destination field, `r_offset`, was serialized into the ELF before ASLR chose the stack address.

This is where the self-modifying relocation primitive from Part 1 becomes essential.

In the glibc 2.39 runtime used by the PoC, the relocation loop advances linearly and reads each entry when it is reached, so a change to a future entry is observed by the same relocation pass.

Assume `rela[k + 1]` is intended to perform the final write, but its destination is not known in advance. An earlier relocation targets the `r_offset` field inside that future entry:

```text
rela[k]:
    rela[k + 1].r_offset = reg_stack + slot_delta

rela[k + 1]:
    *(uint64_t *)rela[k + 1].r_offset = desired_value
```

When `ld.so` reaches `rela[k]`, it patches the instruction that it is about to interpret next. By the time it processes `rela[k + 1]`, the formerly static destination has become a runtime stack address.

One pair performs one computed store. Repeating the pattern selects successive stack slots:

```text
patch next r_offset -> stack + 0x00
write qword 0

patch next r_offset -> stack + 0x08
write qword 1

patch next r_offset -> stack + 0x10
write qword 2
```

The exact offsets and number of entries are implementation details. The general operation is:

```text
STORE [runtime_address + delta], value
```

This is the central transition in the construction. Mutable symbols allow the relocation stream to *compute* an address; self-modifying `r_offset` fields allow it to *use* that address as a destination.

## Turning the Loader Stack into a Program

With computed qword stores, the relocation stream can write data and control-flow values onto the loader's active stack.

**Return-oriented programming (ROP)** is a sequence of return addresses that reuses short instruction sequences—gadgets—from code already mapped as executable. A ROP chain is therefore just structured stack data, which makes it a natural target for a machine whose main output primitive is a sequence of qword writes.

### Locating the Handoff Point

The value obtained through `__libc_stack_end` is a reference to the initial process stack; it is not itself the saved instruction pointer that must be replaced. In the pinned runtime used by the PoC, the relevant saved loader return slot appears at a reproducible displacement from that reference.

The saved loader return slot can therefore be expressed as:

```text
loader_return_slot = initial_stack_pointer + loader_specific_delta
```

ASLR changes `initial_stack_pointer`, while this relative displacement remains stable in the demonstrated setup. The PoC uses that observed displacement to locate the handoff point.

The relocation stream then writes a layout such as:

```text
loader_return_slot + 0x00 : first gadget address
loader_return_slot + 0x08 : first gadget operand
loader_return_slot + 0x10 : second gadget address
loader_return_slot + 0x18 : next operand
...
```

Finally, the qword at the saved return slot is the address of the first gadget. When loader startup later unwinds through that slot, control enters the prepared chain instead of continuing toward the main ELF entry point.

The handoff is now complete:

```text
relocation metadata
  -> mutable symbol state
  -> runtime address discovery
  -> self-modifying stack writes
  -> saved loader return slot
  -> ROP chain in mapped library code
```

## From ROP to Arbitrary Syscalls

Once the stack can describe an arbitrary ROP chain and the libc base is known, the result is not limited to calling a fixed set of library functions.

On Linux x86-64, a syscall invocation is determined by a syscall number and up to six argument registers:

```text
rax = syscall number
rdi = argument 1
rsi = argument 2
rdx = argument 3
r10 = argument 4
r8  = argument 5
r9  = argument 6
rip = address of an existing syscall instruction
```

The relocation program can already write constants, recovered library addresses, pointers to writable storage, and an arbitrary sequence of gadget addresses onto the stack. Register-loading gadgets can assign the syscall number and arguments, and an existing `syscall; ret` sequence performs the transition into the kernel.

No additional relocation primitive is required. Changing the prepared stack data changes the requested syscall and its arguments. This is why the final capability is best described as **arbitrary syscall invocation prepared by relocation metadata**.

The public witness uses an open-read-write sequence for `/flag` and then exits. ORW is not a special requirement of the machine; it is simply an observable payload that demonstrates all of the necessary stages:

1. recover randomized library and stack addresses
2. write a path string and receive buffer
3. prepare arguments and control-flow entries
4. redirect loader return flow
5. perform externally visible I/O

## The Complete Loader-Time Execution

The entire construction can now be described without referring to any concrete virtual address:

1. The kernel maps the main ELF. None of its `PT_LOAD` segments is executable.
2. `PT_INTERP` causes the kernel to map and start `ld.so`.
3. `ld.so` reads `DT_SYMTAB` and `DT_RELA`, which point to the crafted writable tables.
4. Early relocations use mutable `st_value` cells for intermediate state.
5. The relocation stream dereferences the reserved PLT-GOT slot and obtains the main `link_map`.
6. Pointer-chasing relocations recover the libc and loader bases.
7. The loader base leads to `__libc_stack_end`, which yields the initial-stack reference.
8. Earlier relocations rewrite the `r_offset` fields of later relocations, turning them into computed stack stores.
9. Those stores prepare data, a ROP chain, and the first gadget at the saved loader return slot.
10. When loader startup returns, control enters the prepared chain and performs the selected syscall-level behavior.
11. The chain exits without ever transferring control to the main ELF entry point.

No single relocation is especially powerful. The behavior emerges from the ordering and composition of ordinary relocation semantics. That is precisely why the weird-machine framing is useful: `ld.so` supplies the interpreter, ELF metadata supplies the program, and loader state supplies the runtime inputs.

## A Concrete Witness: `xless-elf`

I published the working artifact and build environment at [JiminChip/xless-elf](https://github.com/JiminChip/xless-elf).

The carrier ELF contains an ordinary entry point that would print `nx3`:

```assembly
_start:
    lea rdi, [rip + msg]
    call puts@PLT
    xor edi, edi
    call exit@PLT

msg:
    .asciz "nx3"
```

The final artifact retains that entry point, but its main image has no executable segment or section. The `nx3` path is never reached. Instead, relocation processing builds the ORW chain, redirects the loader return, prints the contents of `/flag`, and exits.

```bash
git clone https://github.com/JiminChip/xless-elf.git
cd xless-elf
docker build -t xless-elf .
docker run --rm xless-elf
```

The expected visible line is:

```text
xless-elf demo flag
```

The repository includes a verifier for the central property:

![The xless-elf verifier confirms that the main image has no executable sections or segments](/assets/img/reloccult/part-2/xless-elf-verifier.png)

The same artifact can be inspected independently:

![readelf output showing that every PT_LOAD segment lacks the execute flag](/assets/img/reloccult/part-2/xless-elf-program-headers.png)

The program-header output contains no executable `PT_LOAD`. The dynamic table, meanwhile, still directs `ld.so` to the crafted symbol and relocation streams.

The Docker image pins a specific loader and libc pair, giving the witness a stable `link_map` order and reproducible offsets for loader-owned symbols, the stack handoff, functions, and gadgets. At runtime, the relocation stream recovers the randomized bases and initial-stack reference, then combines them with those fixed relationships to derive every address used by the ORW chain. This makes the full path from metadata processing to observable syscall output reproducible.

## What the Construction Actually Requires

It is useful to separate the machine's conceptual requirements from the choices made by one PoC:

| Conceptual requirement | Choice used by `xless-elf` |
| --- | --- |
| loader processes metadata before the entry point | normal `PT_INTERP` startup |
| writable state between operations | crafted `Elf64_Sym.st_value` cells |
| address arithmetic | symbol-based relocation plus addend |
| pointer dereference | eight-byte `R_X86_64_COPY` |
| initial runtime anchor | reserved PLT-GOT slot containing `link_map` |
| randomized base discovery | walk the pinned `link_map` order and read `l_addr` |
| stack discovery | loader's `__libc_stack_end` object |
| computed-address stores | rewrite a future relocation's `r_offset` |
| control-flow handoff | overwrite a saved loader return slot |
| visible payload | open, read, and write `/flag`, then exit |

Taken together, these pieces form the complete execution pipeline:

```text
anchor
  -> discover runtime state
  -> compute future destinations
  -> write a stack program
  -> redirect existing control flow
```

The result is a loader-driven program built from ordered relocation semantics, with `xless-elf` as a concrete implementation of that pipeline.

## Closing Notes

Part 1 showed that relocation metadata has write and call semantics before the executable entry point. Part 2 composes those semantics into something larger: a dataflow program that recovers its own runtime environment and prepares a new control-flow path.

The surprising part is not that a ROP chain can call functions or invoke syscalls. The surprising part is **where that chain comes from**. No main-image instruction constructs it. `ld.so` does, while applying a sequence of relocations that use dynamic symbols as state, loader structures as inputs, and future relocation entries as mutable instructions.

The PoC demonstrates this directly. Even when the main ELF contributes no executable load segment, its metadata can make the loader recover randomized addresses, write a control-flow program, and reach arbitrary syscall behavior before the entry point.

The concrete table layout, object order, and ORW payload are one realization. The durable idea is that metadata can become the program when an interpreter gives it enough state, memory semantics, and ordered execution.

## References

- [Weird ELF Machines (Part 1): Relocation Abuse for Arbitrary Writes and Calls](https://mini-chip.kr/posts/weird-elf-machines-part-1/)
- [JiminChip/xless-elf](https://github.com/JiminChip/xless-elf), the concrete PoC used in this post
- Rebecca Shapiro, Sergey Bratus, Sean W. Smith, [“Weird Machines” in ELF: A Spotlight on the Underappreciated Metadata](https://www.usenix.org/system/files/conference/woot13/woot13-shapiro.pdf), WOOT'13
- [System V AMD64 ABI / x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build), ELF relocation and dynamic linking sections
- glibc dynamic linker source: [`elf/dl-reloc.c`](https://codebrowser.dev/glibc/glibc/elf/dl-reloc.c.html), [`sysdeps/x86_64/dl-machine.h`](https://codebrowser.dev/glibc/glibc/sysdeps/x86_64/dl-machine.h), and [`include/link.h`](https://codebrowser.dev/glibc/glibc/include/link.h.html)

---
title: "Weird ELF Machines (Part 1): Relocation Abuse for Arbitrary Writes and Calls"
date: 2026-07-17 00:00:00 +0900
description: How ELF relocation metadata becomes a loader-driven machine for arbitrary writes and relocation-time calls before entry point.
read_time: 16
image:
  path: /assets/img/post-covers/weird-elf-machines-part-1.png
  alt: Diagram of ELF relocation metadata producing arbitrary writes and calls
  no_bg: true
categories: [Tech Articles, Reloccult]
tags: [weird-machine, elf, relocation]
comment: true
---

## Overview

This post starts from WOOT'13 paper, [“Weird Machines” in ELF: A Spotlight on the Underappreciated Metadata](https://www.usenix.org/system/files/conference/woot13/woot13-shapiro.pdf).

The paper is interesting because it asks us to look at ELF metadata differently. We usually treat metadata as something that describes a binary: section names, symbol tables, relocation tables, dynamic entries, and so on. But at load time, **some of that metadata is not passive at all**. It becomes input to `ld.so`, and `ld.so` actually interprets it.

Before a program reaches `main()`, the dynamic loader has already done a lot of work. It maps shared libraries, resolves symbols, applies relocations, and sometimes calls resolver functions. That means there is a window **before the executable entry point** where ELF metadata can already influence memory writes and control flow.

A simplified startup path looks like this:

```text
execve("./host")
  -> kernel reads ELF headers and PT_INTERP
  -> kernel maps the interpreter, ld.so
  -> ld.so maps shared objects
  -> ld.so applies .rela.dyn and any non-lazy .rela.plt relocations
  -> ld.so jumps to the ELF entry point
```

The interesting part is the relocation step. The host binary has not started yet, but `ld.so` is already reading metadata and modifying memory. If we frame that as a weird machine, the pieces line up naturally:

- `ld.so` is the interpreter.
- `.dynamic`, `.dynsym`, `.dynstr`, and `.rela.dyn` are part of the input program.
- relocation entries behave like memory-write instructions.
- symbol table entries can behave like values, pointers, or register-like state.

This series is my attempt to work through that idea from the primitive level up to a practical packer implementation. Part 1 and Part 2 stay close to the loader primitives. Later parts will move into the engineering side.

In this first post, I want to focus on two primitives:

1. arbitrary address write (AAW) behavior from relocation metadata
2. relocation-time arbitrary address calls through `GLOB_DAT` and unresolved `STT_GNU_IFUNC` symbol resolution

## A Quick Refresher on ELF Relocation

ELF relocation exists because some values cannot be finalized at compile time.

A simple example is a global function pointer in a PIE executable:

```c
#include <stdio.h>

static void target(void) {
    puts("target");
}

void (*fp)(void) = target;

int main(void) {
    fp();
    return 0;
}
```

`fp` can live in `.data`, but the exact address of `target` is not known when the binary is linked. If the binary is PIE, the image base changes at runtime. If the symbol comes from a shared object, that shared object also gets mapped at runtime.

So the linker cannot simply write the final address into the file. Instead, it leaves instructions for the loader. Conceptually, it says: “once you know the final address, write it into this slot.”

At runtime, the flow is roughly:

1. the kernel maps the executable and its interpreter, `ld.so`
2. control transfers to the dynamic loader
3. `ld.so` reads `.dynamic` and maps required shared objects
4. `ld.so` processes `.rela.dyn` and, when eager binding is required, `.rela.plt`
5. runtime addresses are written into the required memory slots
6. only then does control transfer to the executable entry point

The GOT follows the same idea. Imported functions such as `printf`, `puts`, or `memcmp` do not have final addresses in the executable file. With lazy binding, their GOT slots are resolved on first use. With `BIND_NOW` or full RELRO, those slots must already be resolved before the program starts running.

The key observation is small but important:

> **relocation is a loader-driven memory write** that happens before the program entry point.

For normal binaries, this is just runtime fixup. But if we can construct or transform relocation metadata, this behavior starts to look like a useful primitive.

## What a Relocation Entry Says

On x86-64, the relocation entries we usually care about are `Elf64_Rela` entries. `Rela` means the addend is stored explicitly in the relocation record.

```c
typedef struct {
    Elf64_Addr   r_offset;  // where to write
    Elf64_Xword  r_info;    // relocation type + symbol index
    Elf64_Sxword r_addend;  // immediate addend used by the relocation rule
} Elf64_Rela;
```

If a relocation references a symbol, the loader also looks at `.dynsym`. Those entries use the `Elf64_Sym` layout:

```c
typedef struct {
    Elf64_Word    st_name;   // offset into .dynstr
    unsigned char st_info;   // binding + type
    unsigned char st_other;
    Elf64_Half    st_shndx;  // section index
    Elf64_Addr    st_value;  // symbol value
    Elf64_Xword   st_size;   // symbol size
} Elf64_Sym;
```

The `r_info` field packs two pieces of information into one value:

```c
#define ELF64_R_SYM(info)   ((info) >> 32)
#define ELF64_R_TYPE(info)  ((uint32_t)(info))
#define ELF64_R_INFO(sym, type) (((uint64_t)(sym) << 32) | (type))
```

So each relocation entry answers three questions:

- `r_offset`: where should the loader write?
- `r_info`: which relocation rule should it use, and which symbol should it reference?
- `r_addend`: what immediate value should be used in the computation?

That maps directly to `readelf -rW` output:

```text
Relocation section '.rela.dyn' contains ... entries:
  Offset          Info           Type              Sym. Name + Addend
  000000004018    000000000008   R_X86_64_RELATIVE 1130
  000000004020    000300000001   R_X86_64_64       target + 0
```

`Offset` is `r_offset`. The upper 32 bits of `Info` are the symbol index, and the lower 32 bits are the relocation type. `Type` tells the loader which rule to apply.

A few relocation types are enough to see where this becomes interesting:

| Type | Approximate behavior | Weird-machine view |
| --- | --- | --- |
| `R_X86_64_RELATIVE` | `*(base + r_offset) = base + r_addend` | immediate-like write |
| `R_X86_64_64` | `*(base + r_offset) = S + A` | symbol value plus addend write |
| `R_X86_64_GLOB_DAT` | `*(base + r_offset) = resolved_symbol_addr` | GOT/function pointer slot patch |
| `R_X86_64_JUMP_SLOT` | write resolved function address into PLT/GOT slot | imported call target patch |
| `R_X86_64_COPY` | copy data from a symbol into the executable | loader-level copy primitive |

Here, `base` is the load base of the PIE or shared object, `S` is the resolved symbol value, and `A` is the addend.

The exact details vary by ABI and loader implementation, but the broad shape is clear: relocation metadata tells `ld.so` **where to write and how to compute the value**. This is why the WOOT'13 Cobbler work can treat relocation metadata as something closer to an instruction stream than a passive table.

## Relocation as a Write Primitive

Once you look at relocation this way, the next question is obvious: is this an arbitrary write?

Yes. **Relocation is a write performed by the dynamic loader**, and the relocation entry controls both the destination and the value computation.

### RELATIVE Writes

The simplest example is `R_X86_64_RELATIVE`:

```text
RELATIVE relocation:
    target = base + r_offset
    value  = base + r_addend
    *(uint64_t *)target = value
```

Here, `base` is already known to the loader while it is relocating the object. That makes the primitive straightforward: the **destination** comes from `r_offset`, and the **base-relative value** comes from `r_addend`.

### Symbol-Based Writes

Symbol-based relocations make the value side more flexible:

```text
R_X86_64_64 relocation:
    target = base + r_offset
    value  = resolved_symbol_value + r_addend
    *(uint64_t *)target = value
```

Now the written value can depend on symbol resolution. For example, the runtime address of a `libc` symbol can be written into a chosen slot. `GLOB_DAT` and `JUMP_SLOT` exist to fill GOT or function-pointer-like slots with resolved addresses.

None of this is a loader bug. This is exactly what relocation is supposed to do. The interesting part is that if the relocation table is crafted or transformed, normal loader behavior becomes **a programmable write engine**.

A normal binary has this path:

```text
source code -> compiler -> linker -> relocation metadata -> ld.so applies it
```

A crafted binary changes the source of the metadata:

```text
crafted metadata -> ld.so applies it -> controlled memory write before main()
```

The core model is simple: a relocation entry is an instruction to `ld.so` to write a computed value to a computed address.

### Self-Modifying Relocations

This also leads naturally to self-modifying relocation. An earlier relocation can patch the `r_offset` or `r_addend` field of a later relocation entry. That means the loader can execute a relocation instruction that was modified by a previous relocation.

```text
rela[0]: write a new value into rela[1].r_addend
rela[1]: use the patched r_addend to write the final value
```

At that point, `.rela.dyn` stops looking like a static table. It starts looking like **a mutable instruction stream**.

## Relocation-Time Arbitrary Address Calls

The write primitive is already useful, but there is another behavior worth separating out: relocation-time arbitrary address calls.

**This is not a GOT overwrite.** A GOT overwrite changes a call target that the program may use later. The program still has to reach a call site and call through that slot. The behavior here happens inside relocation processing itself, before the host executable reaches its entry point.

The WOOT'13 paper does use IFUNC behavior for conditional branching, but it does not present this specific `GLOB_DAT` + IFUNC interaction as a primary relocation-time arbitrary call primitive. That is the behavior I want to separate out here.

### GLOB_DAT and IFUNC

A normal `GLOB_DAT` relocation resolves a symbol and writes the resolved address into a target slot:

```text
R_X86_64_GLOB_DAT:
    sym   = dynsym[ELF64_R_SYM(r_info)]
    value = resolve_symbol(sym)
    *(uint64_t *)r_offset = value
```

If the referenced symbol is an `STT_GNU_IFUNC`, the resolved value is treated as an IFUNC resolver. The loader calls that resolver to obtain the final function address.

In simplified form:

```text
R_X86_64_GLOB_DAT + STT_GNU_IFUNC:
    sym      = dynsym[ELF64_R_SYM(r_info)]
    resolver = resolve_symbol(sym)
    value    = ((ifunc_resolver)resolver)()
    *(uint64_t *)r_offset = value
```

So `GLOB_DAT` is still a write relocation, but the IFUNC path inserts a call into the relocation flow. The important part is where that call happens: inside `ld.so`, **during relocation, before control reaches the executable entry point**.

Now combine this with the earlier write primitive. Suppose earlier relocations patch a symbol table entry that has not been used yet. A later `GLOB_DAT` relocation references that symbol. If the symbol is made to look like an unresolved IFUNC, and its resolved value or `st_value` points at a chosen address, `ld.so` may treat that address as an IFUNC resolver and call it.

```text
crafted dynsym entry:
    st_info  = STT_GNU_IFUNC
    st_value = target_address

crafted relocation:
    type     = R_X86_64_GLOB_DAT
    symbol   = crafted_ifunc_symbol
    r_offset = writable_slot

ld.so relocation path:
    resolver = target_address
    value = resolver()        # forced call before the entry point
    *writable_slot = value
```

That is **the arbitrary address call primitive** I mean here.

### Why This Is Not a GOT Overwrite

The difference from GOT overwrite is important:

- GOT overwrite is a future-call hijack.
- This primitive is a relocation-time call.
- It runs before the host entry point.
- It does not need an existing call instruction in the executable.
- The target is interpreted as an `STT_GNU_IFUNC` resolver.

This is not the same as “call any function with arbitrary arguments.” IFUNC resolver calling conventions and the loader's register/stack state still matter. But as a way to redirect instruction flow before the program starts, it is still a meaningful primitive.

In short:

```text
AAW primitive:
    relocation entries make ld.so perform controlled writes

AAC primitive:
    GLOB_DAT + IFUNC resolution makes ld.so call a controlled address
```

Together, these make ELF metadata feel much less like passive loader data. It has **write semantics**. It has **call semantics**. And the loader executes it before the program's own code begins.

## Putting It Together: AAW + AAC PoC

[**Download the PoC bundle** (`host.c`, the original binary, and the crafted binary)](/assets/files/reloccult/reloccult-part-1-poc.zip)

Now let us put both primitives into one small executable. This PoC starts with an initialized global variable and a function that prints its value. The important detail is that **nothing in the original program calls that function**. Under normal execution, only `main()` should print anything.

The complete source is below:

```c
#include <stddef.h>
#include <stdint.h>

#define INITIAL_VALUE 0x1111111111111111ULL

__attribute__((used, visibility("default")))
volatile uint64_t initialized_global = INITIAL_VALUE;

__attribute__((used, visibility("default")))
volatile uint64_t ifunc_result_slot = 0;

static long raw_write(int fd, const void *buffer, size_t length) {
    register long rax __asm__("rax") = 1;
    register long rdi __asm__("rdi") = fd;
    register const void *rsi __asm__("rsi") = buffer;
    register size_t rdx __asm__("rdx") = length;

    __asm__ volatile(
        "syscall"
        : "+a"(rax)
        : "D"(rdi), "S"(rsi), "d"(rdx)
        : "rcx", "r11", "memory"
    );
    return rax;
}

static size_t append_string(char *output, size_t offset, const char *text) {
    while (*text != '\0') {
        output[offset++] = *text++;
    }
    return offset;
}

static size_t append_hex_u64(char *output, size_t offset, uint64_t value) {
    static const char digits[] = "0123456789abcdef";

    output[offset++] = '0';
    output[offset++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        output[offset++] = digits[(value >> shift) & 0xf];
    }
    return offset;
}

/*
 * The injected STT_GNU_IFUNC symbol points here. ld.so calls this function
 * while processing the crafted GLOB_DAT relocation, before _start runs.
 */
__attribute__((used, noinline, visibility("default")))
void *relocation_time_printer(void) {
    char line[160];
    size_t length = 0;

    length = append_string(
        line,
        length,
        "[AAC] Called by ld.so before the entry point; initialized_global = "
    );
    length = append_hex_u64(line, length, initialized_global);
    line[length++] = '\n';
    raw_write(1, line, length);

    return (void *)&relocation_time_printer;
}

int main(void) {
    static const char message[] =
        "[ENTRY] This is main(), running after the executable entry point.\n";
    raw_write(1, message, sizeof(message) - 1);
    return 0;
}
```

Running the untouched `host` binary produces only the `[ENTRY]` line, exactly as the source suggests. I then add the AAW and AAC metadata described above to create `relocation-poc`. No call to `relocation_time_printer()` is added to the executable code.

The result is quite different:

![Execution of the original and crafted relocation PoC](/assets/img/reloccult/part-1/reloccult-part-1-poc.png)

The crafted binary prints the `[AAC]` line **before `main()` prints the `[ENTRY]` line**. Even more importantly, `relocation_time_printer()` observes `0x2222222222222222`, although the source initializes the global to `0x1111111111111111`.

So two things happened before the executable reached its entry point:

1. the initialized global was overwritten
2. a function with no source-level caller was invoked

How did the loader do that? The relevant relocation and dynamic-symbol metadata tells the whole story:

![The crafted relocation entries and dynamic symbols](/assets/img/reloccult/part-1/reloccult-part-1-poc-metadata.png)

The first crafted entry is the AAW:

```text
offset  = 0x43b8                  # initialized_global
type    = R_X86_64_64
symbol  = sym0                    # absolute value 0
addend  = 0x2222222222222222
```

For `R_X86_64_64`, the loader writes `S + A`. Since `sym0` is an absolute symbol with value zero, `ld.so` writes the addend directly to `initialized_global`:

```text
*(base + 0x43b8) = 0 + 0x2222222222222222
```

The next entry supplies the AAC:

```text
offset  = 0x43c8                  # ifunc_result_slot
type    = R_X86_64_GLOB_DAT
symbol  = sym1
sym1    = STT_GNU_IFUNC at 0x2150 # relocation_time_printer
```

`readelf` displays the type of `sym1` as `<OS specific>: 10`; on GNU systems, type 10 is `STT_GNU_IFUNC`. While resolving the `GLOB_DAT` relocation, `ld.so` therefore treats `base + 0x2150` as an IFUNC resolver and calls it. That address is `relocation_time_printer()`. Its return value is then written to `ifunc_result_slot`, completing the normal `GLOB_DAT` operation.

The order of the relocation entries matters. The AAW changes the global first, and the AAC calls the function afterward, so the function prints the already-modified value. **Both operations are performed by `ld.so` before the executable entry point**, without adding a normal call instruction to the program.

This also places the call earlier than the executable's usual `.init_array` constructor phase. A constructor can run before `main()`, but it is still part of the program's normal initialization path. Here, the loader is redirected while it is still interpreting relocation metadata. That is precisely what makes this behavior feel like a weird machine rather than an ordinary constructor trick.

## Closing Notes

Part 1 has a simple takeaway: relocation is a normal loader feature, but it can be viewed as a programmable engine that runs before the executable entry point.

By controlling `r_offset`, `r_addend`, symbol metadata, and relocation types, we get arbitrary address write behavior. By combining `GLOB_DAT` with unresolved `STT_GNU_IFUNC` symbol resolution, we also get a relocation-time arbitrary address call primitive.

This is why ELF metadata is such a good fit for the weird-machine framing. The executable code section does not have to change for loader behavior to change. **Metadata alone** can make `ld.so` perform meaningful work before `main()`.

In the next part, I will go one layer deeper and treat the relocation table more explicitly as an instruction stream. The main topics will be self-modifying relocations and using symbol metadata as register-like state. The actual packer implementation comes later, after the primitive model is clear.

## References

- Rebecca Shapiro, Sergey Bratus, Sean W. Smith, [“Weird Machines” in ELF: A Spotlight on the Underappreciated Metadata](https://www.usenix.org/system/files/conference/woot13/woot13-shapiro.pdf), WOOT'13.
- [System V AMD64 ABI / x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/jobs/artifacts/master/raw/x86-64-ABI/abi.pdf?job=build), ELF relocation and dynamic linking sections.
- glibc dynamic linker source: [`elf/dl-reloc.c`](https://codebrowser.dev/glibc/glibc/elf/dl-reloc.c.html), [`sysdeps/x86_64/dl-machine.h`](https://codebrowser.dev/glibc/glibc/sysdeps/x86_64/dl-machine.h).

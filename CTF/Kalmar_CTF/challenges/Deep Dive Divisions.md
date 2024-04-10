---
layout: simple
title: Deep Dive Divisions
---

This challenge is a vm challenge. While this may seem simple on the surface, as the decompiled code ends up being less than 150 lines, it’s not as easy a challenge as you might think…

**decompiled code**

```c
void __noreturn start()
{
  char v0; // si
  signed __int64 v1; // r9
  __int64 v2; // rdx
  int i; // eax
  int v4; // ecx
  char v5; // r10
  __int64 v6; // rsi
  int v7; // ecx
  char v8; // r10
  int v9; // eax
  int v10; // ebp
  int v11; // r8d
  int v12; // ebx
  size_t v13; // rdx
  unsigned __int8 v14; // di
  signed __int64 v15; // rax
  _BYTE *v16; // rsi
  int v17; // r11d
  int v18; // eax
  int v19; // r11d
  char *v20; // rsi
  signed __int64 v21; // rax
  __int64 v22; // rax
  __int64 v23; // rax
  __int64 v24; // rax
  __int64 v25; // rax
  __int64 v26; // rax
  signed __int64 v27; // rax

  v0 = -78;
  v1 = sys_mmap(0LL, 0x1F000uLL, 3uLL, 0x22uLL, 0xFFFFFFFFFFFFFFFFLL, 0LL);
  v2 = 0LL;
  for ( i = 0; ; v0 = byte_402080[i] )
  {
    v4 = i + 1;
    if ( v0 )
      break;
    i += 2;
    v5 = byte_402080[v4];
    v6 = i;
    v7 = 0;
    v2 += 1LL + (v5 & 0x7F);
    if ( v5 >= 0 )
      goto LABEL_3;
    do
    {
      v8 = byte_402080[v6];
      v7 += 7;
      v9 = v6++;
      v2 += (unsigned __int64)(v8 & 0x7F) << v7;
    }
    while ( v8 < 0 );
    i = v9 + 1;
    if ( i > 1664 )
    {
LABEL_9:
      v10 = 1;
      v11 = 0;
      v12 = 0;
      v13 = 1LL;
      while ( 1 )
      {
        v14 = *(_BYTE *)(v1 + v11);
        switch ( v14 >> 4 )
        {
          case 0:
            *(_BYTE *)(v1 + v12) += v14 & 0xF;
            break;
          case 1:
            *(_BYTE *)(v1 + v12) -= v14 & 0xF;
            break;
          case 2:
            v23 = v12 + dword_402040[(v14 ^ 8) & 0xF];
            *(_BYTE *)(v1 + v23) += *(_BYTE *)(v1 + v12 + dword_402040[*(_BYTE *)(v1 + v11) & 0xF]);
            break;
          case 3:
            v22 = v12 + dword_402040[(v14 ^ 8) & 0xF];
            *(_BYTE *)(v1 + v22) -= *(_BYTE *)(v1 + v12 + dword_402040[*(_BYTE *)(v1 + v11) & 0xF]);
            break;
          case 4:
            v25 = v12 + dword_402040[(v14 ^ 8) & 0xF];
            *(_BYTE *)(v1 + v25) ^= *(_BYTE *)(v1 + v12 + dword_402040[*(_BYTE *)(v1 + v11) & 0xF]);
            break;
          case 5:
            v24 = v12 + dword_402040[(v14 ^ 8) & 0xF];
            *(_BYTE *)(v1 + v24) &= *(_BYTE *)(v1 + v12 + dword_402040[*(_BYTE *)(v1 + v11) & 0xF]);
            break;
          case 6:
            v26 = v12 + dword_402040[(v14 ^ 8) & 0xF];
            *(_BYTE *)(v1 + v26) |= *(_BYTE *)(v1 + v12 + dword_402040[*(_BYTE *)(v1 + v11) & 0xF]);
            break;
          case 7:
            *(_BYTE *)(v1 + v12 + dword_402040[(v14 ^ 8) & 0xF]) = *(_BYTE *)(v1 + v12 + dword_402040[v14 & 0xF]);
            break;
          case 8:
            v20 = (char *)(v1 + v12);
            if ( (*(_BYTE *)(v1 + v11) & 8) != 0 )
              v21 = sys_write(v13, v20, v13);
            else
              v27 = sys_read(0, v20, v13);
            break;
          case 9:
            *(_BYTE *)(v1 + v12) = (v14 & 0xF) - *(_BYTE *)(v1 + v12) - 1;
            break;
          case 10:
            v16 = (_BYTE *)(v1 + v12);
            v17 = (unsigned __int8)*v16;
            v18 = v17 << (v14 & 7);
            v19 = v17 >> (v14 & 7);
            if ( (*(_BYTE *)(v1 + v11) & 8) == 0 )
              LOBYTE(v18) = v19;
            *v16 = v18;
            break;
          case 11:
            v12 += dword_402040[*(_BYTE *)(v1 + v11) & 7];
            break;
          case 12:
            if ( (*(_BYTE *)(v1 + v12) != 0) == ((v14 & 8) != 0) )
              break;
            goto LABEL_16;
          case 13:
            if ( (v14 & 8) != 0 || *(char *)(v1 + v12) < 0 )
LABEL_16:
              v10 = dword_402040[*(_BYTE *)(v1 + v11) & 7];
            break;
          case 14:
            v11 += v10 * ((char)(16 * v14) >> 4);
            break;
          case 15:
            v15 = sys_exit(0);
            break;
        }
        v11 += v10;
      }
    }
LABEL_4:
    ;
  }
  *(_BYTE *)(v1 + v2) = v0;
  ++i;
  ++v2;
LABEL_3:
  if ( i > 1664 )
    goto LABEL_9;
  goto LABEL_4;
}
```

The operations of VM are pretty straightforward, but how it handles data is quite tricky. This binary doesn’t display its data in a static way. Instead, it dynamically calculates where to store data in memory. I haven’t analyze how it computes dynamically, so I still don’t know its internal algorithm. With some debugging skills, it is not hard to scrape the already computed address where the data is stored, and you can even automate it.

So my first attempt was to analyze entire VM operations with a gdb script.

```python
#gdb -q -x debug.py
import gdb
import re

f = open("machine_code", "w")

# attch binary
gdb.execute("file ./chall")

# NO PIE
base = 0

# breakpoint for opcode
bp = 0x00000000004010DA
gdb.execute("b*"+hex(bp))

# breakpoint for descript
CASE0 = 0x0000000000401301
gdb.execute("b*"+hex(CASE0))
CASE1 = 0x0000000000401266
gdb.execute("b*"+hex(CASE1))
CASE2 = 0x000000000040124A
gdb.execute("b*"+hex(CASE2))
CASE3 = 0x000000000040121A
gdb.execute("b*"+hex(CASE3))
CASE4 = 0x00000000004012BA
gdb.execute("b*"+hex(CASE4))
CASE5 = 0x000000000040128A
gdb.execute("b*"+hex(CASE5))
CASE6 = 0x00000000004012EA
gdb.execute("b*"+hex(CASE6))
CASE7 = 0x00000000004011E5
gdb.execute("b*"+hex(CASE7))
CASEW = 0x00000000004011C5
gdb.execute("b*"+hex(CASEW))
CASER = 0x0000000000401316
gdb.execute("b*"+hex(CASER))
CASE9 = 0x00000000004011A7
gdb.execute("b*"+hex(CASE9))
CASE10 = 0x0000000000401189
gdb.execute("b*"+hex(CASE10))
CASE12 = 0x0000000000401143
gdb.execute("b*"+hex(CASE12))
CASE13 = 0x0000000000401129
gdb.execute("b*"+hex(CASE13))

def read_register(reg):
    val = gdb.execute("i r $"+reg, to_string=True)
    val = int(re.findall("0x([0-9a-f]+)", val)[0], 16)
    return val

def read_byte(addr):
    val = gdb.execute("x/b "+hex(addr), to_string=True)
    while val[0] == ":":
        val = val[1:]
    val = val[1:]
    return int(re.findall("0x([0-9a-f]+)", val)[0], 16)

# run
inp = "abcd"+chr(0xa)
gdb.execute("run "+"<<<"+"".join(inp), to_string=True)
cnt = 0
while True:
    gdb.execute("enable 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")
    cnt += 1
    rax = read_register("rax")
    rax &= 0xff
    opcode = rax >> 4
    operand = rax & 0xF
    gdb.execute("c")
    rip = read_register("rip")
    if rip == CASE0:
        dst = read_register("r9") + read_register("rax")
        src = read_register("rdi")
        assembly = "[%s] += %d\n"%(hex(dst), src & 0xff)
        f.write(assembly)
    elif rip == CASE1:
        dst = read_register("r9") + read_register("rax")
        src = read_register("rdi")
        assembly = "[%s] -= %d\n"%(hex(dst), src & 0xff)
        f.write(assembly)
    elif rip == CASE2:
        src = read_register("r9") + read_register("rcx")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rax")
        val = read_register("rcx")
        val &= 0xff
        assembly = "[%s] += [%s](%d)\n"%(hex(dst), hex(src), val)
        f.write(assembly)
    elif rip == CASE3:
        src = read_register("r9") + read_register("rcx")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rax")
        val = read_register("rcx")
        val &= 0xff
        assembly = "[%s] -= [%s](%d)\n"%(hex(dst), hex(src), val)
        f.write(assembly)
    elif rip == CASE4:
        src = read_register("r9") + read_register("rcx")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rax")
        val = read_register("rcx")
        val &= 0xff
        assembly = "[%s] ^= [%s](%d)\n"%(hex(dst), hex(src), val)
        f.write(assembly)
    elif rip == CASE5:
        src = read_register("r9") + read_register("rcx")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rax")
        val = read_register("rcx")
        val &= 0xff
        assembly = "[%s] &= [%s](%d)\n"%(hex(dst), hex(src), val)
        f.write(assembly)
    elif rip == CASE6:
        src = read_register("r9") + read_register("rcx")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rax")
        val = read_register("rcx")
        val &= 0xff
        assembly = "[%s] |= [%s](%d)\n"%(hex(dst), hex(src), val)
        f.write(assembly)
    elif rip == CASE7:
        src = read_register("r9") + read_register("rax")
        gdb.execute("ni")
        gdb.execute("ni")
        gdb.execute("ni")
        gdb.execute("ni")
        dst = read_register("r9") + read_register("rcx")
        assembly = "[%s] = [%s]\n"%(hex(dst), hex(src))
        f.write(assembly)
    elif rip == CASEW:
        buf = read_register("rsi")
        val = read_byte(buf)
        assembly = "print(%s): %c\n"%(hex(buf), chr(val))
        f.write(assembly)
    elif rip == CASER:
        buf = read_register("rsi")
        assembly = "read(%s)\n"%(hex(buf))
        f.write(assembly)
    elif rip == CASE9:
        dst = read_register("rcx")
        aseembly = "[%s] = %d - [%s] - 1\n"%(hex(dst), operand, hex(dst))
        f.write(assembly)
    elif rip == CASE10:
        conditon = read_register("rdi")
        dst = read_register("rsi")
        if conditon & 8 == 0:
            assembly = "[%s] = ([%s] << %d) >> %d\n"%(dst, dst, operand & 7, operand & 7)
        else:
            assembly = "[%s] = [%s] (do nothing)\n"%(dst, dst)
        f.write(assembly)
    elif opcode == 11:
        assembly = "calc v12 automatically (we don't need to know this val)\n"
        f.write(assembly)
    elif rip == CASE12:
        dst = read_register("r9") + read_register("rax")
        val = read_byte(dst)
        assembly = "cmp ([%s](%d) != 0), (%d != 0)\n"%(dst, val, operand & 8)
        f.write(assembly)
    elif rip == CASE13:
        dst = read_register("r9") + read_register("rax")
        val = read_byte(dst)
        assembly = "if [%s](%d) & 0x80, set zf\n"%(dst, val)
        f.write(assembly)
    elif opcode == 14:
        assembly = "calc v11 automatically (we don't need to know this val)\n"
        f.write(assembly)
    elif opcode == 15:
        assembly = "exit"
        f.write(assembly)
        break
    gdb.execute("c")

print('end??')
print(cnt)
```

Above is the gdb-script that describes the entire operation of vm.

While solving with the above method, I ran into the following big problem..

![Untitled](/CTF/Kalmar_CTF/challenges/Deep%20Dive%20Divisions_img/Untitled.png)

In gdb, the breakpoint was hit 14573 times, but the result of the script has only 250 lines…

I couldn’t find the cause of the problem. So, I tried to debug myself.

The only thing to be careful about is the address where the input is stored, and it can be resolved by inserting hw breakpoints in the memory where the inputs are stored.

I could find a verify routine here. This binary verify flag char by char, so flag can be calculated by 1-byte bruteforce.

![Untitled](/CTF/Kalmar_CTF/challenges/Deep%20Dive%20Divisions_img/Untitled%201.png)

This part doesn't actually check the flag directly, but I could see that the result of sub had to be zero to pass the check.

The detailed debugging process is my own rev know-how… Instead, below is my gdb script code for 1-byte bruteforce.

**exploit.py**

```python
#gdb -q -x exploit.py
import gdb
from string import printable

######## To Do ########
# binary name
binary = "./chall"

# breakpoint (compare instruction)
# bp가 loop 내부에 있지 않다면 코드 수정 바람
bp = 0x401222

# brute-force white list
#white_list = printable
white_list = "{_}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?!@#$%^&*-"

# flag_len
flag_len = 41

# init flag (flag format, etc...)
flag = "kalmar{"

# PIE BASE
#base = 0x0000555555554000
base = 0

#######################

# attach binary
gdb.execute("file ./chall")

# break point
gdb.execute("b*"+hex(base+bp))

def read_register(reg):
    val = gdb.execute("i r $"+reg, to_string=True)
    val = int(re.findall("0x([0-9a-f]+)", val)[0], 16)
    return val

def read_byte(addr):
    val = gdb.execute("x/b "+hex(addr), to_string=True)
    while val[0] == ":":
        val = val[1:]
    val = val[1:]
    return int(re.findall("0x([0-9a-f]+)", val)[0], 16)

# 1 byte brute-force
while (flag[-1] != "}"):
    for m in white_list:
        f = 0
        input = flag + m
        gdb.execute('run '+"<<<"+"".join(input), to_string=True)
        
        # bp가 loop 내부에 걸렸다고 가정함
        for i in range(len(flag)):
            gdb.execute('c')
        
        #############################################
        # 검증 코드 작성
        addr = read_register("r9") + read_register("rax")
        val = read_byte(addr)
        cmp_val = read_register("rcx")
        cmp_val &= 0xff
        if cmp_val == val:
            flag = flag + m
            f = 1
            print(flag)
            break
        #############################################
    if f == 0:
        print("no match error")
        exit()

```

![Untitled](/CTF/Kalmar_CTF/challenges/Deep%20Dive%20Divisions_img/Untitled%202.png)

flag: `kalmar{vm_in_3d_space!_cb3992b605aafe137}`
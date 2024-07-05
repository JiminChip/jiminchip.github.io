---
title: Pwnable Exploit Skeleton Code
categories: Tips-SkeletonCode
comment: true
---

```python
from pwn import *

#####GLOBAL#####
REMOTE = False
GDB = False
LOG = False
#################

###############CHECKSEC###############

######################################

def slog(n, m): return success(": ".join([n, hex(m)]))

def connect():
    global p, e, libc
    e = ELF("./prob")
    
    if LOG:
        context.log_level = 'debug'
    if REMOTE:
        p = remote()
        libc = ELF()
    else:
        p = process()
        libc = ELF()
        if GDB:
            gdb.attach(p)
            pause()
    return

def exploit():
    global p, e, libc

    return

def main():
    global p, e, libc
    connect()
    exploit()
    p.interactive()

if __name__ == "__main__":
    main()

```
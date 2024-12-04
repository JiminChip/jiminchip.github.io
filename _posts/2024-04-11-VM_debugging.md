---
title: VM_debugging (ver. gdbscript)
categories: Skeleton-Code
comment: true
---

**VM_debugging.py**

```python
# gdb -q -x VM_debugging.py
import gdb
import re

###########################################################
# To Do
# binary name
binary = "./binary"

# bp (원하는 pc를 찾기 위한 bp)
bp = 0x2813

#
def pc_debug():
    type = 'm'

    if type == "m":
        # set vm_pc's memory address
        vm_pc = 0x6840
        running_pc = gdb.execute("x/x "+hex(base+vm_pc), to_string=True)
        while running_pc[0] != ':':
            running_pc = running_pc[1:]
        running_pc = running_pc[1:]
        running_pc = eval(running_pc)
    else:
        # set vm_pc's register
        vm_pc = 'rax'
        running_pc = gdb.execute(("i r $"+vm_pc), to_string=True)
        running_pc = int(re.findall("0x([0-9a-f]+)", running_pc)[0], 16)
    return running_pc

# bp_list (원하는 pc를 찾은 뒤 걸려는 bp)
bp_list = []

# PIE Base
base = 0x0000555555554000

# Input 설정
inp = "qijfiejbnqiwfjij10932jfoiqewnboi1joiejfinboqiewjofiqnboqi4j1ofijeoino1ioqeifjo183fj8qiewjdkasv"

# bp건 이후 확인하고자 하는 값들을 자동으로 확인해주도록 함수 작성
def chip_debug(base):
    pass
###############################################################

# attach binary
gdb.execute("file {binary}")

# break point at pc
gdb.execute("b*" + hex(base + bp))

gdb.execute("run program "+"<<<"+"".join(inp), to_string=True)

while True:
    ### pc you want to insert bp ###
    pc = eval(input("input pc bp: "))
    if pc < 0:
        break
    while True:
        running_pc = pc_debug()
        if running_pc == pc:
            chip_debug()
            break
        print(running_pc)
        gdb.execute("c")
```
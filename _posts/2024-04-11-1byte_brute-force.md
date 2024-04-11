---
title: 1 byte brute-force (ver. gdbscript)
categories: Tips-SkeletonCode
comment: true
---


**1byte_bruteforce.py**

```python
# gdb -q -x 1byte_bruteforce.py
import gdb
from string import printable

######## To Do ########
# binary name
binary = 

# breakpoint (compare instruction)
# bp가 loop 내부에 있지 않다면 코드 수정 바람
bp = 

# brute-force white list
#white_list = printable
white_list = "{_}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?"

# flag_len
flag_len =

# init flag (flag format, etc...)
flag = ""

# PIE BASE
#base = 0x0000555555554000
base =

#######################

# attach binary
gdb.execute("file {binary}")

# break point
gdb.execute("b*"+hex(base+bp))

# 1 byte brute-force
while (len(flag) < flag_len):
    for m in white_list:
        input = flag + m
        gdb.execute('run '+"<<<"+"".join(input), to_string=True)
        
        # bp가 loop 내부에 걸렸다고 가정함
        for i in range(len(flag)-1):
            gdb.execute('c')
        
        #############################################
        # 검증 코드 작성
        

        #############################################

print(flag)
```
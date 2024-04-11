---
title: Debugging Automation - Gdb Script
categories: Tips-Reversing
comment: true
---

디버깅 작업을 자동화할 수 있는 도구이며, python 모듈 형태이다.

### 기본적인 기능들

```python
#import문으로 사용할 수 있다.
import gdb

#gdb의 명령어를 그대로 실행해준다.
gdb.execute("{명령어}")

#디버깅할 바이너리를 attach
gdb.execute("file ./binary")

#PIE가 걸린 경우 gdb에서는 대부분 base가 아래와 같다.
base = 0x0000555555554000

#원하는 곳에 bp 걸기
bp = 0x2321    #bp를 걸고 싶은 곳의 주소
gdb.execute("b*"+hex(base+bp))

#bp를 건 이후에 프로그램 실행
#이 때 입력을 미리 넣어줄 수 있다.
input = "303132333435363738393a3b3c3d3e3f40"
gdb.execute("run" + "<<<" + "".join(input), to_string=True)

#프로그램을 실행할 때 인자를 같이 넣어주려면 다음과 같이
gdb.execute("run {인자}" + "<<<" + "".join(input), to_string=True)
```

### Gdb Script가 필요한 경우

1. 1byte or 2byte brute-force
2. 특정 구간의 연산을 여러 번 확인해야 할 때

### 1byte or 2byte brute-force

입력값을 1byte씩 검사하는 로직인 경우에

검증 부분에 bp를 걸고 검증을 통과하면 해당 바이트를 플래그에 추가하고, 통과하지 못하면 다음 값으로 검증하는 것을 반복해서 flag를 얻어냄

예시:

[https://dreamhack.io/wargame/challenges/698](https://dreamhack.io/wargame/challenges/698)

**DreamHack의 r3t 문제의 exploit code**

```python
#gdb -q -x gdbscript.py
import gdb
import re

with open("log", "w") as f:
    f.write("")

def write(s):
    with open("log", "a") as f:
        f.write(s + "\\n")

# attach binary
gdb.execute("file ./run")

# NO PIE
base = 0

############### 1byte brute-force ###############
# flag white list
white_list = "{_}abcdef0123456789?" + "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
flag_len = 44
# delete bp 1 (0x400803)
#gdb.execute("d 1")

# break point - verify flag
bp = 0x402e23
gdb.execute("b*"+hex(base+bp))

# remain flag: 1 byte brute-force
flag = "DH{"
cnt = len(flag)
while(len(flag) < flag_len):
    assert len(flag) == cnt
    for m in white_list:
        input = (flag + m).ljust(flag_len, "A")
        gdb.execute('run '+"<<<"+"".join(input), to_string=True)
        for i in range(len(flag) - 1):
            gdb.execute('c')
        cl = gdb.execute('i r $rcx', to_string=True)
        al = gdb.execute('i r $rax', to_string=True)
        print(input)
        cl = int(re.findall("0x([0-9a-f]+)",cl)[0],16)
        al = int(re.findall("0x([0-9a-f]+)",al)[0],16)
        print(al, cl)
        if cl == al:
            flag += m
            write(flag)
            cnt += 1
            break

print(flag)
```

**1byte brute-force skeleton code**

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

#######################

# attach binary
gdb.execute("file {binary}")

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

### 특정 구간의 연산을 여러 번 확인

확인하고 싶은 곳에 bp를 걸고 거기서 값을 뽑아 옴. 레지스터의 값이나 메모리의 값을 읽어오면 됨. 원하는 결과가 다 뽑일 때까지 c를 반복

예시:

[https://dreamhack.io/wargame/challenges/1082](https://dreamhack.io/wargame/challenges/1082)

**DreamHack의 Function Network 문제의 Exploit Code**

```python
# gdb -q -x gdbscript.py
import gdb
import re

global cmp_table
cmp_table = [
    0xEB, 0xA2, 0x54, 0x42, 0xEF, 0x6B, 0x9A, 0xA7, 0xB8, 0xF7,
  0xFE, 0x80, 0xEC, 0x89, 0x0E, 0xAD, 0x9F, 0xF6, 0xE2, 0x53,
  0x7C, 0xEB, 0xA7, 0xB5, 0x2A, 0x7D, 0xE9, 0xE9, 0x7D, 0xED,
  0x0C, 0x4E, 0xC0, 0x52, 0x66, 0x25, 0xB6, 0x8E, 0x87, 0xD3,
  0xD9, 0xA0, 0x26, 0x8D, 0x6A, 0x04, 0xAF, 0x66, 0x1D, 0x5D,
  0x57, 0x6A, 0xB4, 0x1F, 0xFB, 0x6E, 0x75, 0x02, 0x81, 0x07,
  0xFC, 0x40, 0xB9, 0x3B
]

def convert_to_8byte_array(byte_string):
    result = []
    for i in range(0, len(byte_string), 8):
        value = int.from_bytes(byte_string[i:i+8], byteorder='little')
        result.append(value)
    return result

raw_command = open("export_results.txt", "r").read()

hex_string = raw_command.replace(',', '').replace('0x', '').replace(' ', '').replace('\\n', '')
byte_string = bytes.fromhex(hex_string)
mid_command = convert_to_8byte_array(byte_string)

command = []
for i in range(10000):
    tmp = []
    tmp.append(mid_command[3*i])
    tmp.append(mid_command[3*i + 1])
    tmp.append(mid_command[3*i + 2])
    command.append(tmp)

#get opcode (feat. gdb script)
#0 : add
#1 : xor
#2 : switch
#3 : sub
opcode = []

# attach file
gdb.execute("file ./chal")

# PIE BASE
base = 0x0000555555554000

# bp at opcode function
breakpoints = [0x6f4c, 0x6f8f, 0x7017, 0x6fd0]
for bp in breakpoints:
    gdb.execute("b*" + hex(base+bp))

input = "A"*64
gdb.execute('run '+'<<<'+"".join(input), to_string=True)
for i in range(10000):
    rip = gdb.execute("i r $rip", to_string=True)
    rip = int(re.findall("0x([0-9a-f]+)", rip)[0], 16)
    print(i)
    print(hex(rip))
    for idx, val in enumerate(breakpoints):
        if rip == base + val:
            opcode.append(idx)
    gdb.execute("c")

def sub_1byte(a, b):
    tmp = a - b
    if tmp < 0:
        tmp += 0x100
    return tmp

def add_1byte(a, b):
    tmp = a + b
    return tmp & 0xff

def rev_switch(idx1, idx2):
    global cmp_table
    tmp = cmp_table[idx1]
    cmp_table[idx1] = cmp_table[idx2]
    cmp_table[idx2] = tmp

def rev_add(idx1, idx2):
    global cmp_table
    val2 = cmp_table[idx2]
    val3 = sub_1byte(cmp_table[idx1], val2)
    cmp_table[idx1] = val2
    cmp_table[idx2] = val3

def rev_xor(idx1, idx2):
    global cmp_table
    val2 = cmp_table[idx2]
    val3 = cmp_table[idx1] ^ val2
    cmp_table[idx1] = val2
    cmp_table[idx2] = val3

def rev_sub(idx1, idx2):
    global cmp_table
    val2 = cmp_table[idx2]
    val3 = sub_1byte(val2, cmp_table[idx1])
    cmp_table[idx1] = val2
    cmp_table[idx2] = val3

for idx in reversed(range(10000)):
    if opcode[idx] == 0:
        rev_add(command[idx][1], command[idx][2])
    elif opcode[idx] == 1:
        rev_xor(command[idx][1], command[idx][2])
    elif opcode[idx] == 2:
        rev_switch(command[idx][1], command[idx][2])
    else:
        rev_sub(command[idx][1], command[idx][2])

print(cmp_table)
for i in cmp_table:
    print(chr(i), end ='')
print()

```

---

## How to Debug VM challenge???

VM 형식의 문제를 해결하는 과정에서 까다로운 것 중에 하나가 VM에서 돌아가는 program을 디버깅하는 것입니다.

VM은 loop형태로 program을 파싱하고 실행하기 때문에, 내가 원하는 지점까지 디버깅으로 돌아가기 위해서는 loop를 굉장히 많이 순회하며 원하는 bp까지 도달해야 합니다.

이 과정을 gdb script로 자동화시키면 보다 편하게 디버깅을 수행할 수 있습니다.

다음은 castle 문제를 디버깅하는 gdb script 코드입니다.

castle 문제 write-up

[https://www.notion.so/mini-chip/castle-0e9ab9f371de4c39994ef72ede775702](https://www.notion.so/castle-0e9ab9f371de4c39994ef72ede775702?pvs=21)

### debugging.py

```python
# gdb -q -x debugging.py
import gdb

# attach binary
gdb.execute("file ./vm")

# PIE Base
base = 0x0000555555554000

pop_reg = 0x2269
push_reg = 0x22DA
push_const = 0x2351
reg_add = 0x238F
stack_lshift= 0x23B3
stack_plus = 0x2406
reg_sub = 0x2455
reg_mul = 0x2479
reg_div = 0x249E
reg_rem = 0x24C3
branch_regval = 0x24EA
branch_regstat = 0x2529
cmp_reg = 0x2597
reg_putc = 0x25F9
reg_getc = 0x2635
exit_func = 0x2678
null_sub = 0x2693

bp_list = [0x2269, 0x22DA, 0x2351, 0x238F, 0x23B3, 0x2406, 0x2455, 0x2479, 0x249E, 0x24C3, 0x24EA, 0x2529, 0x2597, 0x25F9, 0x2635, 0x2678, 0x2693]

# break point at pc
gdb.execute("b*" + hex(base + 0x2838))
inp = "qijfiejbnqiwfjij10932jfoiqewnboi1joiejfinboqiewjofiqnboqi4j1ofijeoino1ioqeifjo183fj8qiewjdkasv"
gdb.execute("run program "+"<<<"+"".join(inp), to_string=True)

vm_stack = 0x5840
stack_pointer = 0x6844
vm_pc = 0x6840
reg0 = 0x6850
reg1 = 0x6854
reg2 = 0x6858
reg3 = 0x685c

while True:
    ### pc you want to insert bp ###
    pc = eval(input("input pc bp: "))
    if pc < 0:
        break
    while True:
        running_pc = gdb.execute("x/x "+hex(base+vm_pc), to_string=True)
        while running_pc[0] != ':':
            running_pc = running_pc[1:]
        running_pc = running_pc[1:]
        running_pc = eval(running_pc)
        if running_pc == pc:
            sp = gdb.execute("x/x "+hex(base+stack_pointer), to_string=True)
            while sp[0] != ':':
                sp = sp[1:]
            sp = sp[1:]
            sp = eval(sp)
            print("sp:", hex(sp))
            print("stack[sp]:")
            gdb.execute("x/x "+hex(base+vm_stack+sp))
            print("reg0:")
            gdb.execute("x/x "+hex(base+reg0))
            print("reg1:")
            gdb.execute("x/x "+hex(base+reg1))
            print("reg2:")
            gdb.execute("x/x "+hex(base+reg2))
            print("reg3:")
            gdb.execute("x/x "+hex(base+reg3))
            break
        print(running_pc)
        gdb.execute("c")
```

program file기준으로 원하는 pc에 bp를 걸 수 있도록 gdb script를 세팅했습니다.

원하는 곳에 bp가 걸린 이후에는, 디버깅에 필요한 메모리 정보들을 출력하도록 했습니다.

(stack pointer, stack, 4개의 register, pc)

![Untitled](/HackingTips/Reversing/Debugging%20Automation%20Gdb%20Script/Untitled.png)

3057번째 command에 bp를 걸어보겠습니다.

descriptor에서 뽑은 어셈으로 분석 했을 때에, 저기까지 도달하는 데 분기문이 존재하지 않았습니다.

그러면 원래라면 3057번 직접 gdb에서(혹은 IDA에서) c를 눌러야만 도달할 수 있었습니다.

script에서는 다음처럼 자동으로 해당 bp까지 도달합니다

![Untitled](/HackingTips/Reversing/Debugging%20Automation%20Gdb%20Script/Untitled%201.png)

그리고 필요한 정보들을 자동으로 출력하도록 세팅하는 것도 가능합니다.

하지만, gdb script가 충분한 속도를 제공해주지는 않습니다. 그래서 또 다른 방법은, emulator 구현입니다.

VM을 그대로 구현해주는 방식입니다. program 파일을 파싱해서 실행하는 프로그램을 그대로 구현하고, 디버깅할 수 있는 수단도 같이 구현해 주는 방법입니다. 에뮬레이터 구현은 descriptor를 짜면서 같이 구현하면 큰 시간 투자를 하지 않아도 구현해 줄 수 있어서 나름 선호하는 방법입니다.

cykorkinessis_v2 문제를 풀 때 에뮬레이터를 구현하는 방법을 사용하였습니다.

다음은 cykorkinessis_v2 문제를 풀 때 짰던 descriptor입니다.

```python
def convert_to_4byte_array(byte_array):
    result = []
    for i in range(0, len(byte_array), 4):
        value = int.from_bytes(byte_array[i:i+4], byteorder='little')
        result.append(value)
    return result

file_path = 'command.txt'
with open(file_path, 'r') as file:
    hex_string = file.read().replace(',', '').replace('0x', '').replace('\n', '').replace(' ', '')

    byte_array = bytes.fromhex(hex_string)

    tmp_command = convert_to_4byte_array(byte_array)

global command
command = []
for i in range(len(tmp_command) // 3):
    tmp = []
    tmp.append(tmp_command[3 *i])
    tmp.append(tmp_command[3*i+1])
    tmp.append(tmp_command[3*i+2])
    command.append(tmp)

def descriptor(cmd):
    op = cmd[0]
    dst = cmd[1]
    src = cmd[2]
    if op == 49:
        print("d[%d] = d[%d]"%(dst, src))
    elif op == 100:
        print("d[%d] >>= d[%d]"%(dst, src))
    elif op == 217:
        print("d[%d] ^= d[%d]"%(dst, src))
    elif op == 154:
        print("d[%d] <<= d[%d]"%(dst, src))
    elif op == 176:
        print("d[%d] = is_zero(d[%d])"%(dst, src))
    elif op == 242:
        print("d[%d] = ~d[%d]"%(dst, src))
    elif op == 52:
        print("d[%d] -= d[%d]"%(dst, src))
    elif op == 18:
        print("d[%d] += d[%d]"%(dst, src))
    elif op == 40:
        print("d[%d] = %d"%(dst, src))
    elif op == 67:
        print("d[%d] |= d[%d]"%(dst, src))
    elif op == 69:
        print("d[%d] &= d[%d]"%(dst, src))
    

#descriptor()

loop = [
    [49, 23, 19],
    [49, 24, 22],
    [100, 23, 24],
    [40, 24, 1],
    [69, 23, 24],
    [49, 24, 20],
    [49, 25, 22],
    [100, 24, 25],
    [40, 25, 1],
    [69, 24, 25],
    [49, 25, 23],
    [49, 26, 24],
    [49, 16, 26],
    [49, 17, 26],
    [49, 18, 16],
    [67, 18, 17],
    [176, 18, 18],
    [49, 16, 18],
    [49, 26, 16],
    [49, 16, 25],
    [49, 17, 26],
    [49, 18, 16],
    [67, 18, 17],
    [176, 18, 18],
    [49, 16, 18],
    [49, 25, 16],
    [49, 26, 23],
    [49, 27, 24],
    [49, 16, 26],
    [49, 17, 26],
    [49, 18, 16],
    [67, 18, 17],
    [176, 18, 18],
    [49, 16, 18],
    [49, 26, 16],
    [49, 16, 26],
    [49, 17, 27],
    [49, 18, 16],
    [67, 18, 17],
    [176, 18, 18],
    [49, 16, 18],
    [49, 26, 16],
    [49, 16, 25],
    [49, 17, 26],
    [49, 18, 16],
    [67, 18, 17],
    [176, 18, 18],
    [49, 16, 18],
    [49, 25, 16],
    [49, 26, 22],
    [154, 25, 26],
    [67, 21, 25],
    [40, 23, 1],
    [18, 22, 23]
]

loop1 = [
[49, 11, 2],
[49, 12, 3],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 2, 11],
[49, 3, 12],
[49, 8, 1],
[40, 10, 4],
[154, 8, 10],
[49, 11, 8],
[49, 12, 4],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 8, 11],
[49, 4, 12],
[49, 9, 1],
[49, 11, 9],
[49, 12, 2],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 9, 11],
[49, 2, 12],
[49, 19, 9],
[49, 20, 8],
[40, 21, 0],
[40, 22, 0]
    ]

loop2 = [
[242, 21, 21],
[49, 19, 21],
[49, 9, 19],
[49, 8, 20],
[49, 8, 1],
[40, 10, 5],
[100, 8, 10],
[49, 11, 8],
[49, 12, 5],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 8, 11],
[49, 5, 12],
[49, 19, 9],
[49, 20, 8],
[40, 21, 0],
[40, 22, 0]
    ]

loop3 = [
[242, 21, 21],
[49, 19, 21],
[49, 9, 19],
[49, 8, 20],
[49, 11, 0],
[49, 12, 9],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 0, 11],
[49, 9, 12],
[49, 8, 0],
[40, 10, 4],
[154, 8, 10],
[49, 11, 8],
[49, 12, 6],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 8, 11],
[49, 6, 12],
[49, 9, 0],
[49, 11, 9],
[49, 12, 2],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 9, 11],
[49, 2, 12],
[49, 19, 9],
[49, 20, 8],
[40, 21, 0],
[40, 22, 0]
    ]

loop4 = [
[242, 21, 21],
[49, 19, 21],
[49, 9, 19],
[49, 8, 20],
[49, 8, 0],
[40, 10, 5],
[100, 8, 10],
[49, 11, 8],
[49, 12, 7],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 8, 11],
[49, 7, 12],
[49, 19, 9],
[49, 20, 8],
[40, 21, 0],
[40, 22, 0]
    ]

loop5 = [
[242, 21, 21],
[49, 19, 21],
[49, 9, 19],
[49, 8, 20],
[49, 11, 1],
[49, 12, 9],
[49, 13, 11],
[217, 13, 12],
[49, 14, 11],
[69, 14, 12],
[40, 15, 1],
[154, 14, 15],
[18, 13, 14],
[49, 11, 13],
[49, 1, 11],
[49, 9, 12]
    ]

large_loop = loop1 + (32*loop) + loop2 + (32*loop) + loop3 + (32*loop) + loop4 + (32*loop) + loop5

print("Whole logic")
loop_cnt = 0
i = 0
while i < len(command):
    if command[i] == [49, 11, 2]:
        tmp = []
        for j in range(len(large_loop)):
            tmp.append(command[i+j])
        #print(tmp)
        if tmp == large_loop:
            print("Large loop", loop_cnt)
            i += len(large_loop)
            loop_cnt += 1
            continue
    #descriptor(command[i])
    print(command[i])
    i += 1
        
    
print()
print("Large loop: ")
print("  loop1")
print("  semi_loop x 32")
print("  loop2")
print("  semi_loop x 32")
print("  loop3")
print("  semi_loop x 32")
print("  loop4")
print("  semi_loop x 32")
print("  loop5")
print()

print("loop1:")
for i in loop1:
    descriptor(i)
print()

print("loop2:")
for i in loop2:
    descriptor(i)
print()

print("loop3:")
for i in loop3:
    descriptor(i)
print()

print("loop4:")
for i in loop4:
    descriptor(i)
print()

print("loop5:")
for i in loop5:
    descriptor(i)
print()

print("semi loop:")
for i in loop:
    descriptor(i)

def not_4byte(num):
    return 0xFFFFFFFF - num

def break_point(d, pc):
    global command
    print("================command===============")
    print("pc:", end=' ')
    descriptor(command[pc])
    print("=================data=================")
    print("0: ", end='')
    for i in range(10):
        print(d[i], end=' ')
    print()
    print("10: ", end='')
    for i in range(10):
        print(d[10 + i], end=' ')
    print()
    print("20: ", end='')
    for i in range(8):
        print(d[20+i], end=' ')
    print()
    print("======================================")

def VM(flag0, flag1, bp, command, d):
    d[0] = flag0
    d[1] = flag1
    for i in range(len(command)):
        if i in bp:
            break_point(d, i)
        op = command[i][0]
        dst = command[i][1]
        src = command[i][2]
        if op == 49:
            d[dst] = d[src]
        elif op == 100:
            d[dst] >>= d[src]
        elif op == 217:
            d[dst] ^= d[src]
        elif op == 154:
            d[dst] = (d[dst] << d[src]) & 0xffffffff
        elif op == 176:
            if (d[src] == 0):
                d[dst] = 1
            else:
                d[dst] = 0
        elif op == 242:
            d[dst] = not_4byte(d[src])
        elif op == 52:
            d[dst] = d[dst] - d[src]
            if d[dst] < 0:
                d[dst] += 0x100000000
        elif op == 18:
            d[dst] = (d[dst] + d[src]) & 0xffffffff
        elif op == 40:
            d[dst] = src
        elif op == 67:
            d[dst] |= d[src]
        elif op == 69:
            d[dst] &= d[src]
    return d

Large_loop_start = 6
loop1_len = len(loop1)
semi_loop_len = 32 * len(loop)
loop2_len = len(loop2)
loop3_len = len(loop3)
loop4_len = len(loop4)
loop5_len = len(loop5)

bp = []
ptr = Large_loop_start
bp.append(ptr)
ptr += loop1_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop2_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop3_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop4_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop5_len
bp.append(ptr)

d = []
for i in range(28):
    d.append(0)
print(VM(0x30303030, 0x31313131, bp, command, d))
```

descriptor 코드 내부에 에뮬레이터와 디버깅 수단이 같이 구현되어 있습니다.

해당 부분을 따로 보면 다음과 같습니다.

```python
def break_point(d, pc):
    global command
    print("================command===============")
    print("pc:", end=' ')
    descriptor(command[pc])
    print("=================data=================")
    print("0: ", end='')
    for i in range(10):
        print(d[i], end=' ')
    print()
    print("10: ", end='')
    for i in range(10):
        print(d[10 + i], end=' ')
    print()
    print("20: ", end='')
    for i in range(8):
        print(d[20+i], end=' ')
    print()
    print("======================================")

def VM(flag0, flag1, bp, command, d):
    d[0] = flag0
    d[1] = flag1
    for i in range(len(command)):
        if i in bp:
            break_point(d, i)
        op = command[i][0]
        dst = command[i][1]
        src = command[i][2]
        if op == 49:
            d[dst] = d[src]
        elif op == 100:
            d[dst] >>= d[src]
        elif op == 217:
            d[dst] ^= d[src]
        elif op == 154:
            d[dst] = (d[dst] << d[src]) & 0xffffffff
        elif op == 176:
            if (d[src] == 0):
                d[dst] = 1
            else:
                d[dst] = 0
        elif op == 242:
            d[dst] = not_4byte(d[src])
        elif op == 52:
            d[dst] = d[dst] - d[src]
            if d[dst] < 0:
                d[dst] += 0x100000000
        elif op == 18:
            d[dst] = (d[dst] + d[src]) & 0xffffffff
        elif op == 40:
            d[dst] = src
        elif op == 67:
            d[dst] |= d[src]
        elif op == 69:
            d[dst] &= d[src]
    return d

bp = []
ptr = Large_loop_start
bp.append(ptr)
ptr += loop1_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop2_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop3_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop4_len
bp.append(ptr)
ptr += semi_loop_len
bp.append(ptr)
ptr += loop5_len
bp.append(ptr)

d = []
for i in range(28):
    d.append(0)
print(VM(0x30303030, 0x31313131, bp, command, d))

```

bp를 내 입맛대로 추가해주고, 디버깅 정보를 출력할 수 있도록 구성하였습니다.

실행해보면 다음과 같습니다

![Untitled](/HackingTips/Reversing/Debugging%20Automation%20Gdb%20Script/Untitled%202.png)

cykorkinessis_v2에 대한 전체 wirte-up link: [https://mini-chip.notion.site/CykorKinessis_v2-58d7b4aac86b445aa5572edd97ee9c87?pvs=4](https://www.notion.so/CykorKinessis_v2-58d7b4aac86b445aa5572edd97ee9c87?pvs=21)

이것 외에 Frida를 가지고도 비슷한 기능을 구현할 수 있지 않을까 생각되는데, Frida는 나중에 따로 공부를 해야 할 것 같습니다.

**Skeleton Code**

```python
# gdb -q -x VM_debugging.py
import gdb
import re

######## To Do ########
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

#######################

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
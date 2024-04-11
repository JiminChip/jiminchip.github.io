---
layout: post
title: baeBFP
date: April 11, 2024
categories: CTF
comment: true
---
**상위 포스트 -** [bi0s CTF 2024](/2024-04/bi0s_CTF_2024)

---

이름: 정지민

닉네임: mini_chip

소속: 고려대학교 사이버국방학과

분야: Reversing

체감 난이도(1~10): 5

flag: `bi0sctf{jus7_4noth3r_us3rn4me@bi0s.in}` 

---

## 풀이 과정

문제 바이너리가 제공되지 않습니다. 

대신, nc로 접속하면 asm 코드가 제공됩니다. 어떤 환경에서 실행되는 어셈인지는 모르겠기에 실행 환경 구축하기도 조금 애매하고, 그냥 정적으로만 해결을 했습니다.

문제 제목에서 알 수 있듯이 eBPF라고는 하네요.

[asmdump.txt](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/asmdump.txt)

제공한 어셈코드입니다.

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled.png)

코드 보면, 전반적으로 알아 먹기가 굉장히 힘들었는데…

우선적으로 본 것은 최종 검증으로 추측되는 로직입니다.

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%201.png)

이렇게 `r1 == r3` 검증이 정확히 8번 존재하고, 통과하면 `r8 += 1` 통과 못 하면 `r8 += 0` 이 되도록 구성되어 있습니다. 그러면 저 `r1 == r3` 검증을 모두 다 통과해야 합니다.

그리고 용도를 알 수 없는 8byte 값을 같이 줬는데…. 코드를 어느 정도 보고 나니, 이게 검증하는 데 사용되는 값이지 않을까 싶어서 그냥 때려 봤더니 해결이 되었습니다.

```python
tmp = [0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]
for i in tmp:
    print(chr(i), end='')

print()
tmp = [83, 108, 119, 100, 105, 108, 113, 124]
for i in tmp:
    print(chr(i ^ 5), end='')
print()
```

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%202.png)

이렇게 값을 얻게 되었으니..

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%203.png)

입력을 하면 이렇게 `Lev 1 Complete` 문구와 함께 Level 2가 시작됩니다…

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%204.png)

Level 2에서는 이렇게 output과 어셈코드를 받아 볼 수 있습니다.

[level2_asm.txt](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/level2_asm.txt)

[prog_2_output.txt](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/prog_2_output.txt)

이것도 비슷하게 그냥 어셈 해석하면 됩니다. 대회 끝나니 무슨 로직이었는지 기억이 안나네요. 어렵지는 않았던 것 같습니다.

Level 2 해결하면

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%205.png)

파이썬 코드가 등장합니다.

해당 코드의 결과가 flag인데, reccur가 굉장히 비효율적으로 구현되어 있습니다.

recursive하게 구현된 것을 iterative하게 구현해 주면 효율적으로 구현할 수 있습니다.

이렇게 하면 최종 flag를 구할 수 있습니다.

솔직히 Level 2 하고는 다 푼 줄 알았는데…

또 있어서 멘탈 바사삭 했습니다. 문제 파일을 안 주니 몇 레벨까지 있는지 알 수가 없어서.. ㅠㅠ

그리도 3개의 level로 뇌절까지는 가지 않아서 다행이네요.

### Exploit Code

```python
"""
r1 = 2
(r10-24)[0] = 2
r7 = r10 - 24
r6 = (loop_idx << 3) + (map[idx:4] + 272)
r2 = r10 - 24
r0 = (loop_idx << 3) + (map[idx:3] + 272)
r1 = r6[0] ^ 5
r3 = r0[0]

두 개가 같아야 함

[0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]
"""

tmp = [0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]
for i in tmp:
    print(chr(i), end='')

print()
tmp = [83, 108, 119, 100, 105, 108, 113, 124]
for i in tmp:
    print(chr(i ^ 5), end='')
print()

output = [
    0x33ae2685,0x230bcdd5,0x4f5ac093,0x3dc3e00a,0xda19d0a1,0x32c52ad0,0xc904ffac,0x3037b842,0x9c7bf31e,0x4b8dfebc,0x33335ba7,0x4c4c9188,0xa555d9a9,0xaa069852,0xa177367f,0x79daa10f,0x29ca035c,0x319fbbc8,0xd51b4a1c,0x4a1b63b6,0x99f5d2f1,0xf35fdd82,0x7e70314f,0x42077d00,0x4f84cb2b,0x4a73846a,0xbbb0581e,0x8c33c34f,0x4eb73143,0xac45de0,0x82592087,0xc02544fa,0x56590be4,0xd2f78e08,0xb2c9d125,0x65e106d8,0x46711844,0xcf16ec7f,0xc85dde46,0x51d873d,0x50319f0f,0x8e5370bd,0x80145a76,0xbdbe90a6,0x3a10947e,0xfaf968c7,0xac700a03,0x47e061be,0xe9e65b90,0xe3c65a80,0xd707d969,0x40e93f77,0x447cf10e,0xbc69c7df,0xd8c669de,0x36c05ccf,0x876411ba,0xb37a6436,0xcdbeac33,0x7ba23db9,0xc18251bd,0x926d7a16,0x9ffb0134,0xc7f9ab96,0xc635711e,0x45b69a8,0x7b0fdd2e,0xf54849a7,0x61e5d839,0x1f12687d,0xb39a4ba1,0xd4fa2f5a,0xc308a7fd,0xcc0f199b,0x6b35768,0xecb39e48,0xb2c9d125,0x65e106d8,0x9e9a0f73,0xc58bdf39,0xa9bb76d1,0xc75ccd7,0x8473c66,0x8a4ed0e5,0xae1dcf9a,0x214f0ed5,0xfb6bf695,0x56e45cc6,0x47e4e2b9,0x8e2107d1,0x5a24b1dc,0x70599ee2,0x6cd313ec,0x4fa221e8,0x6696e856,0x62fde305,0x79958e01,0x1b99f294,0x876fd3a,0x59c1d749,0x0,0x0
]
print(len(output))

def sub_4byte(a, b):
    tmp = a - b
    if tmp < 0:
        tmp += 0x100000000
    return tmp

def add_4byte(a, b):
    return (a + b) & 0xffffffff

round_key = [0x9e3779b9]
for i in range(31):
    round_key.append(sub_4byte(round_key[i], 1640531527))

def rev_round(r5, x, round):
    tmp = add_4byte(x, round_key[round])
    tmp ^= add_4byte(((x << 4) & 0xffffffff), 0x12341234)
    tmp ^= add_4byte((x & 0xffffffe0) >> 5, 0x12341234)
    r4 = sub_4byte(r5, tmp)
    tmp = add_4byte(((r4 << 4) & 0xffffffff), 0x12341234)
    tmp ^= add_4byte(r4, round_key[round])
    tmp ^= add_4byte((r4 & 0xffffffe0) >> 5, 0x12341234)
    r7 = sub_4byte(x, tmp)
    return [r4, r7]

def rev_calc(a, b):
    r4 = a
    r7 = b
    for i in range(32):
        res = rev_round(r4, r7, 31-i)
        r4 = res[0]
        r7 = res[1]
    print_val1(r7)
    print_val1(r4)
    
    
    

def print_val(val):
    print(chr(val & 0xff), end='')
    print(chr((val >> 8) & 0xff), end='')
    print(chr((val >> 16) & 0xff), end='')
    print(chr((val >> 24) & 0xff), end='')

def print_val1(val):
    print(chr((val >> 24) & 0xff), end='')
    print(chr((val >> 16) & 0xff), end='')
    print(chr((val >> 8) & 0xff), end='')
    print(chr(val & 0xff), end='')
    
def reccur(i): 
     if(not i):
         return 1
     if(i == 1):
         return  3
     val_2 = 2 *reccur(i-1)
     return val_2 + 3* reccur(i-2) 
     exit()
    
def iter_reccur(i):
    res_list = [1, 3]
    if i >= 2:
        for j in range(i - 1):
            res_list.append(res_list[j+1] * 2 + 3 * res_list[j])
    return res_list[i]

for i in range(len(output) // 2):
    rev_calc(output[2*i+1], output[2*i])
print()

enc_flag = [102,75,163,239,156,158,7,143,92,120,0,54,183,65,199,253,60,182,204, 0]
print(len(enc_flag))
for i in range(19):
    ctr_val = iter_reccur((i * i) + 1) % 256
    #print("ctr_val[%d]:"%i, ctr_val)
    val = enc_flag[i] ^ ctr_val
    print(chr(val), end='')
print()

```

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_baeBPF/Untitled%206.png)

flag: `bi0sctf{eBPF_wtF_1s_th4t???}`
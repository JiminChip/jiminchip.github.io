---
layout: post
title: maybe Checker
date: October 14, 2024
categories: CTF
comment: true
---
**상위 포스트 -** [Blue Water CTF 2024](/2024-10/bwctf_2024)

---
[maybe_checker.zip](maybe_checker.zip)

Binary had 60 functions, and I debated whether to parse it or analyze it manually.

I thought 60 was reasonable number to analyze manually, so I chose to do it manually rather than parsing, which is hard to predict how long it will take.

After I analyzed, getting the flags was a simple matter of using the z3 solver. Below is the z3 solver code.

```python
from z3 import *

s = Solver()

flag = [BitVec(f"flag_{i}", 32) for i in range(48)]

for i in range(48):
    s.add(flag[i] < 0x100)

# 0x401210, 0
s.add(flag[0] == 98)
s.add(flag[1] == 119)
s.add(flag[2] == 99)
s.add(flag[3] == 116)
s.add(flag[4] == 102)
s.add(flag[5] == 123)
s.add(flag[47] == 125)

# 0x401240, 8
s.add(flag[8 + 3] == 45)
s.add(flag[8 + 9] == 45)
s.add(flag[8 + 15] == 45)
s.add(flag[8 + 21] == 45)
s.add(flag[8 + 27] == 45)
s.add(flag[8 + 33] == 45)

# 0x401270, 5
s.add(flag[5 + 13] < flag[5 + 14])

# 0x401280, 4
s.add(flag[4 + 2] ^ flag[4 + 30] == 100)

# 0x401290, 4
s.add(flag[4 + 14] < flag[4 + 17])

# 0x4012A0, 0x22
s.add(flag[0x22 + 2] * flag[0x22 + 8] == 7654)

# 0x4012C0, 4
s.add(flag[4 + 5] < flag[4 + 32])

# 0x4012D0, 7
s.add(flag[7 + 12] > flag[7 + 30])

# 0x4012E0, 7
s.add(flag[7 + 12] == flag[7 + 31])

# 0x4012F0, 0xD
s.add(flag[0xD] * flag[0xD + 14] == 3417)

# 0x17, 0x401310
s.add(flag[0x17 + 1] > flag[0x17 + 3])

# 0x17, 0x401320
s.add(flag[0x17 + 7] < flag[0x17 + 13])

# 0xB, 0x401330
s.add(flag[0xB + 8] > flag[0xB + 21])

# 6, 0x401340
s.add(flag[6 + 28] + flag[6 + 34] == 103)

# 9, 0x401360
s.add(flag[9 + 10] ^ flag[9 + 11] == 102)

# 0x13, 401370
s.add(flag[0x13 + 1] ^ flag[0x13 + 19] == 102)

# 0x16, 401380
s.add(flag[0x16 + 15] + flag[0x16 + 23] == 133)

# 2, 4013A0
s.add(flag[2 + 10] + flag[2 + 41] == 146)

# 6, 4013C0
s.add(flag[6 + 4] + flag[6 + 40] == 126)

# 0x15, 4013E0
s.add(flag[0x15 + 7] > flag[0x15 + 23])

# 6, 0x4013F0
s.add(flag[6 + 2] < flag[6 + 32])

# 0x15, 401400
s.add(flag[0x15 + 5] ^ flag[0x15 + 13] == 97)

# 0x10, 401410
s.add(flag[0x10 + 18] ^ flag[0x10 + 26] == 101)

# 6, 401420
s.add(flag[6 + 2] < flag[6 + 28])

# 8, 0x401430
s.add(flag[8] == flag[8+10])

# 2, 401440
s.add(flag[2 + 10] * flag[2 + 19] == 6699)

# 0xD, 401460
s.add(flag[0xD + 12] ^ flag[0xD + 18] == 123)

# 2, 0x401470
s.add(flag[2 + 4] ^ flag[2 + 14] == 21)

# 0xa, 401480
s.add(flag[0xa + 5] < flag[0xa + 30])

# 9, 0x401490
s.add(flag[9 + 21] ^ flag[9 + 22] == 14)

# 0xC, 4014A0
s.add(flag[0xC + 13] * flag[0xC + 33] == 4335)

# 4, 4014C0
s.add(flag[4 + 12] ^ flag[4 + 27] == 10)

# 0x18, 4014D0
s.add(flag[0x18 + 2] ^ flag[0x18 + 22] == 28)

# 0, 4014E0
s.add(flag[21] > flag[42])

# 3, 0x4014F0
s.add(flag[3 + 11] > flag[3 + 30])

# 1, 401500
s.add(flag[1 + 14] == flag[1 + 31])

# 8, 401510
s.add(flag[8 + 14] * flag[8 + 18] == 4264)

# 3, 401530
s.add(flag[3 + 15] < flag[3 + 19])

# 0, 401540
s.add(flag[14] + flag[15] == 132)

# 5, 401560
s.add(flag[5 + 5] * flag[5 + 28] == 3840)

# 0x16, 401580
s.add(flag[0x16 + 2] + flag[0x16 + 12] == 135)

# 8, 4015A0
s.add(flag[8 + 14] + flag[8 + 17] == 103)

# 8, 0x4015C0
s.add(flag[8 + 1] * flag[8 + 12] == 3417)

# 0xB, 4015E0
s.add(flag[0xB + 8] > flag[0xB + 35])

# 6, 4015F0
s.add(flag[6 + 4] + flag[6 + 22] == 132)

# 2, 401610
s.add(flag[2 + 25] + flag[2 + 28] == 137)

# 9, 401630
s.add(flag[9 + 3] ^ flag[9 + 5] == 25)

# 1, 401640
s.add(flag[1 + 19] * flag[1 + 42] == 3519)

# 0x1C, 401660
s.add(flag[0x1C + 4] * flag[0x1C + 6] == 2448)

# 1, 401680
s.add(flag[1 + 14] + flag[1 + 38] == 120)

# 7, 4016a0
s.add(flag[7 + 6] + flag[7 + 23] == 3570)

# 0x17, 4016C0
s.add(flag[0x17 + 1] + flag[0x17 + 21] == 154)

# 0x11, 4016E0
s.add(flag[0x11 + 3] ^ flag[0x11 + 11] == 103)

# 0xA, 4016F0
s.add(flag[0xA + 8] + flag[0xA + 15] == 100)

# 6, 401710
s.add(flag[6 + 1] * flag[6 + 15] == 6003)

# 0x11, 401730
s.add(flag[0x11 + 8] == flag[0x11 +17])

# 6, 0x401740
s.add(flag[6 + 2] ^ flag[6 + 3] == 114)

# 9, 401750
s.add(flag[9 + 10] ^ flag[9 + 27] == 12)

# 6, 401760
s.add(flag[6 + 4] ^ flag[6 + 8] == 100)

# 0xA, 401770
s.add(flag[0xA + 21] + flag[0xA + 36] == 150)

if s.check() == sat:
    model = s.model()
    res = b""
    for i in range(48):
        res += model[flag[i]].as_long().to_bytes(1, "little")
    print(res)
else:
    print("error")
```

flag: `bwctf{WE1C0-M3T0B-1U3W4-T3RCT-FH0P3-Y0UH4-VEFUN}`
---
layout: simple
title: beehive
---

이름: 정지민

닉네임: mini_chip

소속: 고려대학교 사이버국방학과

분야: Reversing

체감 난이도(1~10): 3

flag: `bi0sctf{jus7_4noth3r_us3rn4me@bi0s.in}` 

---

**문제 파일**

[beehive_zip.zip](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/beehive_zip.zip)

---

## 풀이 과정

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/Untitled.png)

파일의 포멧이 eBPF로 되어 있습니다.

[Reverse Engineering Ebpfkit Rootkit With BlackBerry's Enhanced IDA Processor Tool](https://blogs.blackberry.com/en/2021/12/reverse-engineering-ebpfkit-rootkit-with-blackberrys-free-ida-processor-tool)

eBPF 관련 link

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/Untitled%201.png)

ida에서 eBPF 프로세서 type이 기본적으로 없어서 디스어셈블조차 할 수 없었습니다.

[https://github.com/cylance/eBPF_processor](https://github.com/cylance/eBPF_processor)

**`GOD D1N0`**께서 위 링크 찾아 주셔서, ida에서 까볼 수 있게 되었습니다.

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/Untitled%202.png)

flag관련 핵심 로직인데, 솔직히 말하면, eBPF 어셈은 뭔가 알아먹기가 쉽지 않았습니다. call 3, call 4, call 5 이런게 있는데 이게 뭔가 싶기도 하고.

저게 flag관련 로직인 것도 거의 유사 게싱으로 알아냈습니다.

그래도 저 부분은 이상한 명령어는 없어서 어렵지 않게 해석할 수 있습니다. 매우 간단한 연산이며, 역연산 또한 매우 간단합니다.

### Exploit Code

```python
def rev(r5):
    r5 = ((r5 & 0x55) << 1) | ((r5 >> 1) & 0x55)
    r5 = ((r5 & 0x33) << 2) | ((r5 >> 2) & 0x33)
    r5 = ((r5 & 0xf) << 4) | ((r5 & 0xf0) >> 4)
    return r5

cmp = [
  0x56, 0x00, 0x00, 0x00, 0xAE, 0x00, 0x00, 0x00, 0xCE, 0x00, 
  0x00, 0x00, 0xEC, 0x00, 0x00, 0x00, 0xFA, 0x00, 0x00, 0x00, 
  0x2C, 0x00, 0x00, 0x00, 0x76, 0x00, 0x00, 0x00, 0xF6, 0x00, 
  0x00, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 
  0xCC, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0xFA, 0x00, 
  0x00, 0x00, 0xAE, 0x00, 0x00, 0x00, 0xCE, 0x00, 0x00, 0x00, 
  0xCC, 0x00, 0x00, 0x00, 0x4E, 0x00, 0x00, 0x00, 0x76, 0x00, 
  0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0xB6, 0x00, 0x00, 0x00, 
  0xA6, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x46, 0x00, 
  0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 
  0xCE, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x96, 0x00, 
  0x00, 0x00, 0x76, 0x00, 0x00, 0x00
]

for i in range(len(cmp) // 4):
    tmp = cmp[4*i]
    print(chr(rev(tmp)), end='')
```

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/Untitled%203.png)

flag: `bi0sctf{jus7_4noth3r_us3rn4me@bi0s.in}` 

---

eBPF 기계어를 리버싱할 수 있는 기회였습니다. eBPFkit를 이용해서 실행해 볼 수 있다고 하던데, 실행 환경을 구축해 보지는 않았습니다. 정적으로만 해석했습니다.

로직 자체는 어렵지 않았는데, 난생 처음 보는 바이너리 형태였기 때문에 적잖이 당황했네요.

대회가 끝난 이후 출제자 분의 설명을 보고 이해한 점을 조금 더 기술하자면,

eBPF는 kernel위에 적재되어 실행되는 일종의 유사 VM입니다.

eBPF 바이너리가 kernel에 성공적으로 적재된다면, 트리거가 되는 이벤트 발생 시에 eBPF 바이너리의 코드가 실행되게 됩니다.

beehive 바이너리의 초기 부분을 살펴보면,

![Untitled](/CTF/bi0s%20CTF%202024/Reversing/img_beehive/Untitled%204.png)

마지막 `jne`에서 `r1`값이 `0x31337` 가 아니면 `LBB0_18` 로 jmp하면서 코드가 종료됩니다.

이는 `0x31337`번 `syscall` 발생 시 `jmp`하지 않게 되며 이후 코드가 실행되는 방식의 트리거라고 하네요. 자세한 건 저도 잘 모르겠슴니다… ㅎㅎ..
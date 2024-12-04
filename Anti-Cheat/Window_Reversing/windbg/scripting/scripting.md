---
layout: post
title: Scripting (PyKD)
date: December 4, 2024
categories: Anti-Cheat
comment: true
---

**상위 포스트 -** [WinDbg](/Anti-Cheat/Window_Reversing/windbg/windbg)

---

**Index**

[개요](#개요)

[다운로드](#다운로드)

[&emsp;요청사항](#요청사항)

[&emsp;pykd.dll 설치](#pykddl-설치)

[&emsp;python module 설치](#python-module-설치)

[&emsp;설치 확인](#설치-확인)

[PyKD 기능](#pykd-기능)

[&emsp;pykd script 실행](#pykd-script-실행)

[&emsp;WinDbg command 그대로 수행하기](#windbg-command-그대로-수행하기)

[&emsp;Register 값 가져오기](#register-값-가져오기)

[&emsp;Process 실행 (g 명령어)](#process-실행-g-명령어)

[&emsp;memory 읽기](#memory-읽기)

[&emsp;comparing memory](#comparing-memory)

[&emsp;Detach](#detach)

[&emsp;Find Nearest Valid Memory Location](#find-nearest-valid-memory-location)

[&emsp;Function 찾기 (심볼 있을 때)](#function-찾기-심볼-있을-때)

[&emsp;page의 권한 확인](#page의-권한-확인)

[&emsp;bp 설정](#bp-설정)

[&emsp;Edit Memory](#edit-memory)

[&emsp;Edit IP](#edit-ip)

[마치며](#마치며)


---

## 개요

WinDbg에서 gdb script와 유사한 기능을 사용하고 싶은 것이 첫 번째.

기본적으로 단순 WinDbg 명령어들을 미리 txt에 적어 놓고,

순차적으로 실행할 수 있는 형태의 스크립트가 있지만, 너무나 약한 기능이다.

그것 외에도 WinDbg가 javascript API를 이용한 scripting을 지원하고 있지만, 개인적으로는 javascript보다는 Python이 훨씬 편하고 대다수의 사람들이 비슷하게 생각할 것 같아서 Python으로 scripting을 할 수 있는 WinDbg extension인 PyKD에 대해서 소개함.

---

## 다운로드

### 요청사항

![image.png](image.png)

일단 좀 안타까운 부분인데, 현재 3.9까지만 support된다. 

그렇기에 더 최신의 python을 사용 중이라면 다운그레이드 해야 한다.

3.9를 설치한 뒤, 시스템 환경 변수까지 야무지게 설정해주자.

![image.png](image%201.png)

일반적으로 `C:\Program File\` 여기에 설치되거나, 나처럼 `C:\Users\<username>\AppData\Local\Programs` 여기에 설치된다.

`Python39`의 경로와 `Python39\Scripts` 모두 환경 변수 `PATH`에 추가하면 된다.

### pykd.dl 설치

그 뒤 `pykd.dll`을 다운로드 받아 준다.

[](https://githomelab.ru/pykd/pykd-ext/-/wikis/Downloads)

원래 여기가 공식 다운로드 사이트인데, 더 이상 작동하지 않는다.

[GitHub - uf0o/PyKD: PyKD DLLs for x86 and x64 platforms](https://github.com/uf0o/PyKD/tree/main)

위 링크는 공식 링크는 아니지만, 공식 링크에 있던 `pykd.dll`들을 이전한 듯 하다.

다운로드 받아서 Window Kit 쪽 디렉토리에 넣어 놓거나, 본인이 알아서 새로 디렉토리 만들어서 넣어 놓자.

![image.png](image%202.png)

그 뒤에 `_NT_DEBUGGER_EXTENSION_PATH`라는 시스템 환경 변수를 만들고, 본인이 `pykd.dll`을 설치한 디렉토리를 변수 값으로 넣어 준다.

`pykd.dll`은 일종의 windbg extension이고, windbg는 `_NT_DEBUGGER_EXTENSION_PATH` 환경 변수의 경로에서 extension을 인식한다.

### python module 설치

`pykd.dll`은 windbg extension이었다면, 이제는 python에서 pykd 모듈을 설치할 차례이다.

python 3.9로 성공적으로 다운그레이드 되었다면

`pip install pykd`로 쉽게 다운로드 될 것이다.

![image.png](image%203.png)

### 설치 확인

WinDbg 커멘드 창에서 `.load pykd`를 입력한 뒤

`!help`를 쳤을 때

```
0:000> !help

usage:

!help
	print this text

!info
	list installed python interpreters

!select version
	change default version of a python interpreter

!py [version] [options] [file]
	run python script or REPL

	Version:
	-2           : use Python2
	-2.x         : use Python2.x
	-3           : use Python3
	-3.x         : use Python3.x

	Options:
	-g --global  : run code in the common namespace
	-l --local   : run code in the isolated namespace
	-m --module  : run module as the __main__ module ( see the python command line option -m )

	command samples:
	"!py"                          : run REPL
	"!py --local"                  : run REPL in the isolated namespace
	"!py -g script.py 10 "string"" : run a script file with an argument in the commom namespace
	"!py -m module_name" : run a named module as the __main__

!pip [version] [args]
	run pip package manager

	Version:
	-2           : use Python2
	-2.x         : use Python2.x
	-3           : use Python3
	-3.x         : use Python3.x

	pip command samples:
	"pip list"                   : show all installed packagies
	"pip install pykd"           : install pykd
	"pip install --upgrade pykd" : upgrade pykd to the latest version
	"pip show pykd"              : show info about pykd package
```

이런 식으로 뜬다면 성공이다.

아래는 실패한 경우

```
0:000> !help
acpicache [flags]            - Displays cached ACPI tables
acpiinf                      - Displays ACPI Information structure
acpiirqarb                   - Displays ACPI IRQ Arbiter data
acpiresconflict              - Displays detail on resource conflicts that cause
                               bugcheck 0xA5 (ACPI_ROOT_PCI_RESOURCE_FAILURE)
ahcache [flags]              - Displays application compatibility cache
amli <command|?> [params]    - Use AMLI debugger extensions
apc [[proc|thre] <address>]  - Displays Asynchronous Procedure Calls
arbiter [flags]              - Displays all arbiters and arbitrated ranges
arblist <address> [flags]    - Dump set of resources being arbitrated
bcb <address>                - Display the Buffer Control Block
biosreslist <address>        - Dump PnpBios/ACPI resource list
blockeddrv                   - Dumps the list of blocked drivers in the system
bpid <pid>                   - Tells winlogon to do a user-mode break into
                               process <pid>
bugdump                      - Display bug check dump data
bushnd [address]             - Dump a HAL "BUS HANDLER" structure
ca <address> [flags]         - Dump the control area of a section
calldata <ta이ble name>        - Dump call data hash table
cchelp                       - Display Cache Manager debugger extensions
chklowmem                    - Tests if PAE system booted with /LOWMEM switch
cmreslist <CM Resource List> - Dump CM resource list
(이하 생략)
```

이런 식으로 뜨면 실패한 것이다.

`pydk.dll`이 일단 제대로 로드 되지 않은 것

---

## PyKD 기능

### pykd script 실행

PyKD의 본격적인 기능들을 다루기 전에, PyKD 스크립트를 실행하는 법부터 살펴보자.

먼저 간단하게 WinDbg에서 `r` 명령어를 사용하는 script이다.

```python
# pykd-script.py
import pykd

print(pykd.dbgCommand("r"))
```

** 스크립트 저장할 때 공백 없는 경로에 저장하는 것을 추천한다.

`!py -3.9 <script path>` 이런 형식으로 실행하면 된다.

이렇게 하면 3.9 버전에서 script를 실행할 수 있다.

```
0:000> !py -3.9 C:\Hacking\pykd-script.py
rax=0000000000000000 rbx=00007ff927ceb760 rcx=00007ff927c50674
rdx=0000000000000000 rsi=0000008a77a3d000 rdi=00007ff927ce7b28
rip=00007ff927c8c0c4 rsp=0000008a77cff210 rbp=0000000000000000
 r8=0000008a77cff208  r9=0000000000000000 r10=0000000000000000
r11=0000000000000246 r12=0000000000000040 r13=0000000000000001
r14=000001aa96480000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
ntdll!LdrpDoDebuggerBreak+0x30:
00007ff9`27c8c0c4 cc              int     3
```

<aside>
💡

python version 바꾸기

`!info`를 실행하면 현재 사용 가능한 python 버전이 출력된다.
우리는 일단 3.9에 pykd를 설치했으므로, `!select version 3.9` 이렇게 하면 default 버전이 바뀐다고 한다.
그러면 `!py` 뒤에 `-3.9`를 굳이 안 붙여도 될 것 같은데…
일단 난 잘 안 되더라.

</aside>

<aside>
💡

script path를 작성할 때 “ “ 사이에 끼워 넣으면 path로 인식을 못한다.

</aside>

### WinDbg command 그대로 수행하기

`pykd.dbgCommand()`는 gdb script에서 `gdb.execute()`와 동일한 역할을 수행한다.

인자에 string type으로 WinDbg의 command를 그대로 넣으면 그 결과를 string으로 반환한다.

```python
import pykd

res = pykd.dbgCommand("r")

print(type(res))
```

위 스크립트 실행해보면

![image.png](image%204.png)

이렇게 string type인 것을 확인할 수 있다.

그래서 출력을 하려면 반드시 별도로 print를 수행해 주어야 한다.

### Register 값 가져오기

`pykd.reg()`로 쉽게 레지스터 값을 가져올 수 있다.

```python
import pykd

rax = pykd.reg("rax")
```

반환값은 int type이다.

아쉽게도 SIMD, Floating Point의 일부 레지스터들은 지원이 안된다.

### process 실행 (g 명령어)

`pykd.go()`를 수행하면 된다.

```python
import pykd

pykd.go()
```

### memory 읽기

`pykd.loadBytes`, `pykd.loadAnsiString`, `pykd.loadCStr`, `pykd.loadChars`, `pykd.loadDWords`, `pykd.loadDoubles` 등이 있다.

아마 제일 보편적으로 사용하는 것은 `pykd.loadBytes`일 것이다.

모두 `pykd.loadBytes(addr, size)` 이런 식의 파라미터를 받는다.

반환은 list 형태로 반환한다.

```python
import pykd

addr = pykd.reg("rip")
value = pykd.loadBytes(addr,16)

print(value)
```

![image.png](image%205.png)

### comparing memory

`pykd.compareMemory(addr1, addr2, size)` 이런 형태로 사용된다.

### Detach

`pykd.detachAllProcesses()` : 모든 프로세스들에서 detach하고 그것들의 모든 thread들을 resume

`pykd.detachProcess()` : debugging 중단

### Find Nearest Valid Memory Location

`pykd.findMemoryRegion(addr)`

사실 리버싱 할 때는 별로 의미 없는 기능인데,

addr 주변에서 가장 가까운 valid한 메모리 주소를 얻는다.

pwn할 때는 유용할 듯

### Function 찾기 (심볼 있을 때)

```python
import pykd

result = pykd.getOffset("KERNEL32!CreateFileW")
print(type(result))
print(hex(result))
```

이런 식으로 심볼 있는 dll의 함수 얻을 때 유용함.

int type으로 반환

![image.png](image%206.png)

### page의 권한 확인

```python
import pykd

addr1 = pykd.reg("rip")

result = pykd.getVaProtect(addr1)

print("RIP Attributes  : " + str(result))

addr2 = pykd.reg("rsp")

result = pykd.getVaProtect(addr2)

print("RSP Attributes  : " + str(result))
```

![image.png](image%207.png)

이런 식으로 `pykd.getVaProtect`를 이용하여 권한을 확인할 수 있음

### bp 설정

`pykd.setBP(addr, callback=None, params=None)`

- addr (필수)
    - breakpoint를 설정할 주소
    - 16진수 혹은 디버깅 symbol 사용 가능
    - 예: `0x7ff77b0710eb`, `KERNEL32!CreateFileW`
- callback (선택)
    - bp에 도달했을 때 호출될 Python 함수
    - gdb script에서 Bp class를 생성할 때 stop 메서드와 유사
    - `callback` 함수는 다음과 같은 스펙을 가져야 함
    
    ```python
    def callback(bp_id):
    		# bp_id: breakpoint ID
    		# params: 사용자 정의 parameter
    ```
    
- 반환값
    - 설정된 bp ID가 int type으로 반환됨

자 여기서 어려운 점이 하나 있다.

software bp를 걸어도, WinDbg 내에서 `bl`로 bp를 검색하면 걸리지 않는다.

```python
import pykd

def my_callback():
    rsp = pykd.reg("rsp")
    iter = pykd.loadDWords(rsp + 0x20, 1)[0]
    
    res = pykd.reg("ecx")
    print(hex(iter), ":", hex(res))
    return

bp = pykd.setBp(0x111D+0x7ff77b070000, my_callback)
print(bp)

pykd.go()
```

즉, bp를 걸면 pykd script 내에서만 유효하다.

callback 함수를 잘 설정하면 큰 문제는 없다.

![image.png](image%208.png)

실행 결과

### Edit Memory

`setBytes`, `setDWord`, `setDouble`, `setFloat` 등으로

`EB`, `EW`, `ED`, `EQ` 등등과 동일한 역할을 할 수 있다.

```python
import pykd

rsp = pykd.reg("rsp")

pykd.setDWord(rsp+0x20, 0x20)
```

![image.png](image%209.png)

### Edit IP

`setIP` : RIP나 EIP 등을 바꿀 수 있는 강력한 기능

`pykd.setIP(addr)` 처럼 사용하면 된다.

---

## 마치며

PyKD 공식 사이트가 다운 되어서 공식 docs를 살펴볼 수가 없어서

기능들을 여기 저기서 긁어왔다.

그래서 다루지 못한 중요한 기능들도 많을 것이고 순서도 그리 매끄럽지 않다. 양해 바란다.
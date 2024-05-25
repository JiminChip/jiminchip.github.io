---
title: BrownFlagChecker - LineCTF 2024
categories: CTF
comment: true
---

2024년 Line CTF에서 출제된 유일한 리버싱 문제입니다.

문제의 전반적인 컨셉은 크게 윈도우 드라이브로 Page Table를 수정하여 동일한 메모리를 여러 프로세스에서 접근하는 것 및 선제 디버깅을 통한 안티 디버깅 루틴입니다.

---

## 목차

[Attachment](#attachment)

[실행 환경 구축](#실행-환경-구축)

[BrownFlagChecker.exe 분석](#brownflagcheckerexe-분석)

[&emsp;1. 전반적인 Control Flow](#1-전반적인-control-flow)

[&emsp;2. 선제 디버깅을 통한 anti-debugging](#2-선제-디버깅을-통한-anti-debugging)

[&emsp;3. Parent process - 초기화 단계](#3-parent-process---초기화-단계)

[&emsp;4. Parent process - 입력 및 검증 단계](#4-parent-process---입력-및-검증-단계)

[&emsp;5. Child Process](#5-child-process)

[BrownProtector.sys 분석](#brownprotectorsys-분석)

[&emsp;1. DriverEntry](#1-driverentry)

[&emsp;2. IO Control](#2-io-control)

[&emsp;3. Case 0x224000](#3-case-0x224000)

[&emsp;4. Case 0x224008](#4-case-0x224008)

[&emsp;5. Case 0x224004](#5-case-0x224004)

[&emsp;6. Case 0x22400C](#6-case-0x22400c)

[&emsp;7. Case 0x224010](#7-case-0x224010)

[&emsp;8. Case 0x224014](#8-case-0x224014)

[Control Flow 정리](#control-flow-정리)

[역산](#역산)

[&emsp;Solver.py](#solverpy)

[Bypass Anti-Debug: DBVM](#bypass-anti-debug-dbvm)

[Reference](#reference)


---

## Attachment

아래는 문제에서 제공된 파일 원본입니다.

[BrownFlagChecker_eb525c0de7f75fccac7890e2c4f51216.zip](/CTF/LineCTF/BrownFlagChecker/BrownFlagChecker_eb525c0de7f75fccac7890e2c4f51216.zip)

---

## 실행 환경 구축

제공된 파일 중 README를 읽어보면,

```markdown
This challenge should be run in a Windows 10 or 11 VM, with `Secure Boot` disabled.

You must enable `Test mode` in the VM (See what is `Test mode` here: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

To enable `Test mode`, run the following command in an administrator command prompt.
```
bcdedit.exe -set TESTSIGNING ON
```
After that, reboot your VM.

The binary must also be run in an administrator command prompt.
```

윈도우의 실행 파일인 PE 파일 포멧이지만, 호스트에서 실행되는 것이 권장되지 않습니다. `Secure Boot`가 disable된 상태의 window 10, 11 VM 환경이 필요합니다.

해당 파일을 실행하기 위해서는 `Test mode`를 enable해야 한다고 합니다.

Window Driver의 경우 윈도우에서 공식적으로 서명 받지 않은 Driver는 실행할 수 없습니다.

공식적으로 서명 받지 않은 Driver를 실행시킬 수 있게 해주는 것이 `Test mode`입니다. 일반적으로는 Driver 개발 단계에서 Driver를 충분히 테스트해 볼 수 있도록 제공하는 기능입니다. 문제에서 제공된 Driver가 공식적으로 서명 받지 않은 Driver이기 때문에 실행을 위해서는 `Test mode`가 Enable 되어 있어야 합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled.png)

관리자 권한의 쉘에서 `bcdedit.exe -set TESTSIGNING ON` 명령어를 수행하여 `Test mode`를 Enable하고 재부팅합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%201.png)

원래는 위 화면처럼 실행이 불가능했지만

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%202.png)

이렇게 실행도 가능하고, flag 입력도 잘 들어가는 모습을 볼 수 있습니다.

---

## BrownFlagChecker.exe 분석

### 1. 전반적인 Control Flow

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%203.png)

main 함수의 15 line을 보면 `CreateProcessA`로 BrownFlagChecker.exe를 하나 더 실행하는 것을 확인할 수 있습니다.

`CreateProcessA` 함수의 스펙을 확인해보면

```cpp
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

이 중 `dwCreationFlags`에 해당하는 값이 2인 것을 볼 수 있습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%204.png)

해당 값은 `DEBUG_ONLY_THIS_PROCESS`에 해당하는 값으로 이 flag값은 디버그하며 프로세스를 생성하도록 합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%205.png)

메인 함수 초반에 위 루틴이 존재합니다. `CreateProcessA`에서 디버깅되면서 생성된 Child Process는 `IsDebuggerPresent()`에서 디버거 탐지가 수행되면서 `child_branch()`로 빠지게 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%206.png)

`child_branch`에서는 특정 작업을 수행한 뒤 무조건적으로 `Exit_routine()`을 수행합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%207.png)

`Exit_routine()`으로 인하여 Child Process가 main 함수로 다시 나와서 `CreateProcessA`를 수행하는 일은 없습니다.

`CreateProcessA`를 호출하면서 child를 실행했던 parent process의 경우 main함수 17 line while loop를 돌면서 child에 대한 디버깅을 수행합니다.

### 2. 선제 디버깅을 통한 anti-debugging

Linux에서 ptrace와 거의 유사한 원리입니다.

Window와 Linux를 포함하여 대부분의 운영체제는 프로세스 하나 당 붙일 수 있는 디버거는 하나로 제한됩니다.

그렇기에 보호하기를 원하는 프로세스에 타 디버거보다 선제적으로 디버거를 붙여 버리면, 타 디버거가 붙을 수 없습니다.

Linux에서 `ptrace(0,0,0,0)`으로 Self debugging을 수행할 경우 스스로가 스스로를 디버깅하는 형태로 되며, 현 문제의 경우 BrwonFlagChecker(Parent)가 BrownFlagChecker(Child)를 디버깅 하는 형태입니다.

다만, 이 문제의 경우 조금 더 발전된 기법을 사용하였습니다.

일반적으로 이런 방식의 안티 디버깅은 바이너리 패치로 우회하는 것이 일반적입니다. 허나 이 문제의 경우 디버깅이 실제 바이너리 동작에 관여하는 방식이어서 패치로 디버깅 루틴을 통으로 걸러 낸다면, 동작이 달라지게 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%208.png)

Parent의 `flag_checker`에서 Child로 받은 Debug Event에 따라 다른 동작을 수행하기도 하며,

flag_checker에서 child의 Context들을 받아와 동작을 수행하기도 합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%209.png)

child에서도 Debug Event를 발생시킬 때마다 다른 context를 가지고 있기에, 디버깅 루틴을 통으로 패치하거나 바이너리의 디버깅 루틴보다 더 먼저 디버거를 붙인다 하더라도 본래 바이너리의 동작과는 다르게 동작하게 됩니다.

### 3. Parent process - 초기화 단계

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2010.png)

Parent process의 경우 20 line에서 실행되는 `flag_checker`함수가 핵심입니다.

Child Process에서 Debug Event가 발생할 때마다 해당 Debug Event를 인자로 `flag_checker`함수가 실행됩니다.

Debug Event에 따라 `flag_checker`의 분기가 2가지로 나뉘게 되는데

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2011.png)

정확히는 DEBUG_EVENT 구조체인 parameter에서 DebugEventCode 멤버 변수에 의해 결정됩니다.

62라인, 64라인에서 DebugEventCode 값에 따라 나뉘는 분기가 그것입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2012.png)

위는 MSDN에서 제공하는 DebugEventCode에 해당하는 테이블입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2013.png)

flag의 2가지 핵심 분기 중 하나는 위 사진의 부분입니다.

Debug Event Code가 EXCEPTION이 아니고, CREATE_PROCESS 이벤트인 경우 이쪽 분기로 진입하게 됩니다.

이렇게 되면 CreateProcessA를 한 직후에 Child Process에서 CREATE_PROCESS 이벤트를 전달하게 되고, Parent의 `WaitForDebugEvent`에서 해당 디버그 이벤트를 받아 `flag_checker`에서 해당 분기로 진입하여 초기화 작업을 수행합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2014.png)

분기에 진입하게 되면 문제 파일에 같이 제공된 Driver에 대한 핸들을 열고 `DeviceIoControl`을 수행합니다. Device에서 어떤 작업을 하는지는 아직 분석하지 않았지만, DeviceIoControl의 결과로 OutputBuffer에 0x1337 값이 적재되게 된다면 if문 내부로 진입하면서 초기화 루틴을 수행하게 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2015.png)

위처럼 여러 값들을 대입하는 초기화 루틴을 진행합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2016.png)

최종적으로는 `Core_Buffer`에 `VirtualAlloc`한 메모리 주소들을 적재한 뒤 해당 메모리 주소들이 위에서 초기화했던 값들을 적재합니다.

→ `Core_Buffer`를 초기화하는 루틴으로 이해할 수 있습니다.

### 4. Parent process - 입력 및 검증 단계

`flag_checker`함수에서 핵심이 되는 두 번째 분기에 해당하는 부분입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2017.png)

Debug Event Code가 Exception과 관련된 이벤트일 때 167 line에 도달하게 되고, 167 line의 if문에서는 Context.P3Home값을 검증합니다. 해당 변수가 이후에 Context Structure로도 사용되서 Context 구조체로 캐스팅되어 있으나, 해당 값은 `flag_checker`의 인자인 Debug Event 값이 복사된 값으로 P3Home 멤버 변수의 하위 4byte는 ExceptionCode에 해당합니다.

즉 ExceptionCode가 0xC0000094인 경우 진입하게 되는 if문입니다.

해당 ExceptionCode는 0 나누기 시 발생하는 Floating Point Exception으로 추측됩니다.

→ Child 프로세스에서 Floating Point Exception 발생 시 수행되는 부모의 루틴입니다.

해당 루틴은 switch case문으로 구성되어 있으며, 입력 및 검증 결과를 출력하는 루틴이 포함되어 있습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2018.png)

switch문의 경우 Debug Event가 발생한 시점에서 child process의 context를 불러와서 Rax 레지스터이 값에 따라 분기됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2019.png)

rax값이 1인 경우 `Core_Buffer[0]`에 64byte 크기의 입력을 받은 뒤 `DeviceIoControl`로 device와 통신을 수행합니다.

그 외의 경우는 input 검증 결과를 출력하고 return합니다. 여기서 검증을 통과하기 위해서는 Child Process에서 rax 값이 2로 설정된 상태에서 Floating Point Exception이 일어나야 함을 추측할 수 있습니다.

Parent에서 Exception에 대한 처리 이후 rip 등등의 Context를 조정하는 것을 볼 수 있습니다. 이를 통해 Exception이 발생하더라도 Child는 정상적으로 실행을 이어나가도록 유도하는 것으로 생각됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2020.png)

main함수에서 디버깅 루프를 종료하기 위해서는 `flag_checker`에서 0을 반환해야 합니다.

`flag_checker`에서 0을 반환하는 루틴들을 살펴보면

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2021.png)

Context.P1Home은 Parameter인 Debug Event의 Debug Event Code를 의미합니다.

이 Debug Event Code가 5일 때 0을 return합니다. 즉, Child 프로세스가 종료되는 이벤트가 발생 시에 0을 반환하게 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2022.png)

그 외 0을 반환하는 곳은 flag 인증에 실패한 경우들에 해당합니다.

### 5. Child process

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2023.png)

child process가 최초 실행될 때 parent에서 초기화 루틴이 진행되었었습니다.

13line에서의 `DeviceIoControl`이후에 17 line에서 0 나누기가 발생합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2024.png)

해당 C 코드에 대응하는 어셈 코드를 봤을 때 Debug Event 발생 시점의 Rax값은 1로 추측할 수 있습니다. 이 지점에서 Parent에서 입력을 받게 됩니다.

20 line에서 `DeviceIoControl` 수행 이후에 24 line에서 반환값에 따라 rax값이 다르게 세팅 되게 되고 FPE를 일으키는 모습을 확인할 수 있습니다.

rax가 2가 되면 인증 성공, rax가 3이 되면 인증 실패가 되므로 24 line의 반환 값이 0이 되지 않도록 하는 것이 문제의 목표가 될 것 같습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2025.png)

해당 함수에서는 DeviceIoControl와 AES 루틴을 수행한 뒤

함수 마지막에서 memcmp로 검증을 수행합니다.

---

## BrownProtector.sys 분석

유저 코드에서 중간 중간 `DeviceIoControl`로 드라이버와 통신하는 모습을 볼 수 있었습니다. 이 `DeviceIoControl`로 인하여 드라이버에서 어떤 동작을 수행하는지 분석하겠습니다.

### 1. DriverEntry

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2026.png)

DriverEntry에 해당하는 함수입니다. 특이사항은 딱히 없으며, `IoCreateSymbolicLink`로 인하여 유저 애플리캐이션에서 `"\\??\\BrownProtectorDeviceLink”`로 드라이버에 접근할 수 있었습니다.

### 2. IO Control

유저 애플리케이션에서 `DeviceIoControl`을 수행했을 때 드라이버에서는 이를 처리하는 함수가 존재합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2027.png)

유저 애플리케이션에서 `DeviceIOControl`을 호출하였을 때 드라이버에서는 해당 함수가 호출됩니다.

`DeviceIoControl`을 살펴보면

```cpp
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice,
  [in]                DWORD        dwIoControlCode,
  [in, optional]      LPVOID       lpInBuffer,
  [in]                DWORD        nInBufferSize,
  [out, optional]     LPVOID       lpOutBuffer,
  [in]                DWORD        nOutBufferSize,
  [out, optional]     LPDWORD      lpBytesReturned,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```

위 스펙을 가지고 있습니다.

여기서 `dwIoControlCode`에 해당하는 값이 드라이버의 핸들러 함수에서

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2028.png)

2 번째 인자인 Irp로부터 해당 값을 받아서 19 line의 형식으로 처리하고 있습니다.

이 `dwIoControlCode`값에 따라서 switch문 형식으로 서로 다른 동작을 처리하도록 구현되어 있습니다. 뒤에서 분석할 Case들 역시 이 `dwIoControlCode`값에 따라 나뉘는 case들입니다.

### 3. Case 0x224000

먼저 첫 번째 케이스는 Parent Process에서 초기화 단계에 진입할 때 수행하는 `DeviceIoControl`입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2029.png)

이 곳에서 호출합니다.

아래는 이에 대응하는 드라이버의 코드입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2030.png)

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2031.png)

if문들을 모두 통과하면 OutBuffer쪽에 0x1337 값을 밀어 넣어주고, 그렇지 않다면 0xDEAD값을 넣어 줍니다. (LABEL_42는 DeviceIoControl을 종료하는 루틴입니다)

CRC_checker, CheckDebugging, Check_ControlReg 함수를 각각 살펴보면

**CRC_checker**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2032.png)

먼저 GetImageBase 함수부터 살펴보겠습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2033.png)

`ZwQueryInformationProcess`함수의 주소를 `MmGetSystemRoutineAddress` 함수로 가져온 뒤 실행합니다.

`ZwQueryInformationProcess`의 MSDN을 살펴보면

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2034.png)

저런 방식으로 함수를 가져오는 것이 정상적인 방법이라고 합니다.

이렇게 가져와서 프로세스(드라이버)의 `ImageBaseAddress`를 반환하게 됩니다.

그 다음은 ParsePE 함수입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2035.png)

GetImageBase로 받아온 드라이버의 ImageBase를 이용하여 PE 포멧의 이미지를 파싱합니다.

~~파싱하여 두 번째 세 번째 인자였던 곳에 text영역의 VA와 PA 값을 쓰게 됩니다~~.

정정합니다. 두 번째 인자는 text영역의 VA를 쓰는 것이 맞습니다. PA는 Physical Address가 아닌 VirtualSize를 쓰게 됩니다.

마지막 crcCHECK함수를 살펴보면

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2036.png)

아까 받아온 text영역의 VA를 이용하여 crc 값을 계산합니다. 실재 RAM에 적재되어 있는 이미지를 참조하며 

**CheckDebugging**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2037.png)

이번에도 `ZwQueryInformationProcess` 를 수행합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2038.png)

이 때 해당 함수의 두 번째 인자가 7로 Debugging 정보를 Query하는 동작을 수행하는 것으로 이해할 수 있습니다.

반환 값은 프로세스가 디버깅 중인지 아닌지 여부를 반환하게 됩니다.

**Check_ControlReg**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2039.png)

cr0 레지스터와 cr4 레지스터에 있는 값을 읽어 값을 검증하고 있습니다.

`v0 < 0`의 경우 cr0의 최상위 비트가 set 되어 있는지 여부를 검증하고 있고, `(v1 & 0x1000) == 0`의 경우 cr4 레지스터의 12번째 비트가 set 되어 있는지 여부를 검증합니다.

cr0의 경우 운영 모드를 제어하는 레지스터로 cr0의 최상위 비트는 PE(Protection Enable)을 의미합니다.

cr4의 경우 프로세서에서 지원하는 각종 확장 기능을 제어하는 레지스터로 12번째 비트는 LA57로 5 Level Paging이 Enabled 되어 있는지 여부를 나타냅니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2040.png)

정리해 보면 Driver 코드에 대하여 Anti Cheat 루틴들을 수행하는 것으로 보입니다.

CRC Check로 무결성 검사를 수행하고, 디버깅 중인지 여부 등을 확인합니다.

모든 것이 정상이라고 판단되면 0x1337을 OutBuffer에 내뱉고, 문제가 있다고 판단되면 0xDEAD를 내뱉게 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2041.png)

DeviceIoControl을 호출한 Parent 프로세스의 경우 이 OutBuffer가 0x1337인 경우에만 초기화 루틴을 수행하며 그렇지 않은 경우 `flag_checker`함수에서 0을 리턴하며 프로세스를 바로 종료시킵니다.

### 4. Case 0x224008

해당 케이스의 IO Control을 호출하는 유저 애플리케이션의 지점은 input을 입력 받는 부분입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2042.png)

이곳은 Parent Process에서 초기화 루틴 수행 후, child process에서 최초로 FPE 이벤트가 발생되는 시점에서 수행되는 루틴입니다.

`DeviceIoControl`의 Input에서는 Core_Buffer가 들어가는 것을 볼 수 있습니다.

`Core_Buffer`는 기본적으로 이중 포인터 형식으로 이해해야 하며, `Core_Buffer` 배열에 저장된 값은 모두 초기화 루틴에서 VirtualAlloc으로 할당 받은 주소들입니다.

`Core_Buffer[0]`에는 input이 들어가며, 그 외의 VirtualAlloc으로 할당 받은 주소(Core_Buffer가 가리키는 곳들)에는 초기화 루틴에서 대입한 값들이 적재됩니다.

아래는 Driver에서 해당 케이스의 IO control을 처리하는 코드입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2043.png)

기본적으로 PID check와 CRC_checker, CheckDebugging 등을 수행하고 있습니다.

`Irp→AssociatedIrp.MasterIrp`의 경우에는 `DeviceIoControl`에서 InBuffer에 해당하는 것으로 추측됩니다.

또한 `Options`의 경우에는

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2044.png)

위 형태로 값이 설정되는데, 자료형 캐스팅은 문제가 있어 보이지는 않는데… 해당 멤버 변수와는 무관하게 `DeviceIoControl`에서 InBufferSize로 추측됩니다.

대략적인 코드 동작을 살펴보면, Driver의 전역 변수인 `unk_45A0` 배열에 InBuffer에 들어왔던 VirtualAlloc으로 할당한 주소들 값을 `sub_1C1C`에서 처리한 결과를 적재합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2045.png)

sub_1C1C에서는 cr3 레지스터 기반으로 꽤 복잡해 보이는 동작을 수행합니다.

cr3는 PageDirectory에 관한 정보를 담고 있는 레지스터로 하위 12비트를 제외한 곳에 페이지 디렉토리의 주소를 의미합니다.

실제로 11 line에서 PageDirectory에 접근하려는 것을 볼 수 있습니다.

그 이후로 하는 작업은 인자로 들어온 가상 주소를 Page Directory 통해 그에 해당하는 물리 주소를 찾는 동작입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2046.png)

4 Level Paging으로 구성된 것을 PML4 Table부터 쭉 참조하여 Physical Address를 찾아내는 형식입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2047.png)

다시 정리하자면, InBuffer에서 들어온 값들은 Parent Process에서 초기화 과정 중에 VirtualAlloc으로 할당 받은 메모리 공간의 가상 주소 들입니다.

그리고, 해당 값들을 `sub_1C1C` 를 통해 그에 대응하는 물리 주소를 찾아 `unk_45A0` 배열에 적재하는 동작을 수행하게 됩니다.

### 5. Case 0x224004

이 케이스의 경우 Child Process에서 호출하는 `DeviceIoControl` 에 해당합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2048.png)

Child Process가 실행된 직후에 드라이버 핸들을 가져와서 드라이버와 연결하게 됩니다.

정확히는 Child Process가 생성되면서 프로세스 생성 이벤트 발생으로 Parent에서 초기화 루틴 수행후 재개된 Child Process에서 바로 다음 수행되는 루틴입니다.

아래는 0x224004 케이스를 처리하는 드라이버의 코드입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2049.png)

**sub_1704**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2050.png)

`ZwQueryInformationProcess`로 v2에 현재 프로세스에 대한 정보를 쿼리합니다.

그 후 v2에서 PID를 반환하게 됩니다.

이 PID가 전역 변수 `DriverPID` 의 값과 동일해야 하며, 이 값은 Parent의 초기화 루틴에서 호출된 DeviceIoControl에서 Driver가 `PsGetCurrentProcessId`를 호출한 반환 값으로 설정된 바 있습니다. 이 값은 같아야 정상입니다. 이 검증은 역시나 anti-cheat를 위해 추가된 검증 루틴으로 생각됩니다.

그 뒤에는 전역 변수에 PID와 Thread ID를 저장한 뒤 `sub_1554`의 반환값에 따라 OutBuffer에 0xDEAD 혹은 0x1337 값을 넣어 줍니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2051.png)

OutBuffer에 값이 0x1337이어야만 Child Process에서 동작들을 정상적으로 수행하며,  0xDEAD 값을 내뱉을 경우 바로 `Exit_routine()`을 수행하도록 되어 있습니다.

**sub_1554**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2052.png)

여기서 0을 return해야 0x1337을 OutBuffer로 보냄으로 child가 정상 동작하게 됩니다.

함수의 기본적인 동작은 CallbackRegistration에 값들을 설정하고 `ObRegisterCallbacks` 함수를 통해 프로세스 핸들 작업에 대한 콜백 루틴 목록을 등록합니다.

이 때 39 line의 `ObRegisterCallback`의 반환값은 0이거나 0xC01C0011이어야 하며,

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2053.png)

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2054.png)

해당 값들은 NTSTATUS에 위 값들로 정의되어 있습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2055.png)

즉, registration 작업이 성공적으로 수행되었거나 이미 등록되어 있던 경우만 에러가 아니라고 판단하고, 그 외 registration 작업 중 다른 반환 값을 반환하게 되면 드라이버가 child process에  0xDEAD를 내뱉게 됩니다.

### 6. Case 0x22400C

이 케이스도 child 프로세스에서 호출됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2056.png)

여기서도 OutBuffer인 v3에 0xDEAD말고 다른 값이 반환되어야 child가 정상 동작하게 됩니다.

드라이버에서는 초기화 혹은 anti-cheat를 위한 검증 루틴이 들어 있을 것으로 추측됩니다.

아래는 대응하는 드라이버의 코드입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2057.png)

먼저 `qword_45A0`의 경우 case 0x224008에서 설정해줬던 VirtualAlloc들의 Physical Address들입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2058.png)

그리고 `qword_4430`은 이렇게 값이 초기화 되어 있는 데이터들입니다.

이렇게 v8배열(v16배열이랑 같음)에 data 영역의 값들과 VirtualAlloc 주소들의 Physical Address들을 넣어 준 뒤 `sub_189C`에 전달됩니다.

sub_189C에서는 PML4 Table을 만드는 과정을 수행합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2059.png)

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2060.png)

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2061.png)

함수 전체는 상당히 긴 편이라서 PML4 자료구조를 만드는 것에 핵심적인 루틴만 뽑아 봤습니다.

이 3개의 캡처본 중 가장 위의 것을 보시면 Data에 0x6969696969를 xor 하는 것을 확인할 수 있습니다.

이렇게 xor된 값이 Virtual Address를 의미하게 됩니다.

이 Virtual Address를 구해 보면

```python
qword_4430 = [0x0000006CFC3D1969, 0x0000006D3D5DF969, 0x0000006D9D9DB969, 0x0000006DBDFC0969, 0x0000006D1D9D2969, 0x0000006C2D7D5969, 0x0000006C5C4C7969, 0x0000006C6DFCC969, 0x0000006C2D7D4969, 0x0000006D3CFD3969, 0x0000006D0D3D2969, 0x0000006D3C6C5969, 0x0000006D8DFC1969, 0x0000006DDC2D7969, 0x0000006CFC4D5969, 0x0000006D5D4D7969, 0x0000006D2D3C4969, 0x0000006C4DFD7969, 0x0000006C1D9D5969, 0x0000000000000069]

res = list()
for i in qword_4430:
    tmp = i ^ 0x6969696969
    res.append(tmp)

print([hex(elem) for elem in res])
```

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2062.png)

위와 같습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2063.png)

do-while 문을 돌면서 PML4 구조의 자료구조를 만들어서 VirtualAlloc들의 물리 주소를 저장합니다.

`qword_4430`은 그에 대응하는 가상 주소가 되겠습니다.

여기서 만든 PML4 자료구조를 전역 변수에 저장하고 OutBuffer에 0x1337을 내뱉게 됩니다.

(정확히는 Page Directory Pointer Table로 PML4에서 4개의 레벨 중 최상위 레벨을 제외한 자료구조입니다)

현재 이 `DeviceIoControl`을 호출하는 프로세스는 BrownFlagChecker의 child process입니다. 여기서 PML4 Table에 추가한 Virtual Address들은 `qword_4430`에 0x6969696969를 xor한 값이 사용되며,

Physical Address는 parent process에서 VirtualAlloc 후 전달했던 주소에 대응하는 물리 주소입니다.

즉, 해당 `DeviceIoControl`에서는 parent에서 VirtualAlloc으로 할당하고 초기화 했던 메모리를 child에서도 접근할 수 있도록 Page Table에 해당 메모리 공간들을 추가하는 작업이라고 볼 수 있겠습니다.

### 7. Case 0x224010

이 케이스는 child process에서 호출됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2064.png)

위 함수에서 호출되며 OutBuffer를 반환하게 됩니다.

해당 `DeviceIO_case10`함수의 경우

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2065.png)

child process에서 AES 루틴을 수행하는 과정 중에 진행됩니다.

비트 연산을 보아 하면 페이징과 관련된 연산을 수행할 것으로 추측되기도 합니다.

드라이버에서는 case 0x22400c에서 만든 PML4 자료구조 쪽에서 반환하는 동작을 하지 않을까 싶습니다.

아래는 대응하는 드라이버의 코드입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2066.png)

if문에서 일단 검증을 수행하며, `byte_4598`의 경우 case 0x22400c에서 PML4 테이블을 만들었는지 여부를 표시하는 flag입니다.

`byte_4599`의 경우에는 case 0x224014와 같이 봐야 합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2067.png)

case 0x224010(이하 case 0x10)에서 작업 수행 후 해당 변수를 set하고 case 0x14에서 작업 수행 후 다시 0으로 만드는 형태로 되어 있습니다.

case 0x10에서 실질적으로 수행하는 동작은 `cr3`레지스터에 존재하는 실제 PML4의 주소와 case 0xc에서 만들었던 `DriverPML4` (PDPE)주소를 인자로 입력 받아 그 결과를 `qword_4420`에 기록하고 반환하게 됩니다.

sub_1B74의 세부 코드는 다음과 같습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2068.png)

PML4에서 비어 있는 곳들의 idx를 `v9` 배열에 기록해 둔 뒤, `__rdtsc()`로 비어 있는 곳 중 유사 랜덤한 곳에 case 0xC에서 만들었던 PDPE를 넣게 됩니다.

해당 함수의 반환값은 PDPE를 넣은 index를 반환하게 되며

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2069.png)

그 반환값을 그대로 OutBuffer에 적재하게 됩니다.

그렇다면 이 OutBuffer 값이 child process에서 어떻게 사용되는지를 잠깐 살펴 보면

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2070.png)

이렇게 39비트 left shift를 수행하는 것을 볼 수 있는데

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2071.png)

PML4 Table의 Offset이 Virtual Address에서 39~47번째 비트 수가 되므로,

Virtual Address를 만들려는 동작으로 보입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2072.png)

그 뒤에는 qword 전역 변수에 저장된 값을 기반으로 Virtual Address에 접근하는 모습입니다.

해당 값들을 `v1`에 복사합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2073.png)

해당 Virtual Address를 살펴보면 Parent Process에서 Virtual Alloc 했던 메모리 주소라는 것을 눈치챌 수 있습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2074.png)

즉, Parent Process에서 할당하고 초기화한 메모리를 그대로 Child process에 가져와서 해당 메모리의 값들을 AES 루틴에 사용하고 있는 것을 알 수 있습니다.

### 8. Case 0x224014

child process에서 호출하는 case 0x14의 경우 case 0x10과 세트처럼 보입니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2075.png)

이에 대응하는 Driver의 코드를 봐도

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2076.png)

case 0x10에서 `byte_4599`를 set하고 case 0x14에서는 `byte_4599`를 unset하는 모습을 볼 수 있습니다.

case 0x14는 핵심 루틴이 `sub_1880`으로 보입니다만, case 0x10에서 반환 값에 해당했던 전역 변수 qword_4420을 유효하지 않은 값(-1)으로 만드는 것을 보아 하니, case 0x10에서 PML4 Table에 case 0xC에서 만들었던 PDPE를 넣은 루틴을 역으로 빼는 루틴으로 생각됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2077.png)

실제로도 그러고 있습니당 ㅎㅎ

---

## Control Flow 정리

유저 프로세스와 드라이버 간의 통신 및 드라이버의 동작을 도식화 하면 아래와 같습니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2078.png)

Parent에서 초기화 및 입력을 받은 후 해당 가상 주소를 Driver에게 전달하고 Driver는 Child에서도 해당 메모리 공간에 접근할 수 있도록 Child의 PML4 Table에 PDPE를 만들어 삽입하게 됩니다.

그리고 Child에는 해당 메모리 주소에 접근하여 AES Encryption 및 memcmp를 진행하여 그 결과를 Context(Rax)에 담은 채로 Floating Point Exception을 일으켜 Parent에게 검증 결과를 전달하게 됩니다.

---

## 역산

역산을 수행하기 위해서는 미뤘던 child process의 AES 루틴을 분석해야 합니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2079.png)

이렇게 하나의 AES Encryption 단위입니다.

평문이 64바이트였으므로 총 4 round AES를 진행합니다.

해당 루틴이 AES Encryption이라는 것을 알아채기 위해 모든 루틴을 분석한 것은 아니며, 특징이 되는 몇 가지 부분을 보고 알아차렸습니다.

**Key Expansion**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2080.png)

먼저, 106 line Key_Expansion으로 rename 해 놓은 함수를 보면 16byte input으로 176byte의 아웃풋을 내는 함수입니다. Key Expansion이 정확히 이런 루틴으로 진행이 됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2081.png)

함수 내부에서도 44 word의 subkey를 생성합니다.

**Add Round Key**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2082.png)

119 line을 보면 변수 명이 rename 되지 않아서 직관적으로 보이지는 않지만, IV와 평문을 xor하는 작업입니다.

**S-Box & inverse S-Box**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2083.png)

데이터 영역에 S-Box들이 존재하며 이는 실제로 Key Expansion 및 AES round에서 사용됩니다.

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2084.png)

해당 S-Box와 inverse S-box는 AES의 것과 완전히 일치하는 모습입니다.

**CBC Mode**

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2085.png)

v7을 잘 보시면 이 부분이 IV 역할을 하는 버퍼였습니다.

AES 한 라운드의 결과로 나온 ciphertext를 다시 다음 라운드의 IV로 넣는 것을 보아 CBC 운영 모드를 사용하는 AES Encryption이라고 판단하였습니다.

전체 로직을 살펴보면 평문 64byte를 받아 key와 IV를 바꿔 가면서 9번의 AES Encryption을 수행합니다.

이 AES Encryption에 들어가는 평문, key, IV와

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2086.png)

`memcmp`에서 비교하는 검증 값들은 모두 Parent Process에서 VirtualAlloc으로 Driver에 넘긴 값들이며 이 중 하나는 Input입니다. Driver에서는 이 값들을 Child Process의 PML4 Table에 추가하여 Child Process에서도 접근할 수 있도록 되어 있습니다.

이는 Case 0x8, 0xC, 0x10, 0x14에서 분석한 바 있으며, child process에서 접근한 값들과 Parent Process에서 VirtualAlloc했던 값들을 매칭만 한다면 input을 구해낼 수 있을 것으로 보입니다.

parent의 초기화 루틴과 child에서 해당 값에 접근하는 루틴들이 모두 하드 코딩되어 있어서 저도 수동으로 매칭 과정을 수행하였습니다.

```python
VirtualAlloc_data = [
    0xDC210535BDD023D48AFB11A578FCD4BC,
    0x58F856B4F8527349E78D138DB367D69E,
    0xED2AEC858432CBDA743C8DE8A33CA7FB,
    0xDF6972C6B678902BFA2739E055FA316E,
    0x4E633E05131CD3D7CA75CF3445AABDBB,
    0x33C6961AB2EE2A996F70DA247BE73A60,
    0xF442634BB21171D92F3F2F6B0E2C2971,
    0xD030A86EF4D7B1A32FE5031F3E86DDCB,
    0x8F1D2D089D8BC5AAF384FCD85ACBAED9,
    0xDC020011FA742CE7216BE9B25A5CD1F5,
    0xD961CAD38A5367A77A4A05E784D1442E,
    0x599E6639E08B13C4CC794C6972B918F5,
    0x89670963F5E76E96AA74BB49EF4D74CF,
    0x349E61B0419CBDA3F60CE24760B05001,
    0xF8F8FC36C3098E3C141CAB9F61BB9E69,
    0x3D2BBC03F0CA149C8D5336E9706349E4,
    0x8B57C2CCF83A9C1FF8DDC87B44A1AFEF,
    0x6F52BEFD9BAD8EA6AF8D47264DA85E72,
    0x5853F5C71545EC5C949B63D730B34E62,
    0xE05B4F3578DB067808BBFD8A1CFA57EC3DE4072B66FC9B088A2AB2052AB2865FF346918E4D084196AA6B5972E391D305E27745436A19ECC1C7AE2A1D42F142E2
]
```

이렇게 Parent 초기화 과정의 순서대로 값들을 뽑고

```python
decrypt_key_idx = [
    17,
    10,
    7,
    3,
    5,
    14,
    12,
    11,
    8
]

decrypt_IV_idx = [
    2,
    6,
    16,
    13,
    4,
    1,
    15,
    9,
    18
]
```

child에서는 접근 index를 뽑아냈습니다.

AES에서 key, iv, ciphertext(검증값) 모든 정보를 알고 있기 때문에,  역산이 가능합니다.

### Solver.py

```python
from Crypto.Cipher import AES

VirtualAlloc_data = [
    0xDC210535BDD023D48AFB11A578FCD4BC,
    0x58F856B4F8527349E78D138DB367D69E,
    0xED2AEC858432CBDA743C8DE8A33CA7FB,
    0xDF6972C6B678902BFA2739E055FA316E,
    0x4E633E05131CD3D7CA75CF3445AABDBB,
    0x33C6961AB2EE2A996F70DA247BE73A60,
    0xF442634BB21171D92F3F2F6B0E2C2971,
    0xD030A86EF4D7B1A32FE5031F3E86DDCB,
    0x8F1D2D089D8BC5AAF384FCD85ACBAED9,
    0xDC020011FA742CE7216BE9B25A5CD1F5,
    0xD961CAD38A5367A77A4A05E784D1442E,
    0x599E6639E08B13C4CC794C6972B918F5,
    0x89670963F5E76E96AA74BB49EF4D74CF,
    0x349E61B0419CBDA3F60CE24760B05001,
    0xF8F8FC36C3098E3C141CAB9F61BB9E69,
    0x3D2BBC03F0CA149C8D5336E9706349E4,
    0x8B57C2CCF83A9C1FF8DDC87B44A1AFEF,
    0x6F52BEFD9BAD8EA6AF8D47264DA85E72,
    0x5853F5C71545EC5C949B63D730B34E62,
    0xE05B4F3578DB067808BBFD8A1CFA57EC3DE4072B66FC9B088A2AB2052AB2865FF346918E4D084196AA6B5972E391D305E27745436A19ECC1C7AE2A1D42F142E2
]

decrypt_key_idx = [
    17,
    10,
    7,
    3,
    5,
    14,
    12,
    11,
    8
]

decrypt_IV_idx = [
    2,
    6,
    16,
    13,
    4,
    1,
    15,
    9,
    18
]

def AES_decryptor(ciphertext, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, IV)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

ciphertext = VirtualAlloc_data[19].to_bytes(64, "little")

for i in range(len(decrypt_key_idx)):
    key = VirtualAlloc_data[decrypt_key_idx[i]].to_bytes(16, "little")
    IV = VirtualAlloc_data[decrypt_IV_idx[i]].to_bytes(16, "little")
    plaintext = AES_decryptor(ciphertext, key, IV)
    ciphertext = plaintext

print(plaintext)
```

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2087.png)

input으로 넣어 보면?

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2088.png)

`:(`

블루 스크린은 선 넘네

```powershell
C:\chal>.\BrownFlagChecker.exe
Welcome! Give me the key and I will give you the flag: H4VIn9_7Hi5_KEY_ME4n5_you_4rE_che47In9_ON_me_7f6301e1920cb86cf8e
Correct. Here is your flag
Flag: LINECTF{72f9fc0fdf5129a4930286e5b9794e10}
```

원래는 위와 같이 출력 되어야 정상이라고 합니다. 어쨋든 답은 맞게 잘 구한 것으로..

---

## Bypass Anti-Debug: DBVM

[https://core-research-team.github.io/2020-10-01/Cheat-Engine-DBVM-8b5aa7dc092c4dd2b81b7d4696266309](https://core-research-team.github.io/2020-10-01/Cheat-Engine-DBVM-8b5aa7dc092c4dd2b81b7d4696266309)

이거 보고 따라 해볼 예정이긴 한데

![Untitled](/CTF/LineCTF/BrownFlagChecker/Untitled%2089.png)

이것부터 해결해야 할 듯

---

## Reference

[https://campkim.tistory.com/52](https://campkim.tistory.com/52)

[https://blog.naver.com/wnrjsxo/221711255389](https://blog.naver.com/wnrjsxo/221711255389)
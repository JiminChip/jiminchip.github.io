---
layout: post
title: 직접 만드는 PE Parser
date: December 4, 2024
categories: Anti-Cheat
comment: true
---

**상위 포스트 -** [PE File Format](/Anti-Cheat/Window_Reversing/PE/PE)

---

**Index**

[Source Code](#source-code)

[Code 해석](#code-해석)

---

## Source Code

x86 버전의 PE Parser이다.

```c
#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

int main(void)
{
    /*TODO: 본인 가상머신에 탑재된 x86 PE 파일의 경로로 대체하기*/
    wchar_t path_pefile[] = L"C:\\Users\\jjm40\\OneDrive\\바탕 화면\\Reversing-Tools\\release\\x32\\x32dbg.exe";

    HANDLE hFile = NULL, hFileMap = NULL; /*Win32 API 호출 과정에서 사용되는 변수*/
    LPBYTE lpFileBase = NULL; /*메모리에 매핑된 파일 컨텐츠의 위치*/
    DWORD dwSize = 0; /*PE 파일 사이즈*/

    PIMAGE_DOS_HEADER pDosHeader = NULL; /*DOS 헤더 구조체의 포인터*/
    PIMAGE_NT_HEADERS pNtHeader = NULL; /*NT 헤더 구조체의 포인터*/

    hFile = CreateFileW(path_pefile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        /*실습 중 여기에 진입하게 된다면,
        * 콘솔에서 출력되는 에러 코드를 확인한 뒤 MSDN
        "https://learn.microsoft.com/ko-kr/windows/win32/debug/system-error-codes--0-499-"
        에서 에러 코드의 의미를 확인해 볼 것.*/
        printf("CreateFileA() failed. Error code=%lu\n", GetLastError());
        return GetLastError();
    }
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);
    /*lpFileBase 포인터는 OS에 의해 메모리에 로드된 PE 파일의 가장 첫 바이트를 가리킴*/
    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

    /*TODO: 여기서부터 코딩 시작*/
    printf("### SECTION INFORMATION ###\n");

    // Section Header의 주소 계산 Optional Header바로 뒤에 있기 때문에 [Optional Header 주소 + Optional Header Size] 로 계산할 수 있음
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (LPBYTE)(&pNtHeader->OptionalHeader)
        + (pNtHeader->FileHeader.SizeOfOptionalHeader)
    );

    // Section별로 주요 데이터 출력
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        printf("%d번째 section: %s\n", i + 1, pSectionHeader[i].Name);
        printf("PointerToRawData: %#x \n", pSectionHeader[i].PointerToRawData);
        printf("SizeOfRawData: %#x \n", pSectionHeader[i].SizeOfRawData);
        printf("VirtualAddress: %#x \n", pSectionHeader[i].VirtualAddress);
        printf("VirtualSize: %#x \n\n", pSectionHeader[i].Misc.VirtualSize);
    }

    // IAT 주소 계산
    
    PIMAGE_DATA_DIRECTORY pImportDataDirectory = (PIMAGE_DATA_DIRECTORY)(&(pNtHeader->OptionalHeader.DataDirectory[1]));
    printf("### IAT ###\n");
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].VirtualAddress <= pImportDataDirectory->VirtualAddress && pImportDataDirectory->VirtualAddress < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
            printf("IAT가 저장된 섹션: %s\n", pSectionHeader[i].Name);
            printf("RVA to RAW: %#x->%#x\n", pImportDataDirectory->VirtualAddress, pImportDataDirectory->VirtualAddress - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
            PIMAGE_IMPORT_DESCRIPTOR pIAT = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + pImportDataDirectory->VirtualAddress - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
            for (int j = 0; pIAT[j].Name != NULL; j++) {
                printf("ImportDescriptor[%d].Name=%s\n", j, lpFileBase + pIAT[j].Name - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                PIMAGE_THUNK_DATA pOriginFirstThunk = (PIMAGE_THUNK_DATA)(lpFileBase + pIAT[j].OriginalFirstThunk - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(lpFileBase + pIAT[j].FirstThunk - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                for (int k = 0; pFirstThunk[k].u1.Ordinal != NULL; k++) {
                    printf("  - function name (RVA=%#x), %s\n", pFirstThunk[k].u1.Ordinal, lpFileBase + pOriginFirstThunk[k].u1.Ordinal - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData + 2);
                }
            }
            break;
        }
    }

    /*Windows로부터 할당받은 리소스를 역순으로 반환*/
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    /*main() 함수가 끝까지 실행되었음을 알리기 위해 0을 반환*/
    return 0;
}
```

## Code 해석

27 line ~ 31 line

```c
    dwSize = GetFileSize(hFile, 0);
    printf("File size=%lu bytes\n\n", dwSize);

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		lpFileBase = (LPBYTE)MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwSize);
```

FileSize는 GetFileSize를 호출하면서 쉽게 구하고 있습니다.

그 뒤에 CreateFileMapping을 호출하여 해당 파일을 메모리에 메핑합니다.

lpFileBase를 위와 같이 설정해 주면 앞으로 lpFileBase로 메핑된 영역에 접근할 수 있게 됩니다.

lpFileBase부터 windows.h에 정의된 구조체를 하나씩 씌우면서 PE 파일을 파싱해 주면 됩니다.

33 line ~ 43 line

```c
    printf("File signature=%c%c\n", lpFileBase[0], lpFileBase[1]);

    pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    printf("Offset to the NT header=%#x\n\n", pDosHeader->e_lfanew);

    pNtHeader = (PIMAGE_NT_HEADERS)(lpFileBase + pDosHeader->e_lfanew);
    printf("OptionalHeader.BaseOfCode=%#x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("OptionalHeader.SizeOfCode=%#x\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("OptionalHeader.AddressOfEntryPoint=%#x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("OptionalHeader.BaseOfData=%#x\n", pNtHeader->OptionalHeader.BaseOfData);
    printf("OptionalHeader.ImageBase=%#x\n\n", pNtHeader->OptionalHeader.ImageBase);

```

제일 먼저 시그니처 값을 출력합니다. PE파일이라면 ‘MZ’라는 시그니처 값이 출력되어야 합니다.

이후 OptionalHeader에 존재하는  BaseOfCode, SizeOfCode, AddressOfEntryPoint, BaseOfData, ImageBase 값들을 출력해 줍니다.

44 line ~ 62 line

```c
    /*TODO: 여기서부터 코딩 시작*/
    printf("### SECTION INFORMATION ###\n");

    // Section Header의 주소 계산 Optional Header바로 뒤에 있기 때문에 [Optional Header 주소 + Optional Header Size] 로 계산할 수 있음
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(
        (LPBYTE)(&pNtHeader->OptionalHeader)
        + (pNtHeader->FileHeader.SizeOfOptionalHeader)
    );

    // Section별로 주요 데이터 출력
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        printf("%d번째 section: %s\n", i + 1, pSectionHeader[i].Name);
        printf("PointerToRawData: %#x \n", pSectionHeader[i].PointerToRawData);
        printf("SizeOfRawData: %#x \n", pSectionHeader[i].SizeOfRawData);
        printf("VirtualAddress: %#x \n", pSectionHeader[i].VirtualAddress);
        printf("VirtualSize: %#x \n\n", pSectionHeader[i].Misc.VirtualSize);
    }

```

여기는 섹션 별로 주요한 데이터를 출력하는 코드입니다. 3/27일날 교수님께서 해당 부분의 예시코드를 올려 주셨고 그대로 사용하였습니다.

먼저 Section 헤더에 접근하기 위해서는 주소를 계산해야 합니다. 섹션 해더는 Optional Header에 바로 붙어 있기 때문에, Optional Header의 시작 주소에 Optional Header의 크기를 더해주면 Section Header의 주소를 얻을 수 있습니다.

그 뒤로는 For문으로 Section Header를 순회하면서 Section Header에 존재하는 주요한 데이터들(Name, PointerToRawData, SizeOfRawData, VirtualAddress, VirtualSize)을 출력합니다.

**IAT 부분 출력**

이제부터는 제가 손수 코딩한 부분들입니다.

여기서는 IAT가 어느 섹션에 저장되어 있는지, dll들의 이름을 출력해주면서 해당 dll에서 사용되는 함수들의 목록까지 출력해야 합니다.

```c
    // IAT 주소 계산
    
    PIMAGE_DATA_DIRECTORY pImportDataDirectory = (PIMAGE_DATA_DIRECTORY)(&(pNtHeader->OptionalHeader.DataDirectory[1]));
    printf("### IAT ###\n");
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].VirtualAddress <= pImportDataDirectory->VirtualAddress && pImportDataDirectory->VirtualAddress < pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
            printf("IAT가 저장된 섹션: %s\n", pSectionHeader[i].Name);
            printf("RVA to RAW: %#x->%#x\n", pImportDataDirectory->VirtualAddress, pImportDataDirectory->VirtualAddress - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
            PIMAGE_IMPORT_DESCRIPTOR pIAT = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + pImportDataDirectory->VirtualAddress - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
            for (int j = 0; pIAT[j].Name != NULL; j++) {
                printf("ImportDescriptor[%d].Name=%s\n", j, lpFileBase + pIAT[j].Name - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                PIMAGE_THUNK_DATA pOriginFirstThunk = (PIMAGE_THUNK_DATA)(lpFileBase + pIAT[j].OriginalFirstThunk - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(lpFileBase + pIAT[j].FirstThunk - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
                for (int k = 0; pFirstThunk[k].u1.Ordinal != NULL; k++) {
                    printf("  - function name (RVA=%#x), %s\n", pFirstThunk[k].u1.Ordinal, lpFileBase + pOriginFirstThunk[k].u1.Ordinal - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData + 2);
                }
            }
            break;
        }
    }
```

먼저 IAT의 위치를 찾기 위해서, Section 헤더를 순회하면서 ImportDataDirectory의 Virtual Address가 해당 Section의 Virtual Address 범위 내에 속해 있는지를 검증해보면 어느 섹션에 IAT가 존재하는지 찾을 수 있습니다.

RVA to RAW는 공식을 적용시켜 구할 수 있습니다. `RAW = RVA - VirtualAddress + PointerToRawData`

이제 어느 섹션인지 찾았기 때문에, [RVA to RAW]를 이용해 IAT의 RAW주소도 구할 수 있습니다. 그러면 이제 lpFileBase에 RAW주소를 더해주면 IAT에 접근할 수 있습니다.

IAT 주소를 구하면 이제부터 IAT를 순회하면서 필요한 작업들을 수행합니다.

IAT의 Name이 Null이 될때까지 순회하면 모두 순회할 수 있습니다.

순회하면서 dll의 이름인 Name변수를 출력해주고, 그 다음에는 해당 dll에서 사용되는 함수 목록들과 RVA 출력해야 하는데, 이는 OriginFirstThunk와 FirstThunk에 저장되어 있습니다.

두 영역 다 헤더에 적힌 가상 주소를 RAW주소로 변환해주면 lpFileBase로부터 접근할 수 있습니다.

RVA는 FirstThunk의 값을 그대로 출력해주면 되고, function name은 OriginFirstThunk에 적힌 주소에 존재합니다. 여기에 적힌 주소도 RVA이므로 이를 다시 RAW로 변환해 주면 function name 문자열의 주소를 얻을 수 있습니다.

![Untitled](Untitled.png)

그렇지만, 앞에 2바이트 널이 삽입되어 있기 때문에 해당 주소에 2를 더해주면 문자열을 출력할 수 있습니다.

![Untitled](Untitled%201.png)

abex_crackme1.exe를 파싱한 결과입니다.

![Untitled](Untitled%202.png)

![Untitled](Untitled%203.png)

그 다음은 x32dbg를 파싱해 보았습니다.
---
layout: post
title: Stealer
date: September 11, 2024
categories: CTF
comment: true
---
**상위 포스트 -** [BlackHatMEA 2024](/2024-09/BlackHatMEA_2024)


C#으로 작성된 것으로 보이며, IDA에 넣으면 어셈블리가 아닌 IR 언어가 나옵니다.

`dnSpy`라는 툴을 사용하면 디컴파일 및 디버깅이 가능합니다.

문제 설명에 실제 악성 코드라고 소개되어 있으며, 분석 결과 실제 악성 행위를 수행합니다.

핵심 루틴은 다음과 같습니다.

<aside>
<img src="https://www.notion.so/icons/key-antique_gray.svg" alt="https://www.notion.so/icons/key-antique_gray.svg" width="40px" />

1. 시간 검증: 2024-07-31 이후면 프로그램 종료 및 삭제
2. 메일이나 브라우저 관련 프로세스 모두 종료
3. 브라우저나 메일 프로그램들의 Login Data 같은 것들을 긁어옴
4. 긁어온 뒤에 데이터 전송
    - FTP, SMTP, Telegram Bot 세 가지 중 하나로 전송 가능
    - ProtectedMode로 설정하면 데이터 암호화해서 전송
    - 뭘로 보내든 전송하고 나서 response 따위는 받지 않음
</aside>

바이너리의 동작을 살펴 봤을 때 아무리 봐도 flag가 나올 만한 시나리오가 안 나와서 삽질을 좀 했습니다.

telegram bot한테 전송할 때 Session ID 같은 문자열이 있었는데, 해당 문자열을 Base64 디코딩하니 플래그가 나왔습니다. 어이가 없어서 하하…

사실 이것도 제가 발견한 건 아니기 때문에, 라업을 쓴 목적은 따로 있습니다.

---

[https://medium.com/@0xMr_Robot/blackhat-mea-quals-ctf-2024-reverse-challenges-0ae61ddf324c](https://medium.com/@0xMr_Robot/blackhat-mea-quals-ctf-2024-reverse-challenges-0ae61ddf324c)

디코에 올라온 다른 풀이인데, 분석을 다 제끼고 푸신 분이 계셔서 가져와 봅니다.

풀이 과정을 요약하면 다음과 같습니다.

실제 악성코드라고 설명에 나와 있음 → `VirusTotal`에 해당 바이너리를 올림 → 네트워크 통신 등의 악성 행위들이 분석됨 → 네트워크 통신에서 나온 url을 CyberChef 돌림 → flag가 튀어 나옴
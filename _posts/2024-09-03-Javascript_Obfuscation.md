---
title: Javascript Obfuscation
categories: Tips-Reversing
comment: true
---

일반적으로 Javascript의 난독화는 아래의 오픈소스 툴을 가장 많이 사용한다.

[JavaScript Obfuscator Tool](https://obfuscator.io/)

오픈 소스이기 때문에 deobfuscator 또한 존재한다.

[JavaScript Deobfuscator](https://deobfuscate.io/)

이런 것도 있음

[Online JavaScript beautifier](https://beautifier.io/)

Javascript의 난독화는 일반적으로 바이너리에서처럼 low level에서 난독화하고 그러지는 않는다. 그래서 Javascript에 대한 깊은 지식을 요구하지는 않고 상식적인 수준의 난독화가 이루어진다.

주된 원리를 알아보자.

Compact: 한 줄로 합치는 기능이다. 당연히 한 줄로 합쳐져 있으면 알아보기가 매우 힘들다.

String Array: 문자열을 배열로 대체한다. 직관적으로 문자열이 사용된지 알아보기 힘들게 하고 어느 문자열이 사용되는지 찾는데 시간이 소요되게끔 한다. 바이너리에서 문자열을 암호화해서 사용하는 것과 비슷한 원리라고 보면 될 것 같다. String Array 내부에서도 여러 가지 옵션이 존재한다. 자세히는 몰름

Dead Code Injection: 실제로는 실행되지 않는 더미 코드들을 삽입한다.

Control Flow Flattening: 일반적인 Control Flow Flattening이다. 이렇게 바꾸면 코드의 길이가 많이 늘어나고 정리되지 않은 느낌을 준다.

Rename: 함수명이나 변수 명을 지우고 특색 없는 이름으로 바꾼다. 일반적으로 `_0x[0-9a-f]` 형태로 바뀐다. 일반적인 strip 옵션과 유사.

이것 외에 Javascript의 난독화에서 볼 수 있는 특수한 난독화도 몇 개 있다.

Domain Lock: 특정 도메인에서만 실행이 가능하게끔 하는 방식, 무지성 코드 복붙을 방지 가능

Debug Protection:  개발자 도구에서 디버깅이 못하게 한다.

Disable Output: console.log() 형태로 디버깅을 많이 하는 Javascript 특성 상, 이러한 방식의 로그 출력을 막아 분석을 어렵게 한다.
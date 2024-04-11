---
title: C rand() in Python
categories: Tips-Reversing
comment: true
---

### 개요

rand() 함수는 seed를 통해 난수를 생성해내는 난수 생성기입니다. 하지만, rand()함수를 값을 예측하지 못하도록 하는 의도로써 사용되는 경우에 취약점이 발생합니다. seed를 숨기지 못하면 rand()로 생성된 모든 난수 값이 유출되게 됩니다. 동일한 rand함수를 동일한 seed로 사용하면 모든 값들을 알아낼 수 있죠.

이 때, 보통 python에서 익스코드를 작성할 때 C의 rand()함수를 어떻게 사용하냐는 문제가 있는데, 이를 위해 python에서는 ctypes라는 모듈을 제공합니다.

파이썬 내장 함수이기 때문에, 별도의 설치 없이 사용할 수 있습니다.

```python
from ctypes import *
```

모듈 import 후 libc를 설정해주고 메소드 함수로 libc의 함수들을 동일하게 실행시킬 수 있습니다.

```python
#OS 혹은 library에 따라 rand함수의 작동이 달라질 수 있기 때문에 library를 제대로 가져오도록 합시다

#linux의 경우에 libc.so.6을 libc로 가져오면 됩니다.
libc = CDLL('libc.so.6')

#Window의 경우에는 
libc = CDLL('msvcrt')

#library 경로를 정확하게 입력해야 할 경우에 shell에서 (Powershell or Terminal) ldd 명령어로 확인 가능
```

이후 메소드 형태로 libc 내부의 함수를 사용할 수 있습니다.

```python
from ctypes import *

libc = CDLL('libc.so.6')

# srand로 seed 설정
libc.srand(0)

# rand함
for i in range(10000):
	print(libc.rand())
```
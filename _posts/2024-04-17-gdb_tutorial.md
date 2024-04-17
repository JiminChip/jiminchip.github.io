---
title: gdb 사용법
categories: Tips-Reversing
comment: true
---

Linux에서 사용되는 디버깅 툴. gdb는 리버싱 뿐만 아니라 시스템 해킹에서 굉장히 유용하게 사용되는 툴.

개인적으로 리버싱에서는 IDA에서 remote 디버깅을 하는 것을 더욱 선호하지만, 포너블에서는 gdb가 훨씬 편한 듯 해요.

---

**다운로드**

```bash
sudo apt-get install gdb -y
```

만약 작동하지 않는다면,

```bash
sudo apt-get update
sudo apt-get upgrade
```

위의 명령어를 실행. 보통 `apt`나 `apt-get` 기반 명령어가 잘 작동하지 않으면 가장 먼저 시도해보는 메뉴얼입니다. 그래도 잘 작동하지 않으면 노트북을 오래 켜 둬서 그럴 수 있으니 재부팅 시 다시 시도. 그래도 잘 안된다면 에러 메세지 구글링하면 보통 나와요. 아니면 chat-gpt 형님께 에러 메시지 갖다 드리면 트러블 슈팅 매우 잘해주심니다. 이래도 안되면 갠톡 넣어주세요.

---

이 gdb가 기본 gdb는 좀 많이 구립니다. 편리한 기능들이 많이 빠져 있고, 출력물이 밋밋하고 이쁘지도 않고 가독성도 좀 안 좋아요. 그래서 개편된 버전의 gdb를 많이 사용합니다.

현재 가장 많이 쓰이는 gdb는 gdb-gef이며, gdb-peda도 많이 쓰입니다. 저는 gdb-gef 사용하고 있어서 gdb-gef 기준으로 설명을 드릴건데, peda도 명령어 및 사용법이 거의 유사합니다.

**다운로드**

gdb-gef: [https://github.com/hugsy/gef](https://github.com/hugsy/gef)

gdb-peda: [https://github.com/longld/peda](https://github.com/longld/peda)

어차피 두 개 다 터미널(쉘)에서 명령어 쳐야 해서 명령어도 올려드릴께요

**gdb-gef**

```bash
# via the install script
## using curl
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

## using wget
$ bash -c "$(wget https://gef.blah.cat/sh -O -)"

# or manually
$ wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# or alternatively from inside gdb directly
$ gdb -q
(gdb) pi import urllib.request as u, tempfile as t; g=t.NamedTemporaryFile(suffix='-gef.py'); open(g.name, 'wb+').write(u.urlopen('https://tinyurl.com/gef-main').read()); gdb.execute('source %s' % g.name)
```

4개 방법 중 하나 하시면 되는데, curl은 안 깔려 있을 수도 있어서 2번째나 3번째 방법은 아마 되실 거에요. 근데 curl도 깔아 두면 좋아서

```bash
sudo apt update
sudo apt upgrade
sudo apt install curl
```

위에 거 치시면 curl 설치 되실 겁니다.

**gdb-peda**

```bash
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```

peda의 경우에는 위에 명령어 3줄 치시면 됨니다.

---

### 기능 설명

```bash
gdb [binary path]
```

위 명령어로 원하는 실행 파일을 gdb로 열 수 있습니다. 과제 중 하나인 `game with no rule description` 의 `game` 바이너리를 이용해 실습하겠습니다.

실습 파일

[game with no rule description.zip](/HackingTips/Reversing/gdb_tutorial/game_with_no_rule_description.zip)



![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled.png)

gdb 실행 화면입니다.

디버깅의 주요 기능은 breakpoint를 설정하고 프로그램의 원하는 지점에서 실행을 멈춘 상태로 레지스터나 메모리 등을 보는 기능입니다. 그리고 디스어셈블 기능을 지원합니다.

**디스어셈블하기**

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%201.png)

`disas <함수명>` 명령어로 원하는 함수를 디스어셈블 할 수 있습니다.

gef의 경우에 위의 사진처럼 이쁘게 색깔을 칠해줍니다.

만약 peda에서 색깔이 안입혀진다면 `pdisas <함수명>` (줄여서 `pd <함수명>` 도 가능) 명령어를 수행해 보시면 peda에서도 색깔이 입혀집니다.

함수 말고 특정 주소에 있는 명령어를 디스어셈블 하고 싶다면

`x/i <원하는 주소>` 를 이용할 수 있습니다. 이 때 `x/10i <원하는 주소>` 이런 식으로 숫자를 넣어주면 10줄의 어셈블리를 뽑아 줍니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%202.png)

여기서 주의해야 할 부분이 있는데, 실행 전과 실행 후의 주소가 달라질 수 있습니다. 지금은 main함수의 주소가 0x1289였죠?? 실행 시키고 나면 달라질 겁니다. 이거는 실행하는 방법을 조금 알아본 뒤 시도해봅시다.

**실행하기**

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%203.png)

`run` 명령어를 통해 실행할 수 있습니다. `run <main함수 인자>` 형태로 넣으면 main함수 인자(명령줄 인자)를 넣을 수 있습니다.

`run <<< [input]` 의 형태로 함수의 입력을 미리 줄 수 있습니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%204.png)

이렇게 input: 뒤에 입력을 넣지 않았는데도 입력이 넣은 것으로 취급이 됩니다. 이 기능은 수동으로는 자주 사용되지는 않고 나중에 gdb 디버깅을 자동화시킬 수 있는 gdb script에서 유용한 기능 중 하나가 됩니다.

**중단점 설정**

이렇게 실행만 하면… 디버거를 이용하는 의미가 없죠?? 원하는 곳에 실행 흐름을 멈춰두기 위해서 중단점을 설정합니다.

`b* <멈추고 싶은 주소>` 형태로 사용하실 수 있습니다. 띄워 쓰기는 상관없습니다. 아까 main함수 시작 주소가 0x1289였으니 여기다가 중단점을 걸고 실행해 보겠습니다. `b*<함수명>` 으로도 작동합니다. 혹은 `b*<함수명>+offset` 으로도 작동합니다. main함수에서 109만큼 떨어진 주소에 bp를 걸고 싶다면 `b*main+109` 이런 식으로 넣으면 됩니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%205.png)

이렇게 중단점(브포, bp라고도 자주 부릅니다)을 걸어 두고

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%206.png)

`info b` 줄여서 `i f` 만 해도 됩니다. 이렇게 breakpoint를 검색해보면 이렇게 걸려 있는 것을 확인할 수 있습니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%207.png)

하지만…. 실행이 이상하게 잘 안되는데요…?? 무슨 일이죠…??!!!

이 원인을 이해하려면 몇 가지 설명이 필요합니다. 일단 잘못 설정한 중단점은 `d <중단점 Num>` 으로 지울 수 있습니다. 지금 `i b`에서 보이는 중단점 Num은 1이니 `d 1` 로 1번 중단점을 삭제합시다. `d` 만 입력하면 모든 중단점을 한 번에 지울 수 있습니다.

먼저 entry point에 진입하는 방법입니다. `start` 명령어를 치면 gdb가 entry point에 중단점을 자동으로 걸어주고 entry point에 진입합니다. main에 중단점이 걸리는 경우도 종종 있습니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%208.png)

`start` 수행 시에 이렇게 메인 함수에 멈춘 것을 확인할 수 있습니다.

peda에서 위 명령어가 작동하지 않을 시에 `entry` 혹은 `starti` 명령어를 쳐보세요.

자 여기서 main 함수의 시작 주소를 확인해 볼까요??

아까처럼 `disas main` 을 해도 main함수의 주소를 확인할 수 있지만,

`p <심볼명>` 으로 간단하게 검색 가능합니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%209.png)

심볼은 symbol로 디버깅에 필요한 정보들을 의미합니다. 간단하게 변수명 함수명 정도로 생각하면 편할 듯 합니다.

main 함수의 주소가 `0x555555555289` 로 설정되어 있습니다. 분명히 실행 전에는 `0x1289`였는데 말이죠…

이유를 설명드리자면, 실행 파일을 실행하면 RAM에 실행 파일이 로드 된다고 했죠??

로드 된다는 의미는 RAM에 실행파일이 적재된다는 의미인데, 여기서 이 실행 파일이 RAM의 `0x00000000` 주소에 적재되지 않습니다. `Image Base` 주소부터 적재되기 시작합니다.

`start` 명령어를 친 상태로 `vmmap` 명령어를 쳐봅시다 (실행 상태라면 언제라도 상관없습니다)

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2010.png)

`vmmap`은 메모리에 mapping된 영역을 보여줍니다. 그리고 메핑된 영역의 perm (권한) 상태도 보여줍니다. r, w, x 이렇게 3가지가 있는데 각각 read(읽기), write(쓰기), execute(실행) 권한을 의미합니다.

보시면 `0x555555554000 ~ 0x555555559000` 까지 `game` 실행파일이 적재되어 있습니다.

실행 전에는 `0x1289` 에 있던 메인함수 시작 주소가 실행 후에는 `0x555555555289` 에 있었죠…??

혹시 뭐가 보이시나요…??

game 실행파일이 RAM에 적재된 시작 주소인 `0x555555554000` 에 `0x1289` 를 더하면 `0x555555555289` 가 됩니다.

즉, 실행파일을 RAM에 로드할 때 `0x00000000` 주소가 아닌 ImageBase 주소부터 적재되기 시작하는데 ImageBase에다가 실행 전 주소를 더하면 실행 중의 주소가 됩니다.

대부분의 Linux, Window 바이너리는 실행 시에 실행 파일이 RAM에 무작위 주소에 메핑됩니다. 그렇기 때문에 실행 전에는 실행 이후의 주소를 미리 알 수가 없어서 ImageBase로부터의 offset으로 주소를 표현하게 됩니다.

```
💡 TMI
gdb에서 몇 번 실행해 봤더니… 무작위 주소에 메핑이 아닌 고정 주소에 메핑되는 것 같다구요….???
gdb는 디버깅 툴입니다. 디버깅할 때에 매번 실행할 때마다 다른 주소를 가지게 되면… 골치가 아프겠죠…?? 그래서 gdb는 매번 동일한 주소로 메핑해 줍니다. 고정 주소 메핑은 gdb의 기능인 것이지 실제 실행 환경에서 매번 동일한 주소로 메핑하지는 않습니다.

물론, 컴파일 할 때 저 메핑 주소를 고정시킨 채로 메핑하는 것이 가능합니다. 그럴 경우에는 gdb에서 실행 전 주소와 실행 중의 주소가 동일하게 표기됩니다. 위 옵션으로 컴파일할 경우 일반적으로 ImageBase가 `0x400000` 로 고정됩니다. 그래서 실행 전 주소가 `0x400000` 근방이라면 ImageBase가 고정되었다고 추측할 수 있습니다. 물론 확실하게 알 수 있는 방법이 있는데, 이후에 소개하겠습니다.
```

그러면 breakpoint를 어떻게 걸어야 할까요…??

`start`를 실행한 뒤 다시 주소를 검색해야 합니다. 특정 함수에 bp를 걸고 싶으면 `b*<함수 명>` 으로 주소 검색 후 `b*<함수 주소>` 이런 방식으로 하시면 되고,

제일 편하고 가장 잘 먹히는 방법은 IDA에서 Rebase 기능을 통해 ImageBase를 gdb와 동일하게 설정한 뒤 IDA에서 bp를 걸고 싶은 지점의 주소를 복사해와서 `b*<원하는주소>` 를 집어 넣으면 됩니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2011.png)

이렇게 하면 bp가 걸린 것을 확인할 수 있습니다. 그런데 아까 start로 이미 <main + 8>에 중단점이 걸려 있는 상황이기 때문에… main 시작 주소를 지나쳐버렸죠…??

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2012.png)

이번에는 박스로 표시한 `main+39`에 bp를 걸어 봅시다. `b*main+30`보다는 `0x5555555552b0` 주소를 복사해서 `b*0x5555555552b0`으로 bp를 거는 것을 추천드려요. 나중에 설명하겠지만, 함수명이 아닌 주소에 bp를 거는 것이 훨씬 강력합니다.

bp 걸린 지점으로 이동하고 싶으면 이제는 run이 아닌 `continue` 명령어를 쳐 주어야 합니다. `c` 로도 작동합니다. 지금은 실행 전이 아니라 실행 도중이기 때문에 `r` 명령어를 치면 처음부터 다시 실행하게 됩니다. 그렇기 때문에 `c` 명령어를 사용해야 합니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2013.png)

이렇게 중단점이 걸린 상태를 보실 수 있습니다.

이 쯤에서 중단점이 걸린 상태의 인터페이스를 살펴볼까요??

맨 위에는 `register` 들을 보여주고 있습니다. 각 레지스터별로 레지스터의 값들을 보여주고 있습니다.

레지스터는 명령어로도 확인이 가능합니다. `i r $<register 명>` 으로 확인이 가능합니다. 이것도 지금 당장 알 필요는 없지만 gdb script에서 자주 사용되기에 알아두면 편리합니다.

stack 칸에는 현재 함수가 차지하는 stack을 보여줍니다. rsp와 rbp가 각각 스택의 위와 아래를 가리키는 것을 보실 수 있습니다.

그 밑에는 현재 실행 중인 코드를 보여줍니다. `call`이나 `jmp` 문의 경우에는 위의 사진처럼 jmp할 곳의 코드를 미리 보여주기도 합니다.

arguments는 인자를 보여줍니다. puts를 실행하기 직전이기 때문에 puts의 인자를 미리 보여주고 있습니다. 근데 arguments (guessed)라고 되어 있죠..? guessed 추측됨이라고 적혀 있습니다. 즉 정확하지는 않다는 의미입니다. 실제로 puts는 인자가 하나인데… 두개를 보여주고 있죠??

```
💡 TMI
64bit의 경우 대부분 fastcall 형식의 calling convention을 사용합니다. fastcall의 경우에 함수 실행 전에는 인자를 완벽하게 예측할 수 없습니다. 함수 내부를 들여다 봐야지 제대로 예측할 수 있습니다. calling convention의 경우에는 pwnable에서 자세히 배울 기회가 있을겁니다. 그래도 궁금하시다면 구글링 or 갠톡 ㄱㄱ

(앵간하면… 구글링 먼저 해보고 갠톡해 주세요. 제가 바쁜 것도 없지는 않지만 스스로 정보를 습득하는 능력도 기르셔야 합니다… 해킹은 솔직히 구글링이 80%는 차지하는 것 같습니다. 해킹 뿐만 아니라 컴퓨터 관련 공부라 그런 것 같아요 ㅎㅎ)
```

다음 bp까지가 아니라 한 줄씩 실행하고 싶다면 `si` `ni` 두 개의 명령어를 사용할 수 있습니다.

`ni` 는 기본적으로 next instruction을 의미합니다. 현재 중단점이 가리키고 있는 명령어를 수행하고 다음 명령어에 중단점을 걸라는 의미인데요, `si` 는 step into를 의미합니다. 영어가… 조금 다르죠?

step into는 일반적으로 step over와 대비되는 용어인데 `ni`가 step over에 해당하고 `si` 가 step into에 해당합니다.

step into는 call 명령어에서 해당 함수 내부로 들어가라는 의미이고, step over는 call 명령어에서 해당 함수를 모두 실행하라는 의미가 됩니다.

그래서 위 상태에서 `ni`를 수행하면 아래 상태가 됩니다.

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2014.png)

이렇게 보면 `ni` (step over)가 조금 직관적으로 이해가 되시죠?

![Untitled](/HackingTips/Reversing/gdb_tutorial/Untitled%2015.png)

`si` 의 경우에는 함수 내부로 들어와 집니다.

```
💡 TMI
사실 위의 상태는 puts 함수로 내부로 들어온 상황은 아닙니다. 상세히 설명해 드리고 싶지만… 많은 내용들을 설명해야 하고 pwnable에서 배울 기회가 많으실테니 간단하게만 설명드리겠습니다.
puts는 라이브러리에 선언된 함수이죠?? 바이너리 내부에 선언된 함수가 아닙니다. 그렇기 때문에 당장은 puts 함수가 존재하는 주소를 모르는 상황입니다. puts는 RAM의 libc 영역에 존재합니다. libc 등의 라이브러리가 RAM 어디에 매핑되어 있는지 궁금하시다면 `vmmap`명령어를 수행해 보세요! 실습 바이너리에서는 libc와 ld 라이브러리가 매핑되어 있는 것을 확인하실 수 있습니다 ㅎㅎ
이 라이브러리도 일반적으로 랜덤하게 매핑되기 때문에 puts의 주소를 알아내는 과정이 필요합니다. 그렇기 때문에 libc 영역에 존재하는 puts의 주소를 알아낸 뒤에 실제 libc의 puts 함수 내부로 들어가게 됩니다.
현재 위의 상태에서는 puts의 주소를 알아내는 과정 중에 있다고 이해하시면 편할 것 같아요 ㅎㅎ
```

만약 함수를 잘못 들어왔다….?! 그러면 `finish` 명령어로 빠르게 탈출할 수 있습니다.

이 정도만 알면 중단점을 걸고 실행하는 것 정도는 어렵지 않게 할 수 있으리라 생각됩니다. 이제는 디버거의 다른 주요한 기능인 메모리에 적재된 값을 확인하는 방법을 알아봅시다.

**메모리 확인하기**

`x/b <주소>` : 주소에 있는 값 1byte 출력

`x/h <주소>` : 주소에 있는 값 2byte 출력

`x/w <주소>` : 주소에 있는 값 4byte 출력

`x/gx <주소>` : 주소에 있는 값 8byte 출력

`x/x <주소>` : 최근에 사용한 타입으로 출력. 최근에 사용한 타입이 없으면 4byte로 출력

값은 리틀엔디안으로 출력 되니 유의하도록 합시다.

`x/i <주소>` : 주소에 있는 명령어 출력

`x/s <주소>` : 주소에 있는 문자열 출력

`x/100b <주소>` , `x/50gx <주소>`  등등 사이에 숫자를 끼워 넣으면 그 숫자만큼 출력해줍니다.

예를 들어서 `x/100b <주소>` 의 경우 해당 주소에 있는 값부터 차례대로 100byte를 출력해 줍니다.

띄워 쓰기를 기준으로 구분됩니다. `x/100b` 했다고 해서 100byte가 리틀엔디안으로 출력되는 것은 아니고 리틀엔디안 단위는 띄워쓰기 단위로 되어 있습니다. x/h, x/w, x/gx도 마찬가지

레지스터 확인은 아까 했었죠??

`i r $rax` 

`i r $rip` 

등등으로 하면 됩니다. 64비트 여도 32비트나 16비트, 8비트 형식의 레지스터도 볼 수 있습니다.

`i r $eax` 등등 다 볼 수 있음

메모리 영역을 수정할 수도 있습니다.

`set` 명령어를 사용하면 됩니다.

`set *(자료형)<주소>`

`set $<레지스터>`

위 형태로 작성하면 됩니다.

예시:

`set $rax = 0` : rax 레지스터의 값을 0으로 설정

`set *(char *)0x400670 = 0x50` : 0x400670에 있는 1byte 값을 0x50으로 변경

이 정도면 기본적인 기능들은 거의 다 다룬 것 같습니다!
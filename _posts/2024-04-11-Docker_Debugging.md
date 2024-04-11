---
title: Docker Debugging (Remote debugging & patchelf)
categories: Tips-Pwnable
comment: true
---

CTF나 여러 해킹 문제들의 경우에 Dockerfile을 함께 제공하고 있습니다. 이는, 문제의 환경을 동일하게 제공하기 위함이며 Dockerfile을 빌드하여 실행하는 것으로 간단하게 문제 환경을 구현할 수 있습니다.

  하지만, 단순히 문제 환경을 동일하게 구현하는 것으로는 충분하지 않습니다. 문제를 해결하려면 디버깅 과정이 필수입니다. 이를 위하여 Docker 내부에 직접 들어가서 디버깅하는 방법도 존재하지만 여러모로 불편하기 때문에, Docker 바깥에서 본인의 환경에서 Docker 내부의 프로세스를 디버깅하는 방법을 알아보겠습니다.

[https://dreamhack.io/wargame/challenges/67](https://dreamhack.io/wargame/challenges/67)

드림핵 워게임 문제 tcache_dup2를 가지고 디버깅 환경을 구현해 보겠습니다.

먼저 Dockerfile을 살펴봅시다.

- Docker 기본 명령어
    
    ```
    #현재 디렉토리(.)에 있는 Dockerfile을 빌드
    sudo docker build .
    
    #빌드된 Docker image 확인
    sudo docker images
    
    #Docker 실행
    sudo docker run [image name]
    
    #실행되고 있는 Docker 확인
    sudo docker ps
    
    #정지된 contaner까지 포함하여 확인
    sudo docker ps -a
    
    #실행되고 있는 Docker Container 멈추기
    sudo docker stop [container ID]
    
    #실행되고 있는 Docker Container 강제로 멈추기
    sudo docker kill [container ID]
    
    #정지된 container 다시 실행
    sudo docker start [container ID]
    
    #container 삭제 (image 삭제와 다름)
    sudo docker rm [container ID]
    
    #image 삭제
    sudo docker rmi [image name]
    ```
    

**Dockerfile**

```docker
FROM ubuntu:19.10@sha256:f332c4057e21ec71cc8b20b05328d476104a069bfa6882877e0920e8140edcf0

ENV user tcache_dup2
ENV chall_port 31337

RUN sed -i s/archive.ubuntu.com/old-releases.ubuntu.com/g /etc/apt/sources.list
RUN sed -i s/security.ubuntu.com/old-releases.ubuntu.com/g /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y socat

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./$user /home/$user/$user

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD while :; do socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user ; done
```

마지막 줄 2개를 살펴보면

```docker
EXPOSE $chall_port
CMD while :; do socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user ; done
```

EXPOSE문으로 `$chall_port(31337)` 에 port를 열어 놓고 있습니다.

그리고, 마지막 줄에서 무한 루프를 통해 `socket`을 사용하여 지정된 포트에서 연결을 받고, 해당 연결을 사용자의 홈 디렉토리에 있는 `$user` 파일과 연결합니다.

`$user`파일은 문제 바이너리인 `tcache_dup2`입니다.

이 Docker의 31337 port에 접속하면 tcache_dup2 프로세스와 통신할 수 있게 됩니다. 이를 이용해 pwnable 문제를 해결하기 위해 pwntool로 익스코드를 작성할 때 해당 포트로 remote해주게 되면 로컬에서 익스코드를 테스트해볼 수 있습니다.

이 때, docker를 run할 때 -p옵션으로 localhost의 port와 도커의 port를 매핑할 수 있습니다.

위 예시에서는 docker의 31337 port를 chall_port로 사용하므로,

`sudo docker run -p 31337:31337 [container name]` 으로 localhost의 31337 port에 도커의 31337 port를 매핑할 수 있습니다.

그러면 pwntool에서 `remote("localhost", 31337)` 로 도커에서 실행중인 문제 프로세스에 접속할 수 있습니다.

**docker 실행**

![Untitled](/HackingTips/Pwnable/Docker%20Debugging/Untitled.png)

**익스 코드**

```python
from pwn import *

p = remote("localhost", 31337)
e = ELF("./tcache_dup2")
libc = ELF("./libc-2.30.so")

'''
Exploit Code
'''

p.interactive()
```

**익스 코드 실행**

![Untitled](/HackingTips/Pwnable/Docker%20Debugging/Untitled%201.png)

local에서 잘 작동하는 것을 확인할 수 있습니다.

여기서 gdb를 attach하는 것 또한 가능한데, pwntool코드에서 `gdb.attach(p)` 로는 안됩니다.

그래도, attach할 때 브레이크가 걸리도록 익스 코드에 pause()문을 추가해줍니다.

(이 때, remote로 접속한 이후에 pause를 걸어야 한다)

그리고 docker를 실행하고, pwntool을 실행합니다.

그 상태에서 다른 터미널에서 sudo ps -ef를 치면

![Untitled](/HackingTips/Pwnable/Docker%20Debugging/Untitled%202.png)

위 사진처럼 프로세스의 pid를 확인할 수 있습니다.

익스코드를 실행하여 해당 docker의 포트로 접속하면, docker에서 문제 바이너리를 실행시키게 되면서 저렇게 문제 프로세스의 pid가 뜨게 됩니다.

이 상태로 `sudo gdb -p [pid]` 를 입력해주면 gdb가 attach가 됩니다.

이후 bp를 걸고 디버깅을 진행하시면 됩니다.

- 추가적인 Docker 명령어 옵션
    
    ```
    #docker run할 때 같이 사용하면 좋은 옵션
    
    #docker에게 권한을 주는 명령어. 이게 없으면 docker 내부에서 ptrace가 안된다고 하던데..
    #저 옵션이 없어도 딱히 큰 차이는 모르겠다.
    sudo docker run --privileged [container name]
    
    #--cap-add=SYS_PTRACE의 경우에는 docker 내부에서 gdb 등으로 디버깅이 가능하도록 하는 옵션
    #근데, 지금 시도하는 것은 docker 외부에서 디버깅하는 거라 없어도 큰 차이는 없어 보인다.
    #--security-opt seccomp=unconfined
    #본래 docker 내부에서 seccomp로 syscall이 몇 가지 제한되어 있다고 한다. 그 제한을 풀어주는 옵션
    sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined [container name]
    
    #정리하면 다음과 같다
    sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -p [port number]:[port number] --privileged [container name]
    ```
    

### 위 방법이 통하지 않을 시

시도할 수 있는 여러 가지 방법이 있지만 가장 편리한 방법 중에 하나는, 도커 안에 있는 libc를 도커 밖으로 빼오는 것

이후 patchelf로 libc를 교체해주면 됩니다.

```
sudo docker cp [container name]:[file path] [dst path]

patchelf --set-interpreter ld ./binary
patchelf --replace-needed libc.so.6 ./libc ./binary
```
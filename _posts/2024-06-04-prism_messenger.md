---
title: prism_messenger - CodeGate 2024
categories: CTF
comment: true
---

## 목차
[Gathering Information](#gathering-information)

[&emsp;실행 (ssh 접속)](#실행-ssh-접속)

[&emsp;server (main.py)](#server-mainpy)

[&emsp;Validation TUI 분석 (삽질 1)](#validation-tui-분석-삽질-1)

[&emsp;Validation 통신 루틴 분석](#validation-통신-루틴-분석)

[Validation::genstring](#validationgenstring)

[Session ID to Password](#session-id-to-password)

[Gathering Information 2](#gathering-information-2)

[&emsp;Random to Source of password & session id](#random-to-source-of-password--session-id)

[&emsp;Captcha genstring](#captcha-genstring)

[Get Password](#get-password)

---

## Gathering Information

### 실행 (ssh 접속)

![Untitled](/CTF/Codegate%202024/prism_messenger//Untitled.png)

문제 서버에 접속을 하게 되면, Session ID가 제공됩니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%201.png)

`Enter`를 누르게 되면 위의 Login 창이 뜨게 됩니다.

여기서 Password와 Captcha를 정확히 입력하는 것이 문제의 목적이 될 것으로 생각됩니다.

### server (main.py)

```python
from pymongo import MongoClient, errors
from pymongo.collection import Collection
import urllib
import datetime
import os
import socketserver
import pathlib

SOCK_FILE_LOC = os.environ.get("SOCK_FILE_LOC", "/socket/chall.sock")

class DBManager:
    client: MongoClient = None

    def __init__(self):
        self.client = MongoClient(
            f'mongodb://{os.environ.get("DB_USER")}:{urllib.parse.quote(os.environ.get("DB_PW").encode())}@mongo:27017/admin?retryWrites=true&w=majority'
        )

    def add_session(self, session: dict):
        session["create_date"] = datetime.datetime.now(tz=datetime.timezone.utc)
        session["success_date"] = None
        session["flag"] = None
        
        db = self.client["sessions"]
        collection: Collection = db["sessions"]
        collection.insert_one(session)
    
    def check_session(self, session: dict):
        db = self.client["sessions"]
        collection: Collection = db["sessions"]
        result = collection.find_one({"session_id": session["session_id"], "password": session["password"]})
        if result is None:
            return "NOPE"
        
        with open("/flag", "rb") as f:
            flag = f.read()
        
        collection.update_one({"session_id": session["session_id"], "password": session["password"]}, 
                              {"$set": {"flag": flag.decode(), "success_date": datetime.datetime.now(tz=datetime.timezone.utc)}})
        return flag

class ServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        recv_raw_data = self.request.recv(1024).strip().decode()
        recv_data = recv_raw_data.split(",")
        send_data = b""
        try:
            print(recv_data)
            db = DBManager()
            session = {"password": recv_data[1].strip(), "session_id": recv_data[2].strip()}
            if recv_data[0] == "register":
                db.add_session(session)
                send_data = b"OK"
            elif recv_data[0] == "check":
                send_data = db.check_session(session)
        except Exception as e:
            send_data = b"Call Admin!"
            pass
        self.request.sendall(send_data)

class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    pass

if __name__ == "__main__":
    pathlib.Path(SOCK_FILE_LOC).unlink(missing_ok=True)
    with Server(SOCK_FILE_LOC, ServerHandler) as server:
        server.allow_reuse_addess = True
        print("Start Server...")
        server.serve_forever()
    

```

먼저 server를 보면, client와 세 가지 방법으로 통신하게 됩니다.

register, check, Call Admin 세 가지 케이스가 존재하며,

register 케이스에서 client가 Password, Session ID에 대한 정보를 모두 보내고 해당 데이터를 받은 server는 DB에 해당 정보를 저장합니다.

이후 check에서 Password와 Session ID가 register되어 저장된 값과 일치하게 되면 flag를 client에게 보내주게 됩니다.

여기서 얻게 된 정보를 정리해 보면

1. flag를 얻기 위해서는 client에서 올바른 Password 정보를 입력해야 한다.
2. Password와 session ID는 모두 client가 생성하게 된다.

이렇게 되면 client를 분석할 때 Session ID 및 Password를 생성하는 루틴을 찾아서 분석해 주어야 할 것으로 생각됩니다. 추측컨데 Session ID 생성 루틴과 Password 생성 루틴이 관련이 있어서 Session ID에 대한 정보를 가지고 Password를 추측해낼 수 있지 않을까 싶습니다.

### Validation TUI 분석 (삽질 1)

client 바이너리 자체는 사이즈가 만만치 않기 때문에, client에서 session ID를 출력해주는 지점을 찾아 거기서부터 session ID를 생성하는 지점까지 역으로 찾을 목적으로 client의 UI를 분석하였습니다.

사실 그것은 2번째 목적이었고, 터미널을 전체 화면으로 하지 않으면 Captcha가 화면에서 짤려서 보여서, Captcha 인증을 통과하기 위해 Captcha string까지 찾아야 할 것으로 생각되어서 해당 루틴을 분석했습니다. 근데 전체화면하니까 Captcha가 그냥 보이더라구요…?? (이거 알고 매우 허탈했음)

TUI에서 화면 크기는 자주 있는 이슈입니다. 해당 사실을 간과했던 것 같습니다.

어쨋든

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%202.png)

기본적으로 rust의 ratatui 모듈을 이용하셔 TUI를 구현하도록 되어 있습니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%203.png)

해당 draw 함수 내부를 잘 살펴보면 string들을 display 형식으로 변환하는 등의 루틴들을 볼 수 있습니다.

pure gdb로 디버깅하면서 해당 지점들을 trace 시도했는데 쉽지는 않았습니다. 결론적으로 필요한 작업도 아니었구요.

### Validation 통신 루틴 분석

validation 바이너리가 main.py에게 request를 보내는 지점을 찾게 되면 쉽게 Session ID와 Password를 다루는 메모리 주소를 특정 지을 수 있습니다. 이를 이용하여 validation 바이너리에서 프로세스 간 통신에 이용될 수 있는 모듈들을 살펴보다가 

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%204.png)

main함수에서 connect 후 write로 데이터를 쏴주는 루틴을 목격했습니다.

해당 지점을 디버깅 해보면

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%205.png)

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%206.png)

heap 영역에 register를 위해서 통신하는 데이터를 확인할 수 있습니다.

여기에 담긴 값이 `,` 구분자로 순서대로 `register`, `Password`, `Session ID`에 해당하게 됩니다.

메모리 주소를 찾게 되면, 여기서부터 해당 값들의 생성 루틴까지 역으로 올라가는 것은 어렵지 않습니다. 적절하게 xref 기능과 hw bp, watchpoint를 이용해주면 해당 값들의 생성 루틴을 추적할 수 있습니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%207.png)

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%208.png)

그 결과로 Session ID 및 password는 genstring으로 생성된 문자열을 합친 값이라는 사실을 알 수 있었습니다. 이제 genstring 루틴을 분석한 뒤 `Session ID` → `Password` 변환 방법을 고민해 보면 될 것 같습니다.

---

## validation::genstring

아래는 genstring 함수의 핵심 루틴입니다.

```powershell
      v11 = (unsigned int *)src[137];
      idx = src[138];
      v13 = a;
      v14 = a;
      if ( idx + 28 < a )
        v14 = 0LL;
      v15 = a;
      if ( idx + 1 < a )
        v15 = 0LL;
      v16 = idx + 1 - v15;
      v17 = v11[idx - v14 + 28] + v11[idx];
      if ( v16 + b_1 < a )
        v13 = 0LL;
      v11[v16 + b_1 - v13] = v17;
      v18 = idx - v15 + 29;
      v19 = a;
      v20 = a;
      if ( v18 < a )
        v20 = 0LL;
      v21 = v18 - v20;
      v22 = a;
      if ( v16 + 1 < a )
        v22 = 0LL;
      v23 = v16 + 1 - v22;
      v24 = v11[v21] + v11[v16];
      if ( v23 + b_1 < a )
        v19 = 0LL;
      v11[v23 + b_1 - v19] = v24;
      v25 = a;
      v26 = a;
      if ( v23 + 28 < a )
        v26 = 0LL;
      v27 = v23 + 28 - v26;
      v28 = a;
      if ( v23 + 1 < a )
        v28 = 0LL;
      v29 = v23 + 1 - v28;
      v30 = v11[v27] + v11[v23];
      if ( v29 + b_1 < a )
        v25 = 0LL;
      v11[v29 + b_1 - v25] = v30;
      src[138] = v29;
      v36[0] = v17;
      v36[1] = v24;
      v36[2] = v30;
      v31 = base64::encode::encoded_len(12LL, 1LL);
```

함수의 인자로 들어온 string 값에 특정 연산을 수행한 뒤 해당 값들을 base64 encoding하여 genstring의 output을 내게 됩니다.

정확한 로직을 python으로 정리하면 아래와 같습니다.

```python
src = [0x8C2AC1DC, 0x7A195F79, 0x5EE4E96B, 0xE2BE9249, 0xA85A0B2E, 0x93282C11, 0xD548E881, 0x271BD4F5, 0x94D41CA9, 0x82FC17CF, 0x1CE0A6B5, 0x27764FDB, 0xB42DF9ED, 0x269EDEDF, 0xA0745D85, 0x7F698A69, 0x3DB63F99, 0xE6BD7C7F, 0x1D9CFFFC, 0xFD9BB948, 0x4798AA7A, 0x2A34EC3D, 0xAE66673A, 0xCD944448, 0x5FE8D533, 0xAC3F665A, 0x63110CB5, 0xA3FC2651, 0x78124A78, 0xDBA2F49A, 0x1708FC92, 0x00000000, 0x00000000, 0x00000000]
for i in range(20):
    src.append(0)

genstring_cnt = 8

res = []
for i in range(genstring_cnt):
    R0 = (src[i * 3] + src[(3 * i + 28) % 40]) & 0xffffffff
    src[(31 + i * 3) % 40] = R0
    res.append(R0)
    
    R1 = (src[3*i + 1] + src[(3*i + 29) % 40]) & 0xffffffff
    src[(32 + i*3) % 40] = R1
    res.append(R1)

    R2 = (src[3*i + 2] + src[(3*i + 30) % 40]) & 0xffffffff
    src[(33 + i*3) % 40] = R2
    res.append(R2)
    raw = (R0 + (R1 << 32) + (R2 << 64)).to_bytes(12, "little")
    print(base64.b64encode(raw))
```

genstring이 Password를 생성하기 위해 3번 호출되었고, Session ID를 생성하기 위해 5번 호출되므로

`genstring_cnt` 변수에 8을 넣고 실행시키면 Password와 Session ID를 얻을 수 있습니다.

---

## Session ID to Password

Session ID와 Password 모두 동일한 소스를 기반으로 생성됩니다. 약간 수열 같은 느낌이네요.

수열 A의 A[3]~A[7] 값을 가지고 A[0], A[1], A[2] 값을 성공적으로 추측할 수 있다면 Password를 얻어 낼 수 있습니다.

그럼 Session ID를 가지고 해당 값이 생성되는 소스 값들을 얻을 수 있을까 생각해보면,

소스 값들에 해당하는 미지수는 총 31개입니다. 그리고 Session ID 정보가 제공됨으로써 얻는 식은 고작 15개 밖에 되지 않습니다. 그렇기에 사실상 소스를 얻는 것은 불가능 하였고, 소스 없이 Password만 얻을 수 있는 방법도 고민해 보았지만 불가능으로 판단하였습니다.

---

## Gathering Information 2

### Random to Source of password & session id

지금까지 분석한 정보로는 Password를 얻기 불가능하다는 판단 하에 더 많은 정보를 수집해야 했습니다.

그래서 첫 번째로 삼은 분석 타겟은 genstring의 인자로 들어가는 password와 session ID의 소스 값들이 생성되는 루틴을 분석하고자 하였습니다.

해당 값들은 디버깅을 해보니 랜덤하게 생성되는 것으로 보였습니다. 그래도 해당 값들이 생성되는 루틴을 조금씩 추적해 본 결과

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%209.png)

s 배열이 소스 값들입니다. `s[2*i]`와 `s[2*i+1]`값이 서로 관련이 있다는 것을 알 수 있었습니다.

여기서 `s[0]~s[0x20]`까지 31개의 값들을 s에 넣어준 뒤 아래 루틴으로 넘어갑니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%2010.png)

여기서는 `s[i+31] = s[i] + s[i+28]` 형태로 s[31] 부터 s[0x159]까지 채워 넣는 루틴입니다.

이렇게 하고 `s[0x139]` 부터 31개의 값이 genstring의 소스로 들어가게 됩니다.

이렇게 해도 역산이 잘 안 되었습니다. 그래서 다른 정보들을 더 수집하고자 하였습니다.

### Captcha genstring

Captcha string 또한 genstring으로 생성된다는 사실을 알게 되었습니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%2011.png)

이는 Password와 Session ID 가 생성된 직후에 실행되는 genstring으로 생성됩니다.

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%2012.png)

Captcha를 입력해 주고 나면 5번의 기회가 남았다면서 다른 Captcha Code들도 보여줍니다.

이런 방식으로 총 6개의 captcha code들을 얻을 수 있습니다.

이는 총 6번의 genstring 결과를 얻을 수 있다는 것을 의미하며, Session ID에서 5번의 genstring으로 15개의 식을 얻게 되고, captcha code에서 6번의 genstring으로 18개의 식을 얻어 31개의 미지수를 구하기 위해 총 33개의 식을 얻게 됩니다.

Session ID와 6개의 Captcha code를 이용해 소스를 계산할 수 있게 되고 이는 결국 Password를 계산할 수 있음을 의미하게 됩니다.

---

## Get Password

z3를 이용하여 역연산을 구현해 주었습니다.

33개의 식을 solver에 추가하고 Password에 해당하는 값을 얻어 base64 encoding하여 password string을 얻어 줍니다.

**solver.py**

```c
from z3 import *
import base64

'''
s[i] + s[i + 28] = s[i + 31]

s[0] ~ [30]까지가 변수
'''

Session_ID = "HTyTaILo8RnX0mFsBNOeF1yHRwwMcQpgLp6qJrYnGif5GAK0hFupp7nZAEsZtGIuu1A6ke5dBZEAehZL"
Captcha_0 = "S9vAUDSX4YrhOQXl"
Captcha_1 = "E5GlR3kf1xapjAoc"
Captcha_2 = "FmfOdWOSBjomhXrb"
Captcha_3 = "pjeotiuPhdXDsCUs"
Captcha_4 = "RyLQdV99bzEeC1dC"
Captcha_5 = "7qi4Dny5Apqg80hc"

def src_append(val):
    for i in range(3):
        src.append(val & 0xFFFFFFFF)
        val >>= 32

src = []
Session_raw = int.from_bytes(base64.b64decode(Session_ID), "little")
for i in range(5 * 3):
    tmp = Session_raw & 0xFFFFFFFF
    src.append(tmp)
    Session_raw >>= 32

src_append(int.from_bytes(base64.b64decode(Captcha_0), "little"))
src_append(int.from_bytes(base64.b64decode(Captcha_1), "little"))
src_append(int.from_bytes(base64.b64decode(Captcha_2), "little"))
src_append(int.from_bytes(base64.b64decode(Captcha_3), "little"))
src_append(int.from_bytes(base64.b64decode(Captcha_4), "little"))
src_append(int.from_bytes(base64.b64decode(Captcha_5), "little"))

solver = Solver()
S = [BitVec('s_{}'.format(i), 32) for i in range(31+33+9)]

for i in range(33+9):
    solver.add(S[i+31] == S[i] + S[i+28])

for i in range(33):
    solver.add(S[i+31+9] == src[i])

if solver.check() == sat:
    pass_raw = []
    for i in range(9):
        pass_raw.append(solver.model()[S[i+31]].as_long())
    print(pass_raw)
    print(type(pass_raw[0]))
    
    pass_byte = b""
    for raw in pass_raw:
        pass_byte += int(raw).to_bytes(4, "little")
    print(base64.b64encode(pass_byte))
    
```

Captcha code들을 입력해 주면서 6개의 captcha code들을 모두 얻은 뒤 솔버에 집어 넣어 주면

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%2013.png)

Password를 입력해 주면

![Untitled](/CTF/Codegate%202024/prism_messenger/Untitled%2014.png)

이렇게 Server가 flag를 보내 준 것을 validation 바이너리가 출력되는 것을 확인할 수 있습니다.
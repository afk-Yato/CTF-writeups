***********************JustDoIt!***********************

First thing that i do in every CTF is checking the file to get an idea about what we are dealing with
 $file ./justdoit
 ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked...

 So know we know that we are dealing with executable 32bit ELF(Executable and Linkable Format) file , using least significant bit (LSB) and a architechure : 80386.

 Now let's check for protections
 $checksec --file=./justdoit
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
 Perfect no canaries and no PIE protections but NX is enable ;So we will deal with a static memory layout and no protection for the return to main !

 Now time to start the actual work.
 since we dont have the source code let's decompile the binary with ghidraand see .
 let's dcompile main and take a look 

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

The firs part is not interrestin(setup of the stack and i/o/err)
we can ignore the part reading the file flag.txt and copying its content into a variable called flag.

pcVar1 = fgets(local_28,0x20,stdin); local_28 size is 0x10 byte and it reads 0x20 byte

we can see know the vulnerability :)
buffer overflow in variable local_28 so lets rename it vuln_buffer to see it better

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

  let's understand what are the interrsting variables here;
  vuln buffer that we want to overflow , flag which is a pointer to the flag.txt content,and local_14 (string) that is printed at the end.
  hmmm so know we can see the idea:
  what if we overflow vuln until we reach local_14(target) , overwrite it to point to the flag , then the flag will be printed.

  so know let's collect the addresses of each variable with gdb. 
  $gdb ./justdoit
  starting with flag which is not declared in main and use so it is a global variable so we can get its address before running the program
  gdb> info variables flag
  0x0804a080  flag ;no PIE so we will work with the same addresses

  
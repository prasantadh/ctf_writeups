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

that gives us 0xf70a9b59f70a9b58 = 17801211287834368856. let's try to patch it into the program to see if we get at least the first part of the flag right; but first we gotta get read of the fib()

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

not, back in gdb we set a breakpoint on print_flag, before the call to decrypt_flag, so we can change the value of the key

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

the 16 byte value was enough for the entire flag decryption

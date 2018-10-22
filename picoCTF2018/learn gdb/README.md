# [learn gdb](https://2018game.picoctf.com/problems)

## Problem
Using a debugging tool will be extremely useful on your missions. Can you run this [program](https://2018shell3.picoctf.com/static/da4354bbe8d7772aa4bd34003211b6c5/run) in gdb and find the flag? You can find the file in /problems/learn-gdb_1_a2decdea3e89bfcdcbd9de1a67ceed0e on the shell server.

## Solution

```
——> ./run
Decrypting the Flag into global variable 'flag_buf'
.....................................
Finished Reading Flag into global variable 'flag_buf'. Exiting.
```

it takes quite some time; let's see what it does under the hood

```
——> ltrace ./run
__libc_start_main(0x4008c9, 1, 0x7fffe0f8a7c8, 0x400920 <unfinished ...>
setvbuf(0x7f31b33445c0, 0, 2, 0)                                                                        = 0
puts("Decrypting the Flag into global "...Decrypting the Flag into global variable 'flag_buf'
)                                                             = 52
malloc(47)                                                                                              = 0x1488260
putchar(46, 0x1488290, 0x1488260, 0x1488260.)                                                            = 46
usleep(250000)                                                                                          = <void>
strtol(0x7fffe0f8a6b0, 0, 16, 0)                                                                        = 69
putchar(46, 0x7fffe0f8a6b1, 112, 0xfffffffffffffff.)                                                     = 46
usleep(250000)                                                                                          = <void>
strtol(0x7fffe0f8a6b0, 0, 16, 0)                                                                        = 62
putchar(46, 0x7fffe0f8a6b1, 105, 0xfffffffffffffff.)                                                     = 46
usleep(250000)                                                                                          = <void>
strtol(0x7fffe0f8a6b0, 0, 16, 0)                                                                        = 56
putchar(46, 0x7fffe0f8a6b1, 99, 0xfffffffffffffff.)                                                      = 46
usleep(250000)                                                                                          = <void>
[..]
```

okay so it computes a char at a time then sleeps for 0.25 seconds. lets' geedeebee and break at a call to putchar.

```
——> gdb ./run
Reading symbols from ./run...(no debugging symbols found)...done.
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000004008c9 <+0>:	push   rbp
   0x00000000004008ca <+1>:	mov    rbp,rsp
   0x00000000004008cd <+4>:	sub    rsp,0x10
   0x00000000004008d1 <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x00000000004008d4 <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004008d8 <+15>:	mov    rax,QWORD PTR [rip+0x200af9]        # 0x6013d8 <stdout@@GLIBC_2.2.5>
   0x00000000004008df <+22>:	mov    ecx,0x0
   0x00000000004008e4 <+27>:	mov    edx,0x2
   0x00000000004008e9 <+32>:	mov    esi,0x0
   0x00000000004008ee <+37>:	mov    rdi,rax
   0x00000000004008f1 <+40>:	call   0x400650 <setvbuf@plt>
   0x00000000004008f6 <+45>:	mov    edi,0x4009d0
   0x00000000004008fb <+50>:	call   0x400600 <puts@plt>
   0x0000000000400900 <+55>:	mov    eax,0x0
   0x0000000000400905 <+60>:	call   0x400786 <decrypt_flag>
   0x000000000040090a <+65>:	mov    edi,0x400a08
   0x000000000040090f <+70>:	call   0x400600 <puts@plt>
   0x0000000000400914 <+75>:	mov    eax,0x0
   0x0000000000400919 <+80>:	leave  
   0x000000000040091a <+81>:	ret    
End of assembler dump.
gdb-peda$ disas decrypt_flag
Dump of assembler code for function decrypt_flag:
   0x0000000000400786 <+0>:	push   rbp
[..]
  0x00000000004007e0 <+90>:	mov    DWORD PTR [rbp-0x1c],0x0
  0x00000000004007e7 <+97>:	jmp    0x400889 <decrypt_flag+259>
  0x00000000004007ec <+102>:	mov    edi,0x2e
  0x00000000004007f1 <+107>:	call   0x4005f0 <putchar@plt>
  0x00000000004007f6 <+112>:	mov    edi,0x3d090
  0x00000000004007fb <+117>:	mov    eax,0x0
  0x0000000000400800 <+122>:	call   0x400670 <usleep@plt>
[..]
  End of assembler dump.
  gdb-peda$ break *0x00000000004007f1
  Breakpoint 1 at 0x4007f1
```

after running it, having gdb peda, i noticed that on the RDX register were passed the characters of the flag one by one

```
gdb-peda$ c
Continuing.
.[----------------------------------registers-----------------------------------]
RAX: 0x5
RBX: 0x0
RCX: 0xfffffffffffffff
RDX: 0x70 ('p') <---- first char of "picoCTF{......}"
```

so at this point i just told gdb to redirect the output to a file and print the value in $rdx every time it hit that breakpoint and ran the program again from the start

```
(gdb) set pagination off
(gdb) set logging file gdb.output
(gdb) set logging on
Copying output to gdb.output.
(gdb)
Already logging to gdb.output.
(gdb) break *0x00000000004007f1
Breakpoint 1 at 0x4007f1
(gdb) command 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>p/c $rdx
>continue
>end
```

also had to rerun gdb without sourcing .gdbinit because with gdb-peda it crashed.

```
(gdb) r
Starting program: /home/andrei/Documents/pico/run
Decrypting the Flag into global variable 'flag_buf'

Breakpoint 1, 0x00000000004007f1 in decrypt_flag ()
$1 = 96 '`'
.
Breakpoint 1, 0x00000000004007f1 in decrypt_flag ()
$2 = 112 'p'
[..]
Breakpoint 1, 0x00000000004007f1 in decrypt_flag ()
$36 = 49 '1'
.
Breakpoint 1, 0x00000000004007f1 in decrypt_flag ()
$37 = 52 '4'
.
Finished Reading Flag into global variable 'flag_buf'. Exiting.
```

then parse the output in the gdb.output to get the flag printed sanely, with this horrendous line

```
——> cat gdb.output  | grep "'" | sed -e "s_.* __g" -e "s_'__g" | tr -d '\n' | tr -d '`'
picoCTF{gDb_iS_sUp3r_u53fuL_f3f39814
```

just add the last bracket and we're done.

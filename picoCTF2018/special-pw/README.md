# [special-pw](https://2018game.picoctf.com/problems)

## Problem
 Can you figure out the right argument to this program to login? We couldn't manage to get a copy of the binary but we did manage to [dump](https://2018shell3.picoctf.com/static/1ffabc690f51eafa70601e3be94305d2/special_pw.S) some machine code and memory from the running process.

## Solution

remove the memory dump, comments and other stuff that throws errors with gcc from the file, then compile it with gcc

```
——> gcc -m32 -g spec.S -o spec.o
[andrei@jacky 20:15:59] ~/Documents/pico
——> ./spec.o
Segmentation fault (core dumped)
```

it segfaults because it tries to access the old memory address. opening the executable with a very random decompiler tool we can obtain this pseudocode

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *char_at_pos_j; // ST0C_4
  signed int k; // [esp+0h] [ebp-10h]
  int strlen; // [esp+4h] [ebp-Ch]
  int j; // [esp+8h] [ebp-8h]
  const char *i; // [esp+Ch] [ebp-4h]
  const char *v9; // [esp+Ch] [ebp-4h]

  strlen = 0;
  for ( i = argv[1]; *i; ++i )
    ++strlen;
  for ( j = 0; strlen - 3 > j; ++j )
  {
    char_at_pos_j = (char *)&argv[1][j];
    *char_at_pos_j ^= 0x66u;
    *(_WORD *)char_at_pos_j = __ROR2__(*(_WORD *)char_at_pos_j, 15);
    *(_DWORD *)char_at_pos_j = __ROL4__(*(_DWORD *)char_at_pos_j, 10);
  }
  v9 = argv[1];
  for ( k = 0x59B617B; *(_BYTE *)k; ++k )
  {
    if ( *v9 != *(_BYTE *)k )
      return 0;
    ++v9;
  }
  return argv[1][k - 0x59B617B] == 0;
}
```

what this code does is, for each byte in the dump we have:
- take the address of the current position -> addr
- XOR single byte at dump[addr] with 0x66
- rotate right the two bytes at dump[addr] for 15 bits
- rotate left the four bytes at dump[addr] for 10 bits

and it stops when reaches a position where a 4 bytes value cannot be correctly dereferenced. we just need to execute the same operations in reverse order; this will do the job

```
——> cat solver.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

typedef unsigned short WORD;
typedef unsigned long DWORD;

/*
059B617B:  bd 0e 50 1b ef 9e 16 d1  7d e5 c1 55 c9 7f cf 21   |..P.....}..U...!|
059B618B:  c5 99 51 d5 7d c9 c5 9d  21 d3 7d c1 cd d9 95 8f   |..Q.}...!.}.....|
059B619B:  91 99 97 c5 f5 d1 2d d5  00                        |......-..|
*/

unsigned char dump[] = {
	0xbd, 0x0e, 0x50, 0x1b, 0xef, 0x9e, 0x16, 0xd1,  0x7d, 0xe5, 0xc1, 0x55, 0xc9, 0x7f, 0xcf, 0x21,
	0xc5, 0x99, 0x51, 0xd5, 0x7d, 0xc9, 0xc5, 0x9d,  0x21, 0xd3, 0x7d, 0xc1, 0xcd, 0xd9, 0x95, 0x8f,
	0x91, 0x99, 0x97, 0xc5, 0xf5, 0xd1, 0x2d, 0xd5,  0x00
	};

uint16_t rotate_right16 (uint16_t value, uint32_t count ) {
    const uint16_t mask = (CHAR_BIT * sizeof (value)) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

uint32_t rotate_left32 (uint32_t value, uint32_t count ) {
    const uint32_t mask = (CHAR_BIT * sizeof (value)) - 1;
    count &= mask;
    return (value << count) | (value >> (-count & mask));
}

int main(void) {

	int size = sizeof(dump) / sizeof(unsigned char);
	int i, e;

	for (i = size - 5; i >=0; i--) {
		*((DWORD *) &dump[i]) = rotate_left32(*((DWORD *) &dump[i]), 22);
		*((WORD *) &dump[i]) = rotate_right16(*((WORD *) &dump[i]), 1);
		dump[i] ^= 0x66;
	}

	puts(dump);

	return 0;
}
[andrei@jacky 20:23:19] ~/Documents/pico
——> gcc -m32 -o solver solver.c
[andrei@jacky 20:23:33] ~/Documents/pico
——> ./solver
picoCTF{gEt_y0Ur_sH1fT5_r1gHt_036ecdfe1}
```

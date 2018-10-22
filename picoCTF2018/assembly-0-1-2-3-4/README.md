# [assembly-0-1-2-3-4](https://2018game.picoctf.com/problems)

## Problem 0
What does asm0(0x2a,0x4f) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell3.picoctf.com/static/9dd737e97ccbb554569020e205ffa5c8/intro_asm_rev.S) located in the directory at /problems/assembly-0_3_b7d6c21be1cefd3e53335a66e7815307.

## Problem 1
What does asm1(0xcd) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell3.picoctf.com/static/d0e1ee3fb4731170df828a2a6c81034a/eq_asm_rev.S) located in the directory at /problems/assembly-1_2_ac6a59ca77a2d619ddabb3c3ffedb9a8.


## Problem 2
What does asm2(0x8,0x21) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell3.picoctf.com/static/caa6b40f4abe584fd34004d7bc205234/loop_asm_rev.S) located in the directory at /problems/assembly-2_1_c1900e7d33989b0191c51ef927b24f37.


## Problem 3
What does asm3(0xb5e8e971,0xc6b58a95,0xe20737e9) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. [Source](https://2018shell3.picoctf.com/static/914cb4b741cf358f0cdd4d9d07ad5671/end_asm_rev.S) located in the directory at /problems/assembly-3_3_bfab45ee7af9befc86795220ffa362f4.


## Problem 4
Can you find the flag using the following assembly [source](https://2018shell3.picoctf.com/static/e99256b1516dc6d5d2502611d0385521/comp.nasm)? WARNING: It is VERY long...


## Solution 0-1-2-3

I grouped them together because they can all be solved in the same way.
For the 0-1-2-3, the steps are exactly the same: let's look at assembly-3. We're presented with this source file:

```
.intel_syntax noprefix
.bits 32

.global asm3

asm3:
	push   	ebp
	mov    	ebp,esp
	mov	eax,0x19
	xor	al,al
	mov	ah,BYTE PTR [ebp+0xa]
	sal	ax,0x10
	sub	al,BYTE PTR [ebp+0xd]
	add	ah,BYTE PTR [ebp+0xc]
	xor	ax,WORD PTR [ebp+0x12]
	mov	esp, ebp
	pop	ebp
	ret
```

we can make it a shared library and export its function asm3. let's just make it compatible with nasm assembler: delete the 'PTR' and change the first lines as follows:

```
section .text
global asm3

asm3:
	push   	ebp
	mov    	ebp,esp
	mov	eax,0x19
	xor	al,al
	mov	ah,BYTE [ebp+0xa]
	sal	ax,0x10
	sub	al,BYTE [ebp+0xd]
	add	ah,BYTE [ebp+0xc]
	xor	ax,WORD [ebp+0x12]
	mov	esp, ebp
	pop	ebp
	ret
```

now we can write a little C program that uses the exported library:

```
#include <stdio.h>
extern int asm3(int a, int b, int c);

int main(void) {

	printf("0x%x\n", asm3(0xb5e8e971,0xc6b58a95,0xe20737e9));

	return 0;
}
```

for the number of arguments of the asm function, you can look at the problem description. asm3 is declared as extern, meaning it will look for it in another file at compile(/linking?) time. now just compile them together and execute the resulting executable

```
[andrei@jacky 15:27:00] ~/Documents/pico/3
——> nasm -f elf32 end_asm_rev.S -o asmfun.o
[andrei@jacky 15:27:42] ~/Documents/pico/3
——> gcc sol.c asmfun.o -o sol -m32
[andrei@jacky 15:27:59] ~/Documents/pico/3
——> ./sol
0x7771
```

paste this number into the website to solve the challenge.

## Solution 4

this time the source is already nasm-friendly, we just have to compile and execute it:

```
[andrei@jacky 15:30:26] ~/Documents/pico/4
——> nasm -f elf32 comp.nasm -o comp.o
[andrei@jacky 15:30:28] ~/Documents/pico/4
——> gcc -m32 -o comp comp.o
[andrei@jacky 15:30:37] ~/Documents/pico/4
——> ./comp
picoCTF{1_h0p3_y0u_c0mP1l3d_tH15_3205858729}
```

Felt like cheating solving the first ones like this...

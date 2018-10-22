# [quackme up](https://2018game.picoctf.com/problems)

## Problem
The duck puns continue. Can you crack, I mean quack this [program](https://2018shell3.picoctf.com/static/2bc85a4cb3e4366183c37ec9146a9d05/main) as well? You can find the program in /problems/quackme-up_2_bf9649c854a2615a35ccdc3660a31602 on the shell server.

## Solution

```
——> ./main
We're moving along swimmingly. Is this one too fowl for you?
Enter text to encrypt: AAAABBBB
Here's your ciphertext: 02 02 02 02 32 32 32 32
Now quack it! : 11 80 20 E0 22 53 72 A1 01 41 55 20 A0 C0 25 E3 35 40 65 95 75 00 30 85 C1
That's all folks.
```

this program encrypts the characters you give it, prints the encrypted chars, then tells you to "quack" a ciphertext. inspecting the executable we come across the encryption function. the important stuff is in this snippet, which i already commented:

```
|           ; CODE XREF from sym.encrypt (0x80486ef)                                                                                                                     
|       .-> 0x0804869f      8b55f0         edx = dword [counter]                                                                                                         
|       :   0x080486a2      8b4508         eax = dword [string]        ; [0x8:4]=-1 ; 8                                                                                  
|       :   0x080486a5      01d0           eax += edx                                                                                                                    
|       :   0x080486a7      0fb600         eax = byte [eax]            ; get the current char                                                                            
|       :   0x080486aa      8845ef         byte [character] = al                                                                                                         
|       :   0x080486ad      0fbe45ef       eax = byte [character]       ; get only the single char (only one byte)                                                       
|       :   0x080486b1      83ec0c         esp -= 0xc                                                                                                                    
|       :   0x080486b4      50             push eax                                                                                                                      
|       :   0x080486b5      e817ffffff     sym.rol4 ()                 ;[1]   ; rotate it left 4 bits                                                                    
|       :   0x080486ba      83c410         esp += 0x10                 ; return value is in eax                                                                          
|       :   0x080486bd      8845ef         byte [character] = al                                                                                                         
|       :   0x080486c0      8075ef16       byte [character] ^= 0x16       ; XOR it with 0x16 = 22 = 0b00010110                                                           
|       :   0x080486c4      0fbe45ef       eax = byte [character]                                                                                                        
|       :   0x080486c8      83ec0c         esp -= 0xc                                                                                                                    
|       :   0x080486cb      50             push eax                                                                                                                      
|       :   0x080486cc b    e827ffffff     sym.ror8 ()                 ;[2]   ; rotate it right 8 bits                                                                   
|       :   ;-- eip:                                                                                                                                                     
|       :   0x080486d1      83c410         esp += 0x10                                                                                                                   
|       :   0x080486d4      8845ef         byte [character] = al                                                                                                         
|       :   0x080486d7      8b55f0         edx = dword [counter]                                                                                                         
|       :   0x080486da      8b4508         eax = dword [string]        ; [0x8:4]=-1 ; 8                                                                                  
|       :   0x080486dd      01c2           edx += eax                                                                                                                    
|       :   0x080486df      0fb645ef       eax = byte [character]                                                                                                        
|       :   0x080486e3      8802           byte [edx] = al             ; put it back in the string buffer                                                                
|       :   0x080486e5      8345f001       dword [counter] += 1        ; increment counter                                                                               
|       :   ; CODE XREF from sym.encrypt (0x804869d)                                                                                                                     
|       :   0x080486e9      8b45f0         eax = dword [counter]                                                                                                         
|       :   0x080486ec      3b45f4         var = eax - dword [length]                                                                                                    
|       `=< 0x080486ef      7cae           jl 0x804869f                ;[3]                                                                                              
|           0x080486f1      8b45f4         eax = dword [length]                                                                                                          
|           0x080486f4      c9                                                                                                                                           
\           0x080486f5      c3             return dword [length]                                                                                                         
```

pretty easy stuff. basically goes trough every character of our input, rotates it left 4 bits, XORs it with 0x16, then rotates it right 8 bits; notice the rotate 8 bits does nothing since we work with 8 bits values. we can decrypt the quacked ciphertext with this simple C code:

```
#include <stdio.h>
#include <stdint.h>   // for uint8_t

int main(void) {

	uint8_t encrypted[] = {
	0x11, 0x80, 0x20, 0xE0, 0x22, 0x53, 0x72, 0xA1, 0x01,
    0x41, 0x55, 0x20, 0xA0, 0xC0, 0x25, 0xE3, 0x35, 0x40,
	0x65, 0x95, 0x75, 0x00, 0x30, 0x85, 0xC1
      };

	char decrypted[64];
	int i = 0;
	uint8_t c, n;

	memset(decrypted, 0x00, 64);

	for (i = 0; i < 25; i++) {
		c = encrypted[i];
		c ^= 0x16;
		n = (c << 4) | (c >> 4);
		decrypted[i] = n;
	}

	puts(decrypted);

	return 0;
}
```

that simply goes trough the encryption algorithm in the inverse order.

```
——> ./solver
picoCTF{qu4ckm3_2e786ab9}
```

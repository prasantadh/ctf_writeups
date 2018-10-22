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

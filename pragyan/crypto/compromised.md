### Problem description

In this challenge, we are given a file ```script.py``` that looks like this
```
#!/usr/local/bin/python3

from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256
from random import randrange
from os import urandom
import sys

def is_too_much_evil(x, y):
    if y <= 0:
        return True
    z = x//y
    while z&1 == 0:
        z >>= 1
    return z == 1

def magic(key):
    flag = open("flag.txt", 'rb').readline()
    key = sha256(long_to_bytes(key)).digest()
    iv = urandom(AES.block_size)
    aes = AES.new(key, AES.MODE_CBC, iv)
    ct = iv + aes.encrypt(pad(flag, AES.block_size))
    return ct

p = 143631585913210514235039010914091901837885309376633126253342809551771176885137171094877459999188913342142748419620501172236669295062606053914284568348811271223549440680905140640909882790482660545326407684050654315851945053611416821020364550956522567974906505478346737880716863798325607222759444397302795988689
g = 65537
o = p-1

try:
    eve = int(input('Eve\'s evil number: '), 16)
    if is_too_much_evil(o, eve):
        raise Exception
except:
    sys.exit(1)

alice_secret = randrange(2, o)
recv_alice = pow(g, alice_secret, p)
print('Received from Alice:', hex(recv_alice)[2:])

send_bob = pow(recv_alice, eve, p)
print('Sent to Bob:', hex(send_bob)[2:])

bob_scret = randrange(2, o)
recv_bob = pow(g, bob_scret, p)
print('Received from Bob:', hex(recv_bob)[2:])

send_alice = pow(recv_bob, eve, p)
print('Sent to Alice:', hex(send_alice)[2:])

key = pow(send_alice, alice_secret, p)
if key != pow(send_bob, bob_scret, p):
    sys.exit(1)

print('Ciphertext:', magic(key).hex())

```

Here a DH key exchange is being performed between Alice and Bob, with Eve acting as person in the middle. The challenge is to craft an exponent $e$ such that we can decrypt the ciphertext.

### Approach

This challenge required a bit of number theory knowledge

First we can see that (p-1) has multiple factors like 2, 4, 8, 16 etc. So the first thought that I had was to use $e$ like $\frac{p-1}{2}$ or $\frac{p-1}{4}$, but these fail due the check in ```is_too_much_evil```. However if we choose $e$ as something like $\frac{3(p-1)}{16}$, then the check succeeds. Why? Because (p-1)// $e$ gives us 16//3 which is 5. 
Now lets looks at how key is calculated. Lets assume that Alice's private exponent is $a$, Bob's private exponent is $b$, the final key is $g^{abe}$. Now if either of $a$ or $b$ is a multiple of 16, then the product $abe$ would be a multiple of $(p-1)$, and since $g^{p-1}$ is 1,we would get the key as 1. And using that we can decrypt the ciphertext

### Exploit

```
from pwn import *
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from hashlib import sha256
from random import randrange
from os import urandom

p = 143631585913210514235039010914091901837885309376633126253342809551771176885137171094877459999188913342142748419620501172236669295062606053914284568348811271223549440680905140640909882790482660545326407684050654315851945053611416821020364550956522567974906505478346737880716863798325607222759444397302795988689

o = (p - 1)

g = 65537

for i in range(20):
	# p = remote("compromised.ctf.pragyan.org", 56931)
	p = process("./script.py")
	p.recvuntil(b"Eve's evil number: ")
	evil_num = (3*o)//16
	payload = hex(evil_num)[2:]
	p.sendline(payload.encode())
	p.recvuntil(b"Received from Alice:")
	
	recv_alice = p.recvline().strip().decode()
	recv_alice = int(recv_alice, 16)
	
	p.recvuntil(b"Ciphertext:")
	cipher = int(p.recvline().strip().decode(), 16)
	# Now we assume that the key is 1
	key = 1
	key = sha256(long_to_bytes(key)).digest()
	cipher = bytes.fromhex(hex(cipher)[2:])
	iv = cipher[0:AES.block_size]
	enc = cipher[AES.block_size:]
	aes = AES.new(key, AES.MODE_CBC, iv)
	try:
		msg = unpad(aes.decrypt(enc), AES.block_size)
		print(msg.decode())
		break
	except:
		print(i)
		p.close()
		continue


```
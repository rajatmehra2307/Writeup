### Problem statement
In this problem we are given a modified AES blockcipher where the S-Box is the identity function. And we are asked to decrypt the encryption of flag

### Method

According to this article, https://crypto.stackexchange.com/questions/67612/aes-oracle-with-bad-s-box#67614 an identity S-box can be broken by sending an all 0s plaintext. The ciphertext received once xored with the flag's ciphertext blocks and decrypted using AES without addRoundKe (Here the key does not matter), we would get back the plaintext block.

### Exploit
```
from pwn import *
from aes import AES


def get_xor(s1, s2):
	return [a ^ b for (a,b) in zip(s1, s2)]

def new_addRoundKey(state, roundKey):
	return state

p = remote("puffer.utctf.live", 52584)

p.recvuntil(b"plaintext hex string: ")
payload = b"0"*32
p.sendline(payload)

b = p.recvline().strip().decode()
b = bytes.fromhex(b)

secret_text = "3384f87f781c394b79e331510540a4125a371b057b058d8e793521cd43f2ae94"
# secret_text = secret_text[32:]

secret_text = bytes.fromhex(secret_text)
key = b"\x00"*16
out = b''
for i in range(0, len(secret_text), 16):
	block = secret_text[i:i+16]
	aes = AES()
	aes.addRoundKey = lambda state, __: state
	xored_text = get_xor(block, b)
	out += bytes(aes.decrypt(xored_text, key, 16))

print(out.decode())

```
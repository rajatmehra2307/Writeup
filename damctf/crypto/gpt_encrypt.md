## Problem Statement ##

In this challenge, we are given 3 files, a file called ```gpt.py``` that implements the blockcipher logic, a ```chal.py``` and an encrypted flag file. The code for ```gpt.py``` is

```
import numpy as np
# Define the key schedule function
def key_schedule(key):
    # Convert the key to a numpy array
    key_array = np.array([ord(char) for char in key])
    key_len = len(key_array)

    # Pad the key with zeros to a multiple of 4
    if key_len % 4 != 0:
        key_array = np.pad(key_array, (0, 4 - key_len % 4), mode='constant')
        key_len = len(key_array)

    # Reshape the key to a 4xN matrix
    key_matrix = key_array.reshape(-1, 4).T

    # Generate the key schedule
    round_keys = []
    for i in range(4):
        round_keys.append(key_matrix[i % key_len])

    return round_keys

# Define the encryption function
def encrypt(block, round_keys):
    state = np.array([ord(char) for char in block]).reshape(4, 4).T
    for i in range(4):
        state = np.mod(state + round_keys[i], 256)
        state = np.roll(state, -1, axis=0)
        state = np.roll(state, -1, axis=1)
    return ''.join([chr(char) for char in state.T.flatten()])

# Define the decryption function
def decrypt(block, round_keys):
    state = np.array([ord(char) for char in block]).reshape(4, 4).T
    for i in range(3, -1, -1):
        state = np.roll(state, 1, axis=1)
        state = np.roll(state, 1, axis=0)
        state = np.mod(state - round_keys[i], 256)
    return ''.join([chr(char) for char in state.T.flatten()])

# Example usage
def example():
    key = 'mysecretkey'
    round_keys = key_schedule(key)
    plaintext = 'hello world'
    ciphertext = encrypt(plaintext, round_keys)
    decrypted_text = decrypt(ciphertext, round_keys)
    print('Plaintext:', plaintext)
    print('Ciphertext:', ciphertext)
    print('Decrypted text:', decrypted_text)

"""
This implementation uses a 128-bit block size and a 128-bit key size. The key schedule function pads the key with zeros to a multiple of 4 bytes and generates the round keys by taking the first 4 bytes of each column of the padded key matrix. The encryption function performs 4 rounds of encryption, each of which adds the round key to the state, shifts the rows and columns of the state, and applies a modular arithmetic operation to keep the values within the range of 0 to 255. The decryption function performs the same operations in reverse order to recover the plaintext.
"""

```
The code for the challenge is 
```
#!/usr/bin/env python3

import os
from Crypto.Util.Padding import pad

import gpt


KEY_SIZE = 16
BLOCK_SIZE = 16

def xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

# Wrappers to work with bytes instead of strings.
def key_schedule(key):
    return gpt.key_schedule(key.decode('latin-1'))
def encrypt(block, round_keys):
    return gpt.encrypt(block.decode('latin-1'), round_keys).encode('latin-1')

def cbc_enc(msg, key):
    msg = pad(msg, BLOCK_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    round_keys = key_schedule(key)

    ciphertext = iv
    for i in range(0, len(msg), BLOCK_SIZE):
        iv = encrypt(xor(iv, msg[i:i+BLOCK_SIZE]), round_keys)
        ciphertext += iv
    return ciphertext

with open('flag', 'r') as f:
    flag = f.read().strip()
assert(len(flag) == 33)

key = os.urandom(KEY_SIZE)
print("Key is:")
print(key)
ciphertext = cbc_enc(flag.encode(), key)
print(ciphertext.hex())

```

## Solution ##

As explained in the last comment of the code in ```gpt.py```, the encryption performs some operation using the ```round_keys``` which is essentially the following,
$\left[\begin{array}{ccc}
k_1 & k_5 & k_9 & k_{13}\\
k_2 & k_6 & k_{10} & k_{14}\\
k_3 & k_7 & k_{11} & k_{15}\\
k_4 & k_8 & k_{12} & k_{16}
\end{array}\right]$

In every round we take one row of this 2D matrix and perform some operation on the input msg, which is again represented as 

$\left[\begin{array}{ccc}
m_1 & m_5 & m_9 & m_{13}\\
m_2 & m_6 & m_{10} & m_{14}\\
m_3 & m_7 & m_{11} & m_{15}\\
m_4 & m_8 & m_{12} & m_{16}
\end{array}\right]$

In order to understand how ```encrypt``` function modifies the input msg, I wrote the following script
```
import numpy as np

message = ""
for i in range(1, 17):
	message += "m"+str(i)+","

key = message.replace("m", "k")
message = message.split(",")[:-1]
key = key.split(",")[:-1]

message = np.array(message,dtype=object).reshape(4,4).T
key = np.array(key,dtype=object).reshape(4,4).T

state = message

for i in range(4):
	state = state + '+' + key[i]
	state = np.roll(state, -1, axis=0)
	state = np.roll(state, -1, axis=1)

print(state)
```

The result of this encryption is essentially the following 2D matrix

$\left[\begin{array}{ccc}
m_1 + \alpha & m_5+\beta& m_9+\gamma& m_{13}+\delta\\
m_2 + \alpha& m_6 + \beta& m_{10}+\gamma & m_{14}+\delta\\
m_3 + \alpha& m_7 + \beta& m_{11}+\gamma & m_{15}+\delta\\
m_4+ \alpha & m_8 + \beta& m_{12}+\gamma & m_{16}+\delta
\end{array}\right]$

where $\alpha = k_1+k_{14}+k_{11}+k_8$

$\beta = k_5+k_{2}+k_{15}+k_{12}$

$\gamma = k_9+k_{6}+k_{3}+k_{16}$

$\delta = k_{13}+k_{10}+k_{7}+k_{4}$

From the length of the flag we know it is 33, hence the last block of the msg is '}' padded to 16 bytes. We can xor it from the second last block of ciphertext, to get what would have been the input for the original flag's encryption. And since we know the final ciphertext block, we can get these values of $\alpha,\beta,\gamma,\delta$.
Then all we need to do is subtract these values from the corresponding cipherblock and xor with previous cipherblock and we would get the flag

The solution script is this:

```
from Crypto.Util.Padding import pad,unpad
BLOCK_SIZE = 16

def xor(msg1, msg2):
    return [a ^ b for (a, b) in zip(msg1, msg2)]

ciphertext = open("output.txt", 'r').read().strip()
ciphertext = bytes.fromhex(ciphertext)
cipher = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

plaintext_last_block = pad(b'}', BLOCK_SIZE)

plaintext_last_block = xor(plaintext_last_block, cipher[-2])

offset = [a - b for (a,b) in zip(cipher[-1], plaintext_last_block)]

ans = b''

for i in range(1, 4):
    c_prime = [k for k in cipher[i]]
    m_prime = [(a-b)%256 for (a,b) in zip(c_prime, offset)]
    ans += bytes(xor(bytes(m_prime), cipher[i-1]))

print(unpad(ans, BLOCK_SIZE))

```

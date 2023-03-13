## Problem description
I was unable to solve this problem during the CTF. But the attack idea is simple. We are given a file which has the following code:
```
#!/usr/local/bin/python

from cryptography.hazmat.primitives.asymmetric import rsa
from secrets import randbits

if __name__ == '__main__':
    alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    print("Alice's pk: ", alice.public_key().public_numbers().n, alice.public_key().public_numbers().e)
    m = randbits(256)
    s = pow(m, alice.private_numbers().d, alice.public_key().public_numbers().n)
    print(m, s)
    print("Your key: ")
    n_prime = abs(int(input("n': ")))
    e_prime = abs(int(input("e': ")))
    d_prime = abs(int(input("d': ")))

    # Checks
    x = randbits(256)
    assert alice.public_key().public_numbers().n != n_prime or alice.public_key().public_numbers().e != e_prime
    assert n_prime > s
    assert pow(x, e_prime * d_prime, n_prime) == x
    assert e_prime > 1
    assert pow(s, e_prime, n_prime) == m

    with open('flag.txt', 'r') as f:
        print("Flag: " + f.read().strip())

```
So basically, we are given Alice's public key $(n, e)$ and also a signature $(m, s)$ where $s = m^{d}$ $mod(n)$, and we are asked to compute a new $(n', e', d')$ such that verification of the signature using $e'$ yields the same message.

### Attack idea
Since there is no restriction on $n'$ except that it should be larger than $s$, we can come up with any $n'$ such that the discrete log problem is easy for this $n'$. And using the discrete log problem, we can figure out $e'$ which satisfies $s^{e'}$ $mod(n')$ = $m$. And then we can compute inverse of $e'$ mod $\phi(n)$. Note that $e'$ might not have an inverse always, so we need to run this attack multiple times till it succeeds. 
```
Flag: utflag{hey_wait_signature_forgery_is_illegal}
```

### Exploit

Since this attack makes use of sage, we need to run it as ```sage --python exploit.py```. Also, the attack script is taken from someone's writeup of this challenge
```
from pwn import *
from sage.all import *

while True:
    try:
        conn = remote("puffer.utctf.live", 52548)
        conn.recvline()
        line = conn.recvline().decode().strip().split()
        m, s = int(line[0]), int(line[1])
        print("M: ",m)
        print("S: ", s)
        n = 107**300
        while n < s:
            n *= 107
        e = discrete_log(Mod(m, n), Mod(s, n))
        print("e:",e)
        d = pow(e, -1, euler_phi(n))
        print("d:",d)
        conn.sendlineafter(b"n': ", str(n).encode())
        conn.sendlineafter(b"e': ", str(e).encode())
        conn.sendlineafter(b"d': ", str(d).encode())
        conn.interactive()
        break
    except:
        continue
```
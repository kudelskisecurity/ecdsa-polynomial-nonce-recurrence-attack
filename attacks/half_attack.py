import random
import hashlib
import time
import gmpy2

from binascii import unhexlify
from fastecdsa.curve import secp256k1
from fastecdsa.ecdsa import verify
from fastecdsa.point import Point
from itertools import product

mask_lsb = (1 << 128) - 1
mask_msb = (1 << 256) - 1

def sign(h, k,d):
    R = k*secp256k1.G
    r = R.x
    s = (gmpy2.invert(k, secp256k1.q) * (h + r*d)) % secp256k1.q
    return r, s

def recover_key_lsb(h, s, r, Q):
    s_inv = [gmpy2.invert(s_i, secp256k1.q) for s_i in s]
    h1_msb = h[0] & mask_lsb
    h2_msb = h[1] & mask_lsb
    # Test all the 4 sign possibilities for nonces.
    signs = product([-1, 1], repeat=2)
    a_inv = gmpy2.invert(r[0]*s_inv[0] - r[1]*s_inv[1], secp256k1.q)
    b = h[0]*s_inv[0] - h[1]*s_inv[1]
    for s in signs:
        c = (s[0] * h1_msb - s[1] * h2_msb) << 128
        d = ((c-b) * a_inv) % secp256k1.q
        if int(d) * secp256k1.G == Q:
            break
        else:
            d = None
    return d

def recover_key_msb(h, s, r, Q):
    s_inv = [gmpy2.invert(s_i, secp256k1.q) for s_i in s]
    h1_lsb = h[0] >> 128
    h2_lsb = h[1] >> 128
    # Test all the 4 sign possibilities for nonces.
    signs = product([-1, 1], repeat=2)
    a_inv = gmpy2.invert(r[0]*s_inv[0] - r[1]*s_inv[1], secp256k1.q)
    b = h[0]*s_inv[0] - h[1]*s_inv[1]
    for sign in signs:
        c = (sign[0] * h1_lsb - sign[1] * h2_lsb)
        d = ((c-b) * a_inv) % secp256k1.q
        k = (sign[0] * s_inv[0] * (h[0] + r[0]*d)) % secp256k1.q
        if k & mask_lsb == h1_lsb:
            if int(d) * secp256k1.G == Q:
                break
        else:
            d = None
    return d

def nonce_lsb(h, d):
    return ((h << 128) & mask_msb) | (d >> 128)

def nonce_msb(h, d):
    return ((d >> 128) << 128) | (h >> 128)

def example():
    # Keys
    d = random.randint(0, (1 << 256) - 1)
    print(d)
    Q = d*secp256k1.G

    # messages
    m1 = b"Nobody inspects the spammish repetition"
    h1 = hashlib.sha256(m1).digest()
    h1_int = int.from_bytes(h1, "big")

    m2 = b"Procrastinating on something important is choosing to delay a better future."
    h2 = hashlib.sha256(m2).digest()
    h2_int = int.from_bytes(h2, "big")
    
    # Flaw nonce generation
    k1 = nonce_msb(h1_int, d)
    k2 = nonce_msb(h2_int, d)

    # Sign
    r1,s1 = sign(h1_int, k1, d)
    r2,s2 = sign(h2_int, k2, d)

    # Verify
    print(verify((r1,s1), m1 , Q, secp256k1))

    start = time.time()
    dd = recover_key_msb([h1_int, h2_int], [s1, s2], [r1, r2], Q)
    end = time.time()
    print(end - start)
    print(dd)
    print(dd == d)

if __name__ == '__main__':
    example()
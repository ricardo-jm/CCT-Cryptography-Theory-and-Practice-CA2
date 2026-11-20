
# Nouce reuse attacks demonstration:
# 1. Keystream-reuse (XOR) attack
# 2. Joux forbidden attack (recover H + forge tag)

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sage.all import GF

#-begin-forbidden attack
#The following code was resued from the original forbidden attack and uses SageMath to perform the polynomial arithmetic as found in:
# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py

x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)

def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])

def _from_gf2e(p):
    n = 0
    polynomial = p.polynomial()
    for i in range(128):
        n <<= 1
        n |= int(polynomial[i])
    return n

def _ghash(h, a, c):
    la = len(a)
    lc = len(c)
    p = gf2e(0)
    for i in range(la // 16):
        p += _to_gf2e(int.from_bytes(a[16*i:16*(i+1)], byteorder="big"))
        p *= h
    if la % 16 != 0:
        p += _to_gf2e(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        p *= h
    for i in range(lc // 16):
        p += _to_gf2e(int.from_bytes(c[16*i:16*(i+1)], byteorder="big"))
        p *= h
    if lc % 16 != 0:
        p += _to_gf2e(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        p *= h
    p += _to_gf2e(((8 * la) << 64) | (8 * lc))
    p *= h
    return p

def recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
    """Recover candidate authentication keys H (Joux forbidden attack)."""
    h = gf2e["h"].gen()
    p1 = _ghash(h, a1, c1) + _to_gf2e(int.from_bytes(t1, byteorder="big"))
    p2 = _ghash(h, a2, c2) + _to_gf2e(int.from_bytes(t2, byteorder="big"))
    for candidate, _ in (p1 + p2).roots():
        yield candidate

def forge_tag(h, a, c, t, target_a, target_c):
    """Forge a valid tag for (target_a, target_c) using a recovered H."""
    ghash = _from_gf2e(_ghash(h, a, c))
    target_ghash = _from_gf2e(_ghash(h, target_a, target_c))
    return (ghash ^ int.from_bytes(t, byteorder="big") ^ target_ghash).to_bytes(16, byteorder="big")
#-end-forbidden attack


# ------------------------------------------------------------
# Vulnerability: the same nonce used in two encrypted messages
# ------------------------------------------------------------

# The encryption and decryption used was sourced from https://mojoauth.com/security-guides/serpent-256-encryption--python
key   = AESGCM.generate_key(bit_length=256)
# reused nouce
nonce = os.urandom(12)          

aesgcm = AESGCM(key)

# Associated data (AAD): data that is authenticated but not encrypted.
aad_1 = b"header-1"
aad_2 = b"header-2"

# known by the attacker
plain_text_1 = b"secret message 1"   
# not known by the attacker
plain_text_2 = b"secret message 2"   

# Encrypt both messages using the same nonce
full1 = aesgcm.encrypt(nonce, plain_text_1, aad_1)
# Uncomment the following line to use a new nonce for the second message, which would prevent the attacks.
#nonce = os.urandom(12)        
full2 = aesgcm.encrypt(nonce, plain_text_2, aad_2)

#c1, c2 are ciphertext
#t1, t2 are the authentication tags (128 bit/16 bytes)
c1, t1 = full1[:-16], full1[-16:]
c2, t2 = full2[:-16], full2[-16:]

# Nouce reuse XOR attack:
print()
print("Attack 1 - Nouce-reuse (XOR) attack: ")
# C1 XOR C2 = P1 XOR P2  →  P2 = C1 XOR C2 XOR P1 : If one of the plaintexts is known, the other can be recovered.
print("C1 XOR C2 = P1 XOR P2  --->  P2 = C1 XOR C2 XOR P1")
recovered_plain_text_2 = bytes(x ^ y ^ z for x, y, z in zip(c1, c2, plain_text_1))
print("Original  Plain text 2 :", plain_text_2)
print("Recovered Plain text 2 :", recovered_plain_text_2)
if (recovered_plain_text_2 == plain_text_2):
    print("Original Plain text 2 is the same as Recovered Plain text 2")
else:
    print("Original Plain text 2 is different from Recovered Plain text 2")
print()

# Forbidden attack (Joux attack):
print("Attack 2 - Joux forbidden attack (recover possible auth keys + forge auth tag): ")
possible_auth_keys = list(recover_possible_auth_keys(aad_1, c1, t1, aad_2, c2, t2))
print(f"Found {len(possible_auth_keys)} possible auth keys H")

# Try each possible auth key and forge a tag for a new message
target_pt  = b"forged message"
target_aad = b"forged header"

# New ciphertext encrypted with the same nonce. 
target_full = aesgcm.encrypt(nonce, target_pt, target_aad)
target_c    = target_full[:-16]
real_tag    = target_full[-16:]

for i, h in enumerate(possible_auth_keys):
    forged = forge_tag(h, aad_1, c1, t1, target_aad, target_c)
    if (forged == real_tag):
        print(f"For possible authentication tag {i} the forged tag and the real tag are the same. ")
    else:
        print(f"For possible authentication tag {i} the forged tag and the real tag are different. ")
    print()
    print(f"Forget Tag: {forged}")
    print(f"Real Tag  : {real_tag}")
    print("---------------------------")
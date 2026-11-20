
# This script uses AES-GCM encryption to encrypt two messages in a secure way by encrypting them with different nonces.


import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key   = AESGCM.generate_key(bit_length=256)
# first nonce
nonce = os.urandom(12)          

aesgcm = AESGCM(key)

# Associated data (AAD): data that is authenticated but not encrypted.
aad_1 = b"header-1"
aad_2 = b"header-2"

# Plain text 1
plain_text_1 = b"secret message 1"  
print("Plain text 1 :", plain_text_1) 
# Plain text 2
plain_text_2 = b"secret message 2"   
print("Plain text 2 :", plain_text_2)

# Encrypt and decrypt the first message with initial nonce
full1 = aesgcm.encrypt(nonce, plain_text_1, aad_1)
decrypted_plain_text_1 = aesgcm.decrypt(nonce, full1, aad_1)
print("Decrypted Plain text 1 :", decrypted_plain_text_1)

# Encrypt the second message with a new nonce
nonce = os.urandom(12) 
full2 = aesgcm.encrypt(nonce, plain_text_2, aad_2)
decrypted_plain_text_2 = aesgcm.decrypt(nonce, full2, aad_2)
print("Decrypted Plain text 2 :", decrypted_plain_text_2)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, json, secrets

AES_KEY_FILE = "aes_key.bin"

def load_or_generate_aes_key():
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, "rb") as f:
            return f.read()
    key = secrets.token_bytes(32)  # AES-256
    with open(AES_KEY_FILE, "wb") as f:
        f.write(key)
    return key

def get_aes_key():
    if os.path.exists(AES_KEY_FILE):
        with open(AES_KEY_FILE, 'r') as f:
            return bytes.fromhex(json.load(f)['key'])
    key = os.urandom(32)
    with open(AES_KEY_FILE, 'w') as f:
        json.dump({'key': key.hex()}, f)
    return key

def aes_encrypt(plaintext):
    AES_KEY = load_or_generate_aes_key()
    nonce = secrets.token_bytes(12)  # 12 bytes for AES GCM
    encryptor = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b"AES1" + nonce + encryptor.tag + ciphertext



def aes_decrypt(data):
    AES_KEY = load_or_generate_aes_key()
    if not data.startswith(b"AES1"):
        raise ValueError("Invalid AES data")
    nonce = data[4:16]
    tag = data[16:32]
    ciphertext = data[32:]
    decryptor = Cipher(algorithms.AES(AES_KEY), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


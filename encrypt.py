from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = 0
iv = 0
text = ""
with open("settings", "rb") as file:
    text = file.read()
with open("key.txt", "rb") as file:
    key = file.readline().strip()
    iv = file.readline().strip()
    print(key, iv)


def encrypt(plaintext, key, iv):
    pad = padding.PKCS7(algorithms.AES.block_size).padder()
    pad_plaintext = pad.update(plaintext) + pad.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ct = encryptor.update(pad_plaintext) + encryptor.finalize()

    return ct


def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpad = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpad.update(padded_plain) + unpad.finalize()

    return plaintext


with open("settings", "wb") as file:
    file.write(encrypt(text, key, iv))

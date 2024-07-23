import os


def generate_AES_key():
    key = os.urandom(16)  # 128 bits
    iv = os.urandom(16)
    with open("key.txt", "wb") as file:
        file.write(key + b'\n')  # adding newlines to make it easier to strip
        file.write(iv + b'\n')


def read_AES_key():
    with open("key.txt", "rb") as file:
        key = file.readline().strip()
        iv = file.readline().strip()
        print(key, iv)


generate_AES_key()
read_AES_key()

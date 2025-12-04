from Cryptodome.Cipher import AES

from Cryptodome.Random import get_random_bytes

import hashlib

BUFFER_SIZE = 64 * 1024  # 64KB

def generate_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_file(password, input_file, output_file):
    key = generate_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        fout.write(iv)
        while chunk := fin.read(BUFFER_SIZE):
            fout.write(cipher.encrypt(chunk))

    return True

def decrypt_file(password, input_file, output_file):
    key = generate_key(password)

    with open(input_file, "rb") as fin:
        iv = fin.read(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)

        with open(output_file, "wb") as fout:
            while chunk := fin.read(BUFFER_SIZE):
                fout.write(cipher.decrypt(chunk))

    return True



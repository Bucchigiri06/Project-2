from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
from metadata import create_metadata, serialize_metadata, deserialize_metadata, calculate_hash

BUFFER_SIZE = 64 * 1024

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()  # AES-256

def encrypt_file(password, input_file, output_file):
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    metadata = create_metadata(input_file)
    meta_bytes = serialize_metadata(metadata)

    with open(input_file, "rb") as fin, open(output_file, "wb") as fout:
        fout.write(iv)
        fout.write(len(meta_bytes).to_bytes(4, "big"))
        fout.write(cipher.encrypt(meta_bytes))

        while chunk := fin.read(BUFFER_SIZE):
            fout.write(cipher.encrypt(chunk))

    return True

def decrypt_file(password, input_file, output_file):
    key = derive_key(password)

    with open(input_file, "rb") as fin:
        iv = fin.read(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)

        meta_len = int.from_bytes(fin.read(4), "big")
        metadata = deserialize_metadata(cipher.decrypt(fin.read(meta_len)))

        with open(output_file, "wb") as fout:
            while chunk := fin.read(BUFFER_SIZE):
                fout.write(cipher.decrypt(chunk))

    # Integrity check
    new_hash = calculate_hash(output_file)
    if new_hash != metadata["hash"]:
        raise ValueError("❌ Integrity verification failed. File may be tampered.")

    return metadata

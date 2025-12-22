import hashlib
import json
import os
import time

BUFFER_SIZE = 64 * 1024  # 64KB

def calculate_hash(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            sha.update(chunk)
    return sha.hexdigest()

def create_metadata(file_path):
    return {
        "original_name": os.path.basename(file_path),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hash": calculate_hash(file_path)
    }

def serialize_metadata(metadata: dict) -> bytes:
    return json.dumps(metadata).encode()

def deserialize_metadata(data: bytes) -> dict:
    return json.loads(data.decode())

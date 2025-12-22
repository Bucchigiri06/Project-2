# Secure File Storage System with AES-256

## Overview

The Secure File Storage System is a Python-based application designed to protect sensitive files using strong cryptographic techniques. The system encrypts files using **AES-256**, securely stores encrypted metadata, and verifies file integrity using **SHA-256 hashing** to detect tampering or unauthorized modifications.

This project follows industry-recommended cryptographic practices and is intended for academic and educational purposes.

---

## Features

* AES-256 symmetric file encryption
* Password-based key derivation
* Secure random Initialization Vector (IV)
* Encrypted metadata storage (file name, timestamp, hash)
* SHA-256 integrity verification
* Tamper and wrong-password detection
* User-friendly graphical interface
* Local secure file storage using `.enc` format

---

## Technologies Used

* **Language:** Python
* **Cryptography Library:** PyCryptodome
* **GUI Framework:** Tkinter
* **Hash Algorithm:** SHA-256

---

## Project Structure

```
secure_file_storage/
│
├── crypto_engine.py   # AES encryption/decryption logic
├── metadata.py        # Metadata and hash handling
├── gui.py             # Graphical User Interface
└── main.py            # Application entry point
```

---

## Installation

Install the required dependency:

```bash
pip install pycryptodome
```

---

## How to Run

Run the application using:

```bash
python main.py
```

---

## Usage

1. Launch the application
2. Select a file to encrypt or decrypt
3. Enter a secure password
4. Click **Encrypt File** or **Decrypt File**

---

## Output

* **Encrypted file:** `filename.ext.enc`
* **Decrypted file:** `filename.ext_decrypted`

---

## Security Notes

* Files are encrypted locally; no data is sent over the network
* Metadata is encrypted and stored inside the encrypted file
* Integrity verification prevents tampering or unauthorized access

---

## Disclaimer

This project is intended strictly for educational and authorized use only.

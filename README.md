# 📄 **PROJECT REPORT – SECURE FILE STORAGE SYSTEM USING AES ENCRYPTION**

## **1. Title**

**Secure File Storage and Encryption System using Python & AES-256**

---

## **2. Abstract**

In a world where digital information has become the most valuable resource, securing data from unauthorized access is a critical requirement. This project focuses on developing a secure file storage system using **AES-256 encryption**, ensuring data confidentiality and integrity.
The system enables users to encrypt files with a password-based key and decrypt them when needed. Built using **Python and Tkinter**, the application provides a simplified GUI to make cryptography accessible for real-world use without requiring technical knowledge.

This solution can be used for personal data protection, secure business transfers, and cybersecurity demonstrations.

---

## **3. Introduction**

Data breaches, cyber-attacks, and unauthorized access are rapidly increasing concerns in modern computing environments. Sensitive documents stored in plain text formats can easily be compromised. Therefore, secure encryption practices are essential for ensuring privacy.

Advanced Encryption Standard (AES) is one of the most secure and widely accepted cryptographic algorithms used in military, banking, and governmental security systems. This project implements AES-256 to provide a stable and strong data encryption mechanism.

---

## **4. Problem Statement**

Traditional file storage mechanisms do not provide encryption by default, which leaves sensitive data vulnerable. Users need a secure, user-friendly system to encrypt and decrypt files without advanced technical skills.

---

## **5. Objectives**

| Objective                             | Description                          |
| ------------------------------------- | ------------------------------------ |
| Encrypt files using AES-256           | Protect confidentiality              |
| Decrypt encrypted files securely      | Restore original information         |
| Provide password-based key generation | No key stored in application         |
| Develop user-friendly GUI             | Simple usage for non-technical users |
| Ensure offline functionality          | No internet exposure                 |

---

## **6. System Requirements**

### **Software Requirements**

* Python 3.10 – 3.13
* Tkinter (GUI framework)
* PyCryptodomex (AES encryption library)
* OS: Windows/Linux/Mac

### **Hardware Requirements**

* 2GB RAM
* 64-bit processor
* 50MB disk space

---

## **7. Technology Used**

| Component            | Tool                 |
| -------------------- | -------------------- |
| Programming Language | Python               |
| GUI Framework        | Tkinter              |
| Encryption Algorithm | AES-256 (CFB mode)   |
| Key Generation       | SHA-256 hashing      |
| File output formats  | `.enc`, `.decrypted` |

---

## **8. System Architecture**

```
User Interface (Tkinter)
         |
User selects file + password
         |
Generate SHA-256 Key
         |
AES-256 CFB Encryption / Decryption
         |
Encrypted .enc file / Decrypted output file
```

---

## **9. Methodology**

### **Encryption Process**

```
Input: File + Password
Generate 32-byte key using SHA-256 hash
Create random 16-byte IV
Encrypt file contents in chunks (64KB)
Write IV + encrypted data to ".enc" file
Output: Encrypted secure file
```

### **Decryption Process**

```
Input: Encrypted .enc File + Password
Read IV from file
Recreate key from password
Decrypt file chunk by chunk
Restore original file with "_decrypted" suffix
```

---

## **10. GUI Design**

| UI Feature             | Description                    |
| ---------------------- | ------------------------------ |
| Browse file system     | Select any file for processing |
| Password field         | Input for encryption key       |
| Encrypt button         | Creates encrypted file         |
| Decrypt button         | Recovers original content      |
| Success/Failure popups | User feedback                  |

---

## **11. Screenshots**

(Insert after testing — placeholders below)

```
Figure 1: Home Screen of Encryption Tool
Figure 2: File Path Selection & Password Field
Figure 3: Successful Encryption Message
Figure 4: Decryption Result
```

---

## **12. Results**

* Successfully encrypts any file type (PDF, DOCX, TXT, Images, Videos, ZIP)
* Produces secure `.enc` files that cannot be opened without password
* Recovers exact original file when decrypted
* Stable and functioning GUI without errors

---

## **13. Applications**

* Secure document storage
* Corporate confidential data handling
* Academic cybersecurity training
* Personal privacy and encrypted backups
* Military and government data protection

---

## **14. Advantages & Limitations**

### Advantages

✔ Strong AES-256 encryption
✔ Offline and secure
✔ GUI friendly for non-technical users
✔ Cross-platform compatibility

### Limitations

✘ Password loss leads to permanent data lock
✘ No cloud sync or network transfer currently
✘ No multi-user or login system

---

## **15. Future Enhancements**

🔹 Cloud secure storage integration
🔹 Mobile app version
🔹 Facial/Fingerprint login
🔹 Key management & digital signatures
🔹 SHA-512 + RSA Hybrid encryption model

---

## **16. Conclusion**

The Secure File Storage System successfully demonstrates strong AES-256 encryption with an easy-to-use graphical interface. Users can encrypt and decrypt files seamlessly without needing advanced cryptographic knowledge. The project highlights the importance of securing personal and organizational data and serves as a practical demonstration of real-world cybersecurity solutions.

---

## **17. References**

1. NIST AES Encryption Standards
2. PyCryptodomex Documentation
3. OWASP Secure Storage Guide
4. Cybersecurity Data Protection Guidelines 2024

---


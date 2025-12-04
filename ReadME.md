# **Datasec | AES-256 File Encryptor**

**Datasec | AES-256 File Encryptor** is a secure file encryption application designed for Data Science workflows. It allows users to encrypt sensitive tabular data (CSV/Excel) using **AES-256 (CBC Mode)** authenticated with **HMAC-SHA256** for data integrity.

This project was developed for the **Data Security Course** (Tugas Keamanan Data) to demonstrate the implementation of robust cryptographic primitives in a user-friendly application.

## **Live Demo: \[https://datasec-aes256-cryptography.streamlit.app/\](https://datasec-aes256-cryptography.streamlit.app/**

## **✨ \[Key Features\]**

* **Strong Encryption:** Uses **AES-256-CBC** (Advanced Encryption Standard) to secure data.  
* **Integrity Check:** Implements **Encrypt-then-MAC** architecture using **HMAC-SHA256**. The application detects and rejects any tampered or corrupted files before decryption.  
* **Secure Key Management:** Keys are derived using **PBKDF2-HMAC-SHA256** with **200,000 iterations** and random Salt. We use a **Split-Key** strategy (separate keys for Encryption and HMAC).  
* **Data-Analyst Friendly:** Supports .csv and .xlsx (Excel) files. Automatically sanitizes Excel inputs into standard CSV format.  
* **Audit Trail:** Records encryption/decryption history (timestamp, file hash) without storing the actual sensitive data in memory.  
* **Modern UI:** Built with **Streamlit** for a responsive and clean web interface.

## **🛠️ \[Technical Architecture\]**

### **1\. Encryption Flow**

The application follows the **Encrypt-then-MAC** construction to ensure both confidentiality and integrity.

1. **Key Derivation:**  
   * Input: User Password \+ Random Salt (16 bytes).  
   * Algorithm: PBKDF2 (200,000 iterations).  
   * Output: 64 bytes $\\rightarrow$ Split into **Enc\_Key** (32 bytes) and **MAC\_Key** (32 bytes).  
2. **Encryption:**  
   * Data is padded using **PKCS7**.  
   * Encrypted using **AES-256-CBC** with a random IV.  
3. **integrity:**  
   * HMAC-SHA256 is calculated over the header, salt, IV, and ciphertext.

### **2\. Encrypted File Structure (.enc)**

Every encrypted file produced by this app follows a strict binary structure:

| Component | Size | Description |
| :---- | :---- | :---- |
| **Magic Header** | 9 Bytes | DATASEC02 (File Signature) |
| **Version** | 1 Byte | Format Version (e.g., 0x01) |
| **Salt** | 16 Bytes | Random salt for KDF |
| **IV** | 16 Bytes | Initialization Vector for AES-CBC |
| **Ciphertext** | Variable | The encrypted data |
| **HMAC Tag** | 32 Bytes | SHA-256 Integrity Signature |

## **📂 Project Structure**

SecureDS-Vault/  
├── backend/  
│   ├── crypto\_backend.py   \# Core cryptographic logic (AES, HMAC, KDF)  
│   └── crypto\_dummy.py     \# Dummy data generator for unit testing  
├── frontend/  
│   ├── Home.py             \# Main Streamlit UI application  
│   └── pages/  
│       └── Log.py          \# History/Audit Log page  
└── requirements.txt        \# Python dependencies

## **🚀 Installation & Usage**

### **Prerequisites**

* Python 3.8 or higher.  
* Anaconda Distribution (Preferably)

### **1\. Clone the Repository**

git clone \[https://github.com/yourusername/SecureDS-Vault.git\](https://github.com/yourusername/SecureDS-Vault.git)  
cd SecureDS-Vault

### **2\. Install Dependencies**

It is recommended to use a virtual environment.

pip install \-r requirements.txt

### **3\. Run the Application**

Navigate to the root directory and run Streamlit:

streamlit run frontend/Home.py

The application will open in your browser at http://localhost:8501.

## **⚠️ \[Disclaimer\!\]**

This application is created for **educational purposes** as part of a university assignment. While it implements standard cryptographic libraries (cryptography), it has not been audited by third-party security professionals. Use with caution for production data.

**Developed by \[Keamanannya Data Group\] \- DS-47-02**  
**Farand Diy Dat Mahazalfaa**
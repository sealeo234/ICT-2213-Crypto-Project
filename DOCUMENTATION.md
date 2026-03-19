# VaulnZero: Enterprise End-to-End Encrypted File Vault

VaulnZero is a secure, zero-knowledge file storage and sharing application. It is designed to ensure that the server infrastructure acting as the storage provider never has access to plaintext files or user private keys. All cryptographic operations—including encryption, decryption, key wrapping, and digital signatures—are executed client-side within the user's browser using the Web Crypto API.

## Key Features

* **Zero-Knowledge Architecture:** The backend only stores encrypted blobs and public key material. It cannot read file contents or forge signatures.
* **Client-Side Cryptography:** Fully utilizes the native browser Web Crypto API for high-performance, secure operations.
* **End-to-End Encrypted Sharing:** Granular access control using RSA key wrapping allows users to share files without exposing the underlying symmetric keys to the server.
* **Cryptographic Authenticity:** ECDSA signatures verify that a file has not been tampered with while at rest on the server.
* **Local Key Custody:** Private keys are securely managed via IndexedDB and can be exported/imported as AES-encrypted `.pem` identity containers.
* **Seamless Key Rotation:** Automated workflows to generate new key pairs and seamlessly re-wrap all accessible files.

## Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Framework** | Python / Flask | RESTful API and routing. |
| **Database** | SQLite / SQLAlchemy | Relational storage for users, file metadata, and access lists. |
| **Frontend** | HTML5 / Tailwind CSS | Responsive, glassmorphism-styled user interface. |
| **Cryptography** | Web Crypto API | Native browser execution of AES, RSA, and ECDSA. |

## Documentation

For more detailed information, please refer to the following guides:
* [Security Architecture & Workflows](ARCHITECTURE.md)
* [Local Development & Setup Guide](DEVELOPMENT.md)
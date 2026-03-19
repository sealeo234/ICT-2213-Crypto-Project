# ICT2213 Applied Cryptography Project

## VaulnZero

VaulnZero is a secure, zero-knowledge file storage and sharing web application. It is designed to ensure that the server infrastructure acting as the storage provider never has access to plaintext files or user private keys. All cryptographic operations—including encryption, decryption, key wrapping, and digital signatures—are executed client-side within the user's browser using the Web Crypto API.

## Key Features

* **Zero-Knowledge Architecture:** The backend only stores encrypted blobs and public key material. It cannot read file contents or forge signatures.
* **Client-Side Cryptography:** Fully utilizes the native browser Web Crypto API for high-performance, secure operations.
* **End-to-End Encrypted Sharing:** Granular access control using RSA key wrapping allows users to share files without exposing the underlying symmetric keys to the server.
* **Cryptographic Authenticity:** ECDSA signatures verify that a file has not been tampered with while at rest on the server.
* **Local Key Custody:** Private keys are securely managed via IndexedDB and can be exported/imported as AES-encrypted `.pem` identity containers.
* **Seamless Key Rotation:** Automated workflows to generate new key pairs and seamlessly re-wrap all accessible files.

# Documentation

## Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Framework** | Python / Flask | RESTful API and routing. |
| **Database** | SQLite / SQLAlchemy | Relational storage for users, file metadata, and access lists. |
| **Frontend** | HTML5 / Tailwind CSS | Responsive, glassmorphism-styled user interface. |
| **Cryptography** | Web Crypto API | Native browser execution of AES, RSA, and ECDSA. |

## Database Schema

The SQLite database (`users.db`) relies on three primary models:

* **`User`**: Stores identity metadata.
    * Contains the hashed login password, UUID, RSA `public_key`, and ECDSA `signing_public_key`.
* **`VaultFile`**: Stores file metadata.
    * Contains the file size, filename, `owner_uuid`, encryption `iv`, and signature data (`signature`, `signature_alg`, `signer_public_key`).
* **`FileKey`**: Maps users to files.
    * Contains the `file_id`, `recipient_uuid`, and the RSA-encrypted `wrapped_key` specific to that recipient.

## Local Setup Instructions

### Prerequisites
* Python 3.8+
* A modern web browser with Web Crypto API support (Chrome, Firefox, Edge, Safari).
* An Internet connection

### Installation Steps

1. **Clone the repository and navigate to the directory:**
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install the required Python dependencies:**
   *(Note: `pyOpenSSL` is required to run Flask with the `adhoc` SSL context).*
   ```bash
   pip install Flask Flask-SQLAlchemy Flask-Login Flask-CORS Werkzeug pyOpenSSL
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

5. **Access the application:**
   Open your browser and navigate to `https://127.0.0.1`. 
   
   > **Important Note:** Because client-side cryptography requires a secure context, the Flask app is configured to run with `ssl_context="adhoc"`. Your browser will warn you about a self-signed certificate. You must bypass this warning to test locally.

# Security Architecture & Core Workflows

VaulnZero employs a hybrid cryptographic approach to balance the speed of symmetric encryption with the secure key distribution of asymmetric encryption.

## 🔐 Security Architecture

* **File Encryption (Symmetric):** * **Algorithm:** AES-GCM (256-bit).
    * **Mechanism:** Every uploaded file is encrypted with a newly generated, unique File Encryption Key (FEK) and a random 12-byte Initialization Vector (IV).
* **Key Wrapping (Asymmetric):** * **Algorithm:** RSA-OAEP (4096-bit, SHA-256).
    * **Mechanism:** The AES FEK is never stored in plaintext. It is encrypted ("wrapped") using the RSA public key of the file owner and any authorized recipients. 
* **Authenticity & Integrity (Signatures):** * **Algorithm:** ECDSA (P-256 curve, SHA-256 hash).
    * **Mechanism:** The file's IV concatenated with its ciphertext is signed by the uploader's private ECDSA key. Upon download, the client verifies this signature against the uploader's public key before attempting decryption.
* **Identity Container Encryption:** * **Algorithm:** AES-GCM (256-bit) derived via PBKDF2 (100,000 iterations).
    * **Mechanism:** User private keys are encrypted locally using a user-provided passphrase before being exported as `.pem` backups.

## 🔄 Core Workflows

### 1. Account Initialization & Registration
When a user registers, the browser generates the RSA and ECDSA key pairs locally. The public keys are sent to the server. The user is forced to create a passphrase to encrypt their private keys into a `.pem` file, which is downloaded as a backup. The private keys are then temporarily held in `sessionStorage` and permanently migrated to the browser's `IndexedDB`.

### 2. Secure File Upload
1. A random AES-256 FEK and IV are generated.
2. The file is encrypted locally using the FEK.
3. The FEK is wrapped using the uploader's RSA public key.
4. The IV and Ciphertext are concatenated and signed using the uploader's ECDSA private key.
5. The encrypted file, wrapped key, IV, and signature are transmitted to the Flask backend.

### 3. File Download & Verification
1. The client requests the encrypted file blob, IV, wrapped key, and signature metadata from the server.
2. The client verifies the ECDSA signature against the payload to ensure integrity.
3. If verified, the client unwraps the FEK using their local RSA private key (loaded from IndexedDB).
4. The file is decrypted locally, and a blob URL is generated to trigger the browser download.

### 4. Access Control (Sharing)
To grant access to another user, the file owner:
1. Retrieves their own wrapped FEK from the server and unwraps it locally.
2. Retrieves the target user's RSA public key.
3. Wraps the FEK using the target user's public key.
4. Submits the newly wrapped key back to the server.
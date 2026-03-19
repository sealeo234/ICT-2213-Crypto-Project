# Local Development & Setup Guide

This guide covers the database schema and instructions for running the VaulnZero application on your local machine.

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
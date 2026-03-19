/**
 * @file key-wrapping.js
 * @description RSA-OAEP key import, generation, and FEK wrap/unwrap helpers.
 */

/**
 * Imports a base64-encoded PKCS8 RSA private key for OAEP decryption.
 *
 * @param {string} base64 - Base64 PKCS8 private key.
 * @returns {Promise<CryptoKey>} Imported RSA private key.
 */
async function importEncryptionPrivateKey(base64) {
    // Import as decrypt-only to keep private key capabilities minimal.
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        binary.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
}

/**
 * Imports a base64-encoded SPKI RSA public key for OAEP encryption.
 *
 * @param {string} base64 - Base64 SPKI public key.
 * @returns {Promise<CryptoKey>} Imported RSA public key.
 */
async function importEncryptionPublicKey(base64) {
    // Import as encrypt-only because this key is used to wrap FEKs for recipients.
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "spki",
        binary.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
}

/**
 * Generates a new RSA-OAEP key pair for FEK wrapping operations.
 *
 * @returns {Promise<CryptoKeyPair>} Generated encryption key pair.
 */
async function generateEncryptionKeyPair() {
    // 4096-bit RSA-OAEP improves long-term margin for wrapped FEK confidentiality.
    return crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
}

/**
 * Wraps a raw FEK for a recipient using a base64-encoded RSA public key.
 *
 * @param {string} recipientPublicKeyBase64 - Base64 recipient SPKI public key.
 * @param {ArrayBuffer} rawAes - Raw FEK bytes.
 * @returns {Promise<ArrayBuffer>} Wrapped FEK bytes.
 */
async function wrapRawKeyForRecipient(recipientPublicKeyBase64, rawAes) {
    const recipientPubKey = await importEncryptionPublicKey(recipientPublicKeyBase64);
    // Wrap raw FEK bytes so server never receives FEKs in plaintext.
    return crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPubKey,
        rawAes
    );
}

/**
 * Wraps a raw FEK with an already-imported recipient RSA public key.
 *
 * @param {CryptoKey} recipientPubKey - Imported recipient public key.
 * @param {ArrayBuffer} rawAes - Raw FEK bytes.
 * @returns {Promise<ArrayBuffer>} Wrapped FEK bytes.
 */
async function wrapRawKeyWithPublicKey(recipientPubKey, rawAes) {
    return crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPubKey,
        rawAes
    );
}

/**
 * Unwraps a wrapped FEK for the owner using a base64-encoded private key.
 *
 * @param {string} ownerPrivateKeyBase64 - Base64 owner PKCS8 private key.
 * @param {ArrayBuffer} wrappedKeyBuf - Wrapped FEK bytes.
 * @returns {Promise<ArrayBuffer>} Unwrapped raw FEK bytes.
 */
async function unwrapRawKeyForOwner(ownerPrivateKeyBase64, wrappedKeyBuf) {
    const ownerPrivateKey = await importEncryptionPrivateKey(ownerPrivateKeyBase64);
    // Only the holder of the matching private key can recover the FEK.
    return crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        ownerPrivateKey,
        wrappedKeyBuf
    );
}

/**
 * Unwraps a base64-encoded wrapped FEK for the owner.
 *
 * @param {string} ownerPrivateKeyBase64 - Base64 owner PKCS8 private key.
 * @param {string} wrappedKeyBase64 - Base64 wrapped FEK bytes.
 * @returns {Promise<ArrayBuffer>} Unwrapped raw FEK bytes.
 */
async function unwrapRawKeyFromBase64(ownerPrivateKeyBase64, wrappedKeyBase64) {
    return unwrapRawKeyForOwner(ownerPrivateKeyBase64, base64ToArrayBuffer(wrappedKeyBase64));
}

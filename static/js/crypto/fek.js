/**
 * @file fek.js
 * @description File encryption key derivation and AES-GCM encryption/decryption helpers.
 */

/**
 * Derives an AES-GCM key from a password using PBKDF2.
 *
 * @param {string} password - User-provided password.
 * @param {Uint8Array} salt - Random PBKDF2 salt.
 * @param {Array<KeyUsage>} [usages=["encrypt", "decrypt"]] - Key usages for the derived key.
 * @returns {Promise<CryptoKey>} Derived AES-GCM key.
 */
async function deriveKey(password, salt, usages = ["encrypt", "decrypt"]) {
    const enc = new TextEncoder();
    // PBKDF2 is used only to derive a symmetric key from user password material.
    const baseKey = await crypto.subtle.importKey(
        "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        usages
    );
}

/**
 * Encrypts plaintext bytes using a password-derived AES-GCM key.
 *
 * @param {ArrayBuffer|Uint8Array} plaintextBytes - Bytes to encrypt.
 * @param {string} password - Password used for PBKDF2 key derivation.
 * @returns {Promise<{salt: Uint8Array, iv: Uint8Array, ciphertext: ArrayBuffer}>} Encryption bundle.
 */
async function encryptPayload(plaintextBytes, password) {
    // Salt and IV are generated per export so encrypted containers are non-deterministic.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, ["encrypt","decrypt"]);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes);
    return { salt, iv, ciphertext };
}

/**
 * Decrypts a base64 payload previously produced by encrypted PEM container serialization.
 *
 * @param {string} encryptedPemBase64 - Base64 payload containing salt, IV, and ciphertext.
 * @param {string} password - Password used to derive the decryption key.
 * @returns {Promise<ArrayBuffer>} Decrypted plaintext bytes.
 */
async function decryptPem(encryptedPemBase64, password) {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedPemBase64));
    // Serialized layout: [0..15]=salt, [16..27]=iv, [28..]=ciphertext.
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);
    const key = await deriveKey(password, salt, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return decrypted;
}

/**
 * Encrypts file bytes with a newly generated AES-GCM file encryption key (FEK).
 *
 * @param {ArrayBuffer} fileBuf - Plain file bytes.
 * @returns {Promise<{iv: Uint8Array, ciphertext: ArrayBuffer, rawAes: ArrayBuffer}>} FEK encryption outputs.
 */
async function encryptFileWithFek(fileBuf) {
    // FEK is a per-file AES key so large file encryption stays efficient.
    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = generateRandomBytes(12);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, fileBuf);
    const rawAes = await crypto.subtle.exportKey("raw", aesKey);
    return { iv, ciphertext, rawAes };
}

/**
 * Imports a raw AES key for decryption usage.
 *
 * @param {ArrayBuffer} rawAes - Raw AES key bytes.
 * @returns {Promise<CryptoKey>} AES-GCM CryptoKey for decryption.
 */
async function importFekForDecrypt(rawAes) {
    return crypto.subtle.importKey(
        "raw",
        rawAes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

/**
 * Decrypts ciphertext bytes using AES-GCM and a raw FEK.
 *
 * @param {Uint8Array} iv - AES-GCM initialization vector.
 * @param {ArrayBuffer} ciphertext - Ciphertext bytes.
 * @param {ArrayBuffer} rawAes - Raw AES key bytes.
 * @returns {Promise<ArrayBuffer>} Decrypted plaintext bytes.
 */
async function decryptFileWithFek(iv, ciphertext, rawAes) {
    const aesKey = await importFekForDecrypt(rawAes);
    // AES-GCM decrypt also authenticates ciphertext+tag and throws on tampering.
    return crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        ciphertext
    );
}

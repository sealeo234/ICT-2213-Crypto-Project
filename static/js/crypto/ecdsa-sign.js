/**
 * @file ecdsa-sign.js
 * @description ECDSA P-256 key import, generation, signing, and verification helpers.
 */

/**
 * Imports a base64-encoded PKCS8 ECDSA private key for signing.
 *
 * @param {string} base64 - Base64 PKCS8 private key.
 * @returns {Promise<CryptoKey>} Imported private key.
 */
async function importSigningPrivateKey(base64) {
    // Web Crypto expects raw bytes, so convert base64 PKCS8 into an ArrayBuffer first.
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        binary.buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
    );
}

/**
 * Imports a base64-encoded SPKI ECDSA public key for signature verification.
 *
 * @param {string} base64 - Base64 SPKI public key.
 * @returns {Promise<CryptoKey>} Imported public key.
 */
async function importSigningPublicKey(base64) {
    // SPKI public key bytes are imported as verify-only to reduce misuse surface.
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "spki",
        binary.buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );
}

/**
 * Generates a new ECDSA P-256 key pair.
 *
 * @returns {Promise<CryptoKeyPair>} Generated signing key pair.
 */
async function generateSigningKeyPair() {
    return crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
}

/**
 * Signs a payload with a base64-encoded signing private key.
 *
 * @param {string} signingPrivateKeyBase64 - Base64 PKCS8 signing private key.
 * @param {ArrayBuffer} payload - Payload bytes to sign.
 * @returns {Promise<ArrayBuffer>} ECDSA signature bytes.
 */
async function signPayloadWithIdentity(signingPrivateKeyBase64, payload) {
    const signingKey = await importSigningPrivateKey(signingPrivateKeyBase64);
    // Signature input is caller-defined bytes (for files: IV || ciphertext).
    return crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        payload
    );
}

/**
 * Verifies a payload signature with a base64-encoded signer public key.
 *
 * @param {string} signerPublicKeyBase64 - Base64 SPKI signer public key.
 * @param {ArrayBuffer} signatureBuf - Signature bytes.
 * @param {ArrayBuffer} payload - Signed payload bytes.
 * @returns {Promise<boolean>} True if signature verification succeeds.
 */
async function verifyPayloadWithSigner(signerPublicKeyBase64, signatureBuf, payload) {
    const signerKey = await importSigningPublicKey(signerPublicKeyBase64);
    // Verification must use the exact same byte layout used during signing.
    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        signerKey,
        signatureBuf,
        payload
    );
}

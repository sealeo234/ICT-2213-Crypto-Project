// Crypto: Derive AES Key
async function deriveKey(password, salt, usages = ["encrypt", "decrypt"]) {
    const enc = new TextEncoder();
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

// Encrypt / Decrypt Payload
async function encryptPayload(plaintextBytes, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, ["encrypt","decrypt"]);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes);
    return { salt, iv, ciphertext };
}

async function decryptPem(encryptedPemBase64, password) {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedPemBase64));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);
    const key = await deriveKey(password, salt, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return decrypted;
}

async function encryptFileWithFek(fileBuf) {
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

async function importFekForDecrypt(rawAes) {
    return crypto.subtle.importKey(
        "raw",
        rawAes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
}

async function decryptFileWithFek(iv, ciphertext, rawAes) {
    const aesKey = await importFekForDecrypt(rawAes);
    return crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        ciphertext
    );
}

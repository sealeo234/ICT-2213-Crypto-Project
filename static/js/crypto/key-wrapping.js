async function importEncryptionPrivateKey(base64) {
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        binary.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );
}

async function importEncryptionPublicKey(base64) {
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "spki",
        binary.buffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );
}

async function generateEncryptionKeyPair() {
    return crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
}

async function wrapRawKeyForRecipient(recipientPublicKeyBase64, rawAes) {
    const recipientPubKey = await importEncryptionPublicKey(recipientPublicKeyBase64);
    return crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPubKey,
        rawAes
    );
}

async function wrapRawKeyWithPublicKey(recipientPubKey, rawAes) {
    return crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        recipientPubKey,
        rawAes
    );
}

async function unwrapRawKeyForOwner(ownerPrivateKeyBase64, wrappedKeyBuf) {
    const ownerPrivateKey = await importEncryptionPrivateKey(ownerPrivateKeyBase64);
    return crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        ownerPrivateKey,
        wrappedKeyBuf
    );
}

async function unwrapRawKeyFromBase64(ownerPrivateKeyBase64, wrappedKeyBase64) {
    return unwrapRawKeyForOwner(ownerPrivateKeyBase64, base64ToArrayBuffer(wrappedKeyBase64));
}

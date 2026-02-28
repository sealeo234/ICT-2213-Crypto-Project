async function importSigningPrivateKey(base64) {
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "pkcs8",
        binary.buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
    );
}

async function importSigningPublicKey(base64) {
    const binary = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
        "spki",
        binary.buffer,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );
}

async function generateSigningKeyPair() {
    return crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
}

async function signPayloadWithIdentity(signingPrivateKeyBase64, payload) {
    const signingKey = await importSigningPrivateKey(signingPrivateKeyBase64);
    return crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        payload
    );
}

async function verifyPayloadWithSigner(signerPublicKeyBase64, signatureBuf, payload) {
    const signerKey = await importSigningPublicKey(signerPublicKeyBase64);
    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        signerKey,
        signatureBuf,
        payload
    );
}

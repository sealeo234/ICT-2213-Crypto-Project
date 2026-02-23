/* =========================================================
   Secure Private Key Export and Import (Encrypted PEM)
   ========================================================= */

/* ---------- Password Prompt Modal ---------- */
function promptPassword({ title, message }) {
    return new Promise(resolve => {
        const modal = document.getElementById("password-modal");
        modal.classList.remove("hidden");
        document.getElementById("password-title").textContent = title;
        document.getElementById("password-message").textContent = message;
        const input = document.getElementById("password-input");
        input.value = "";
        input.focus();

        const cleanup = () => {
            modal.classList.add("hidden");
            confirmBtn.removeEventListener("click", onConfirm);
            cancelBtn.removeEventListener("click", onCancel);
        };

        const onConfirm = () => { cleanup(); resolve(input.value); };
        const onCancel = () => { cleanup(); resolve(null); };

        const confirmBtn = document.getElementById("password-confirm");
        const cancelBtn = document.getElementById("password-cancel");
        confirmBtn.addEventListener("click", onConfirm);
        cancelBtn.addEventListener("click", onCancel);
    });
}

async function promptConfirm({ title, message }) {
    return new Promise(resolve => {
        const modal = document.getElementById("confirm-modal");
        const confirmBtn = document.getElementById("confirm-confirm");
        const cancelBtn = document.getElementById("confirm-cancel");

        document.getElementById("confirm-title").textContent = title;
        document.getElementById("confirm-message").textContent = message;

        modal.classList.remove("hidden");

        const cleanup = () => {
            modal.classList.add("hidden");
            confirmBtn.onclick = null;
            cancelBtn.onclick = null;
        };

        confirmBtn.onclick = () => { cleanup(); resolve(true); };
        cancelBtn.onclick = () => { cleanup(); resolve(false); };
    });
}


/* ---------- Base64 / Buffer Helpers ---------- */
function arrayBufferToBase64(buf) {
    let binary = "";
    const bytes = new Uint8Array(buf);
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
}


function base64ToArrayBuffer(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

function toPem(base64, label) {
    const lines = base64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToBase64(pem) {
    return pem.replace(/-----BEGIN .*-----/, "")
              .replace(/-----END .*-----/, "")
              .replace(/\s+/g, "");
}

function encodeUtf8(text) {
    return new TextEncoder().encode(text);
}

function decodeUtf8(buf) {
    return new TextDecoder().decode(buf);
}

/* ---------- IndexedDB Access ---------- */
function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function loadIdentity(uuid) {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    return new Promise((resolve, reject) => {
        const req = store.get(uuid);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function storeIdentity(uuid, identity) {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    return new Promise((resolve, reject) => {
        const req = store.put(identity, uuid);
        req.onsuccess = () => resolve(true);
        req.onerror = () => reject(req.error);
    });
}

/* ---------- Crypto: Derive AES Key ---------- */
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

/* ---------- Encrypt / Decrypt Payload ---------- */
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

/* ---------- Build Encrypted PEM ---------- */

// Format: [16-byte salt][12-byte iv][AES-GCM ciphertext]

function buildEncryptedPem({ salt, iv, ciphertext }, label) {
    const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.byteLength);
    combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);
    return toPem(arrayBufferToBase64(combined.buffer), label);
}

/* ---------- Key Generation / Export ---------- */
async function generateEncryptionKeyPair() {
    return crypto.subtle.generateKey(
        { name: "RSA-OAEP", modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" },
        true,
        ["encrypt", "decrypt"]
    );
}

async function generateSigningKeyPair() {
    return crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
}

async function exportPublicKey(key) {
    const spki = await crypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(spki);
}

async function exportPrivateKey(key) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(pkcs8);
}

/* ---------- Export Identity Container ---------- */
async function exportIdentityWithPrompt(identity) {

    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    const uuid = uuidMeta ? uuidMeta.content : "New";

    const password = await promptPassword({
        title: "Encrypt Identity",
        message: "Enter a password to encrypt your identity container. This cannot be recovered."
    });

    if (!password)
        throw new Error("Identity export cancelled");

    if (password.length < 8)
        throw new Error("Password must be at least 8 characters");

    const password2 = await promptPassword({
        title: "Confirm Password",
        message: "Re-enter the password."
    });

    if (!password2)
        throw new Error("Identity export cancelled");

    if (password !== password2)
        throw new Error("Passwords do not match");

    const payload = encodeUtf8(JSON.stringify(identity));
    const encrypted = await encryptPayload(payload, password);
    const pem = buildEncryptedPem(encrypted, "VAULT IDENTITY");

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `vault_${uuid}_${timestamp}.pem`;

    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    console.log("[Vault] Encrypted identity exported");
    return true;
}


/* ---------- Vault Key Rotation ---------- */
async function rotateVaultKey() {
    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) {
        showAlert({ title: "Authentication Error", message: "You are not authenticated.", type: "error" });
        return;
    }

    const uuid = uuidMeta.content;

    const proceed = await promptConfirm({
        title: "Rotate Key",
        message: "This will generate a new encryption key and rewrap all your files.\nDo NOT close this window.\nContinue?"
    });

    if (!proceed) return;

    try {
        showAlert({ title: "Key Rotation", message: "Starting key rotation...", type: "success" });

        // Load OLD private key
        const oldIdentity = await loadIdentity(uuid);
        if (!oldIdentity || !oldIdentity.encPriv) throw new Error("Old private key not found");

        const oldPrivateKey = await importEncryptionPrivateKey(oldIdentity.encPriv);

        // Generate NEW keypairs
        const { publicKey: newEncPublicKey, privateKey: newEncPrivateKey } = await generateEncryptionKeyPair();
        const { publicKey: newSignPublicKey, privateKey: newSignPrivateKey } = await generateSigningKeyPair();
        const newEncPublicBase64 = await exportPublicKey(newEncPublicKey);
        const newEncPrivateBase64 = await exportPrivateKey(newEncPrivateKey);
        const newSignPublicBase64 = await exportPublicKey(newSignPublicKey);
        const newSignPrivateBase64 = await exportPrivateKey(newSignPrivateKey);

        // Get all files user has access to
        const fileIds = await fetch("/my_files").then(r => r.json());

        for (const fileId of fileIds) {

            try {
                const keyResp = await fetch(`/file_key/${fileId}`);
                if (!keyResp.ok) continue;

                const { wrapped_key } = await keyResp.json();
                if (!wrapped_key) continue;

                const wrappedKeyBuf = base64ToArrayBuffer(wrapped_key);

                const rawAes = await crypto.subtle.decrypt(
                    { name: "RSA-OAEP" },
                    oldPrivateKey,
                    wrappedKeyBuf
                );

                const rewrappedBuf = await crypto.subtle.encrypt(
                    { name: "RSA-OAEP" },
                    newEncPublicKey,
                    rawAes
                );

                const newWrapped = arrayBufferToBase64(rewrappedBuf);

                await fetch(`/rewrap_self/${fileId}`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ wrapped_key: newWrapped })
                });

            } catch (err) {
                console.error("Rewrap failed:", fileId, err);

                showAlert({
                    title: "Invalid Private Key",
                    message: "The loaded private key cannot decrypt your files. Check your passphrase.",
                    type: "error"
                });

                return; // stop entire rotation safely
            }
        }

        // Update server public key
        const iv = crypto.getRandomValues(new Uint8Array(16));
        await fetch("/rotate_key", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                public_key: newEncPublicBase64,
                signing_public_key: newSignPublicBase64,
                iv: arrayBufferToBase64(iv)
            })
        });

        // Store NEW identity
        const newIdentity = {
            encPriv: newEncPrivateBase64,
            signPriv: newSignPrivateBase64,
            encPub: newEncPublicBase64,
            signPub: newSignPublicBase64,
            version: 1
        };

        await storeIdentity(uuid, newIdentity);
        await exportIdentityWithPrompt(newIdentity);

        showAlert({
            title: "Rotation Complete",
            message: "All files successfully rewrapped with new key.",
            type: "success"
        });

        location.reload();

    } catch (err) {
        console.error(err);
        showAlert({
            title: "Rotation Failed",
            message: err.message || "Key rotation failed.",
            type: "error"
        });
    }
}

/* ---------- Load Private Key from File ---------- */
async function importPrivateKeyFromFile() {
    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) { showAlert({ title: "Authentication Error", message: "You are not authenticated.", type: "error" }); return; }
    const uuid = uuidMeta.content;

    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".pem";
    input.onchange = async () => {
        const file = input.files[0];
        if (!file) return;

        let text = await file.text();
        const base64 = pemToBase64(text);
        let identity = null;

        if (/-----BEGIN VAULT IDENTITY-----/.test(text)) {
            const password = await promptPassword({
                title: "Decrypt Identity",
                message: "Enter the password used to encrypt this identity container."
            });
            if (!password) return showAlert({ title: "Password Error", message: "Password required", type: "error" });
            try {
                const decrypted = await decryptPem(base64, password);
                identity = JSON.parse(decodeUtf8(decrypted));
            } catch (err) {
                console.error(err);
                return showAlert({ title: "Decryption Error", message: "Failed to decrypt identity. Wrong password?", type: "error" });
            }
        } else if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text)) {
            const password = await promptPassword({
                title: "Decrypt Private Key",
                message: "Enter the password used to encrypt this private key."
            });
            if (!password) return showAlert({ title: "Password Error", message: "Password required", type: "error" });
            try {
                const decrypted = await decryptPem(base64, password);
                identity = { encPriv: arrayBufferToBase64(decrypted), signPriv: null, version: 1 };
            } catch (err) {
                console.error(err);
                return showAlert({ title: "Decryption Error", message: "Failed to decrypt private key. Wrong password?", type: "error" });
            }
        } else {
            return showAlert({ title: "Unsupported File", message: "This PEM is not a supported identity container.", type: "error" });
        }

        try {
            await storeIdentity(uuid, identity);
            if (!identity.signPriv) {
                showAlert({
                    title: "Partial Identity Loaded",
                    message: "Signing key missing. Rotate your keys to enable file authenticity.",
                    type: "error"
                });
                return;
            }
            showAlert({ title: "Success", message: "Identity container successfully loaded!", type: "success" });
        } catch (err) {
            console.error(err);
            showAlert({ title: "Error", message: "Failed to store identity", type: "error" });
        }
    };
    input.click();
}

/* ---------- Event Bindings ---------- */
document.addEventListener("DOMContentLoaded", () => {
    const rotateBtn = document.getElementById("rotate-key-btn");
    if (rotateBtn) rotateBtn.addEventListener("click", rotateVaultKey);

    const loadBtn = document.getElementById("load-key-btn");
    if (loadBtn) loadBtn.addEventListener("click", importPrivateKeyFromFile);
});


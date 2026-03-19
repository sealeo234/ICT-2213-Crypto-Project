/**
 * @file key-mgmt.js
 * @description Shared UI, encoding, storage, and identity-container helpers for client-side key management.
 */

/**
 * Handles an error by logging and displaying a standardized alert modal.
 *
 * @param {unknown} err - Error object or thrown value.
 * @param {string} [title="Error"] - Alert title.
 * @returns {void}
 */
function handleError(err, title = "Error") {
    console.error(err);
    const message = err?.message || "An unexpected error occurred";
    showAlert({ title, message, type: "error" });
}

/**
 * Verifies browser support for required Web Crypto APIs.
 *
 * @returns {boolean} True when the environment supports required crypto primitives.
 */
function checkCryptoSupport() {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
        showAlert({
            title: "Browser Not Supported",
            message: "Your browser does not support the Web Crypto API required for client-side encryption. Please use a modern browser like Chrome, Firefox, or Edge.",
            type: "error"
        });
        return false;
    }
    return true;
}

/**
 * Renders and opens the alert modal with configurable content.
 *
 * @param {{title?: string, message?: string, type?: string, onClose?: Function}} options - Alert options.
 * @returns {void}
 */
function showAlert({ title = "Alert", message = "", type = "error", onClose }) {
    const modal = document.getElementById("alert-modal");
    modal.classList.remove("hidden");
    document.getElementById("alert-title").textContent = title;
    document.getElementById("alert-message").textContent = message;

    const box = document.getElementById("alert-box");
    box.style.borderColor = type === "error" ? "#3b82f6" : "#ffffff";
    box.querySelector("button").onclick = () => {
        modal.classList.add("hidden");
        if (typeof onClose === "function") onClose();
    };
}

/**
 * Ensures a private encryption key exists in local identity storage.
 *
 * @returns {Promise<boolean>} True when a decrypt-capable identity is available.
 */
async function ensurePrivateKeyPresent() {
    if (!checkCryptoSupport()) return false;
    const identity = await getIdentity();
    if (!identity || !identity.encPriv) {
        showAlert({
            title: "Private Key Required",
            message: "Your private key is not loaded. Please load your identity container before accessing or decrypting files.",
            type: "error"
        });
        return false;
    }

    return true;
}

/**
 * Displays a password prompt modal and resolves with entered value or null.
 *
 * @param {{title: string, message: string}} options - Prompt display content.
 * @returns {Promise<string|null>} Entered password or null if cancelled.
 */
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
            // Remove listeners each time to avoid duplicated handlers on repeated prompts.
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

/**
 * Displays a confirmation prompt modal.
 *
 * @param {{title: string, message: string}} options - Prompt display content.
 * @returns {Promise<boolean>} True when confirmed, false when cancelled.
 */
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


/**
 * Converts an ArrayBuffer to base64.
 *
 * @param {ArrayBuffer} buf - Input bytes.
 * @returns {string} Base64-encoded string.
 */
function arrayBufferToBase64(buf) {
    let binary = "";
    const bytes = new Uint8Array(buf);
    const chunkSize = 0x8000;
    // Chunk conversion prevents stack overflows on large buffers in fromCharCode spread.
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary);
}


/**
 * Converts a base64 string to an ArrayBuffer.
 *
 * @param {string} b64 - Base64-encoded input.
 * @returns {ArrayBuffer} Decoded bytes.
 */
function base64ToArrayBuffer(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

/**
 * Formats base64 data as PEM with the provided label.
 *
 * @param {string} base64 - Base64 payload.
 * @param {string} label - PEM block label.
 * @returns {string} PEM-encoded string.
 */
function toPem(base64, label) {
    const lines = base64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

/**
 * Strips PEM headers and whitespace and returns the inner base64 payload.
 *
 * @param {string} pem - PEM-formatted text.
 * @returns {string} Base64 payload.
 */
function pemToBase64(pem) {
    return pem.replace(/-----BEGIN .*-----/, "")
              .replace(/-----END .*-----/, "")
              .replace(/\s+/g, "");
}

/**
 * UTF-8 encodes a string.
 *
 * @param {string} text - Input text.
 * @returns {Uint8Array} Encoded bytes.
 */
function encodeUtf8(text) {
    return new TextEncoder().encode(text);
}

/**
 * UTF-8 decodes bytes.
 *
 * @param {BufferSource} buf - Encoded bytes.
 * @returns {string} Decoded text.
 */
function decodeUtf8(buf) {
    return new TextDecoder().decode(buf);
}

/**
 * Generates cryptographically secure random bytes.
 *
 * @param {number} length - Number of random bytes.
 * @returns {Uint8Array} Random byte array.
 */
function generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Concatenates two ArrayBuffers.
 *
 * @param {ArrayBuffer} a - First buffer.
 * @param {ArrayBuffer} b - Second buffer.
 * @returns {ArrayBuffer} Combined buffer.
 */
function concatBuffers(a, b) {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(new Uint8Array(a), 0);
    out.set(new Uint8Array(b), a.byteLength);
    return out.buffer;
}

const DB_NAME = "vault_keys";
const STORE_NAME = "keys";

/**
 * Opens the vault IndexedDB database.
 *
 * @returns {Promise<IDBDatabase>} Opened database handle.
 */
function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, 1);
        // One-time schema creation for key-value identity store.
        req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

/**
 * Loads a stored identity record by UUID key.
 *
 * @param {string} uuid - Storage key.
 * @returns {Promise<any>} Stored identity record or undefined.
 */
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

/**
 * Stores an identity record under a UUID key.
 *
 * @param {string} uuid - Storage key.
 * @param {any} identity - Identity record payload.
 * @returns {Promise<boolean>} True when persistence succeeds.
 */
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

/**
 * Resolves the current authenticated user's local identity.
 *
 * @returns {Promise<any|null>} Identity record or null when unavailable.
 */
async function getIdentity() {
    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) return null;
    const record = await loadIdentity(uuidMeta.content);
    if (!record) return null;
    // Backward compatibility: legacy records stored only encryption private key string.
    if (typeof record === "string") {
        return { encPriv: record, signPriv: null, version: 1 };
    }
    return record;
}

/**
 * Builds a PEM identity container from encrypted components.
 *
 * Binary layout before PEM encoding: [16-byte salt][12-byte IV][AES-GCM ciphertext].
 *
 * @param {{salt: Uint8Array, iv: Uint8Array, ciphertext: ArrayBuffer}} encryptedData - Encrypted payload parts.
 * @param {string} label - PEM block label.
 * @returns {string} PEM-encoded encrypted identity container.
 */
function buildEncryptedPem({ salt, iv, ciphertext }, label) {
    const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.byteLength);
    combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);
    return toPem(arrayBufferToBase64(combined.buffer), label);
}

/**
 * Exports a public CryptoKey to base64 SPKI.
 *
 * @param {CryptoKey} key - Public key to export.
 * @returns {Promise<string>} Base64 SPKI public key.
 */
async function exportPublicKey(key) {
    const spki = await crypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(spki);
}

/**
 * Exports a private CryptoKey to base64 PKCS8.
 *
 * @param {CryptoKey} key - Private key to export.
 * @returns {Promise<string>} Base64 PKCS8 private key.
 */
async function exportPrivateKey(key) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(pkcs8);
}

/**
 * Encrypts and exports an identity as a password-protected PEM file.
 *
 * @param {any} identity - Identity record to export.
 * @returns {Promise<boolean>} True when export completes.
 */
async function exportIdentityWithPrompt(identity) {

    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    const uuid = uuidMeta ? uuidMeta.content : "New";

    const password = await promptPassword({
        title: "Encrypt Identity",
        message: "Enter a password to encrypt your identity container. This cannot be recovered. Password must be at least 8 characters"
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
    // Identity JSON is encrypted before disk export; plaintext keys are never written to file.
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

/**
 * Imports a password-protected identity or encrypted private key PEM file.
 *
 * @returns {Promise<void>}
 */
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

        // Support two container types: full identity bundle or legacy encrypted private key.
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
            console.log("[Vault] Verifying private key against account public key...");
            const pubKeyBase64 = document.querySelector('meta[name="user-public-key"]').content;
            
            const pubKey = await importEncryptionPublicKey(pubKeyBase64);
            const testMessage = new TextEncoder().encode("KeyMatchTest");
            // Challenge round-trip proves imported private key belongs to current account.
            const encryptedChallenge = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, testMessage);
            
            const privKey = await importEncryptionPrivateKey(identity.encPriv);
            await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, encryptedChallenge);
            
            console.log("[Vault] Key verification passed!");
        } catch (err) {
            console.error("[Vault] Key verification failed:", err);
            showAlert({ 
                title: "Invalid Identity Container", 
                message: "This key does not match your account. Please select the correct .pem file.", 
                type: "error" 
            });
            return;
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
            showAlert({ title: "Success", message: "Identity container successfully loaded!", type: "success", onClose: () => window.location.reload()});
        } catch (err) {
            console.error(err);
            showAlert({ title: "Error", message: "Failed to store identity", type: "error" });
        }
    };
    input.click();
}


/**
 * Commits a pending post-registration identity into permanent user storage.
 *
 * @returns {Promise<void>}
 */
async function commitPendingKey() {
    console.log("[Vault] commitPendingKey() called");
    
    const pendingFlag = sessionStorage.getItem("__pending_migration__");
    if (!pendingFlag) {
        console.log("[Vault] No pending migration flag found");
        return;
    }

    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) {
        console.log("[Vault] User not authenticated yet, pending migration will occur on next load");
        return;
    }

    const uuid = uuidMeta.content;
    console.log("[Vault] User authenticated with UUID:", uuid);
    console.log("[Vault] Beginning pending identity migration...");

    if (navigator.storage && navigator.storage.persist) {
        try {
            // Request persistent storage to reduce risk of browser eviction of vault keys.
            const granted = await navigator.storage.persist();
            console.log("[Vault] Storage persistence:", granted);
            if (!granted) {
                console.warn("Warning: Your browser may delete your vault keys.");
            }
        } catch (err) {
            console.warn("[Vault] Storage persistence request failed:", err);
        }
    }

    let pendingIdentity = null;
    let pendingSource = null;

    try {
        pendingIdentity = await loadIdentity("__pending__");
        if (pendingIdentity) {
            // Prefer IndexedDB copy when available because it is the primary storage path.
            pendingSource = "indexeddb";
        }
    } catch (err) {
        console.warn("[Vault] Could not load pending identity from IndexedDB:", err);
    }

    if (!pendingIdentity) {
        console.log("[Vault] Checking sessionStorage for pending identity...");
        const sessionPending = sessionStorage.getItem("pending_identity");
        if (sessionPending) {
            try {
                pendingIdentity = JSON.parse(sessionPending);
                console.log("[Vault] Found pending identity in sessionStorage");
                // Session fallback is used when pending IndexedDB write is unavailable.
                pendingSource = "sessionstorage";
            } catch (err) {
                console.error("[Vault] Failed to parse pending identity from sessionStorage:", err);
            }
        }
    }

    if (!pendingIdentity) {
        console.error("[Vault] CRITICAL: No pending identity found in either IndexedDB or sessionStorage!");
        sessionStorage.removeItem("__pending_migration__");
        showAlert({
            title: "Identity Recovery Required",
            message: "Your identity was not found. Please load your .pem identity file using the 'Load Key' button.",
            type: "error"
        });
        return;
    }

    try {
        console.log("[Vault] Migrating pending identity to permanent storage under UUID...");
        await storeIdentity(uuid, pendingIdentity);
        console.log("[Vault] Identity migrated successfully");
        
        const verifyMigrated = await loadIdentity(uuid);
        if (!verifyMigrated) {
            throw new Error("Identity migration verification failed");
        }
        console.log("[Vault] Migration verified - identity confirmed in permanent storage");
        
        console.log("[Vault] Cleaning up temporary storage from source: " + pendingSource);
        if (pendingSource === "indexeddb") {
            const db = await openDB();
            const tx = db.transaction(STORE_NAME, "readwrite");
            const store = tx.objectStore(STORE_NAME);
            // Remove temporary key only after successful migration verification.
            await new Promise((resolve, reject) => {
                const req = store.delete("__pending__");
                req.onsuccess = () => resolve();
                req.onerror = () => reject(req.error);
            });
        }
        if (pendingSource === "sessionstorage") {
            sessionStorage.removeItem("pending_identity");
            console.log("[Vault] Cleaned up sessionStorage");
        }
        
        sessionStorage.removeItem("__pending_migration__");
        
        showAlert({
            title: "Identity Loaded",
            message: "Your cryptographic identity has been automatically loaded.",
            type: "success",
            onClose: () => window.location.reload()
        });
    } catch (err) {
        console.error("[Vault] Failed to commit pending identity:", err);
        showAlert({
            title: "Identity Load Failed",
            message: "Failed to load identity. Please load your .pem file manually.",
            type: "error"
        });
    }
}

/**
 * Binds key-management UI events on page load.
 *
 * @returns {void}
 */
document.addEventListener("DOMContentLoaded", () => {
    const loadBtn = document.getElementById("load-key-btn");
    if (loadBtn) loadBtn.addEventListener("click", importPrivateKeyFromFile);

    console.log("[Vault] Checking for pending identity to commit...");
    commitPendingKey().catch(err => {
        console.error("[Vault] Error committing pending identity:", err);
    });

    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (uuidMeta) {
        console.log("[Vault] User authenticated with UUID:", uuidMeta.content);
        getIdentity().catch(err => {
            console.error("[Vault] Error loading identity:", err);
        });
    }
});


/* 
    Shared Key/Identity Management Helpers
    has UI prompts and alerts
    uses encoding and buffer utilities
    uses IndexedDB identity storage
    supports identity container import/export (.pem)
*/

// UI
function handleError(err, title = "Error") {
    console.error(err);
    const message = err?.message || "An unexpected error occurred";
    showAlert({ title, message, type: "error" });
}

// Check for Web Crypto API support
function checkCryptoSupport() {
    // Check if Web Crypto API is available
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

// Alert modal renderer
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

// Modal prompts
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


// Encoding / buffer utilities
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

function generateRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function concatBuffers(a, b) {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(new Uint8Array(a), 0);
    out.set(new Uint8Array(b), a.byteLength);
    return out.buffer;
}

// IndexedDB identity store
const DB_NAME = "vault_keys";
const STORE_NAME = "keys";

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

async function getIdentity() {
    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) return null;
    const record = await loadIdentity(uuidMeta.content);
    if (!record) return null;
    if (typeof record === "string") {
        return { encPriv: record, signPriv: null, version: 1 };
    }
    return record;
}

// Encrypted identity container format

// Binary layout before PEM encoding: [16-byte salt][12-byte IV][AES-GCM ciphertext]

function buildEncryptedPem({ salt, iv, ciphertext }, label) {
    const combined = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.byteLength);
    combined.set(new Uint8Array(ciphertext), salt.byteLength + iv.byteLength);
    return toPem(arrayBufferToBase64(combined.buffer), label);
}

// Key export helpers
async function exportPublicKey(key) {
    const spki = await crypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(spki);
}

async function exportPrivateKey(key) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(pkcs8);
}

// Export identity container (.pem)
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

// Import identity/private key from .pem
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


// Persist post-registration identity
async function commitPendingKey() {
    console.log("[Vault] commitPendingKey() called");
    
    // Check if migration is needed first
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
            const granted = await navigator.storage.persist();
            console.log("[Vault] Storage persistence:", granted);
            if (!granted) {
                console.warn("Warning: Your browser may delete your vault keys.");
            }
        } catch (err) {
            console.warn("[Vault] Storage persistence request failed:", err);
        }
    }

    // Try to load pending identity from IndexedDB first
    let pendingIdentity = null;
    let pendingSource = null;

    try {
        pendingIdentity = await loadIdentity("__pending__");
        if (pendingIdentity) {
            pendingSource = "indexeddb";
        }
    } catch (err) {
        console.warn("[Vault] Could not load pending identity from IndexedDB:", err);
    }

    // Fallback to sessionStorage if IndexedDB didn't work
    if (!pendingIdentity) {
        console.log("[Vault] Checking sessionStorage for pending identity...");
        const sessionPending = sessionStorage.getItem("pending_identity");
        if (sessionPending) {
            try {
                pendingIdentity = JSON.parse(sessionPending);
                console.log("[Vault] Found pending identity in sessionStorage");
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
        // Migrate from temporary storage to permanent user-uuid storage
        await storeIdentity(uuid, pendingIdentity);
        console.log("[Vault] Identity migrated successfully");
        
        // Verify migration succeeded
        const verifyMigrated = await loadIdentity(uuid);
        if (!verifyMigrated) {
            throw new Error("Identity migration verification failed");
        }
        console.log("[Vault] Migration verified - identity confirmed in permanent storage");
        
        // Clean up temporary storage
        console.log("[Vault] Cleaning up temporary storage from source: " + pendingSource);
        if (pendingSource === "indexeddb") {
            const db = await openDB();
            const tx = db.transaction(STORE_NAME, "readwrite");
            const store = tx.objectStore(STORE_NAME);
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
        
        // Clear the pending migration flag
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

// Event wiring
document.addEventListener("DOMContentLoaded", () => {
    const loadBtn = document.getElementById("load-key-btn");
    if (loadBtn) loadBtn.addEventListener("click", importPrivateKeyFromFile);

    // Immediately attempt to commit pending identity
    console.log("[Vault] Checking for pending identity to commit...");
    commitPendingKey().catch(err => {
        console.error("[Vault] Error committing pending identity:", err);
    });

    // Also ensure identity is loaded for authenticated users
    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (uuidMeta) {
        console.log("[Vault] User authenticated with UUID:", uuidMeta.content);
        getIdentity().catch(err => {
            console.error("[Vault] Error loading identity:", err);
        });
    }
});


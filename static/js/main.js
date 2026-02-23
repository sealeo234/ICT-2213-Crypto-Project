/* ===============================
   Error Handling
================================ */
function handleError(err, title = "Error") {
    console.error(err);
    const message = err?.message || "An unexpected error occurred";
    showAlert({ title, message, type: "error" });
}

/* ---------- Custom Alert Modal ---------- */
function showAlert({ title = "Alert", message = "", type = "error" }) {
    const modal = document.getElementById("alert-modal");
    modal.classList.remove("hidden");
    document.getElementById("alert-title").textContent = title;
    document.getElementById("alert-message").textContent = message;

    const box = document.getElementById("alert-box");
    box.style.borderColor = type === "error" ? "#3b82f6" : "#ffffff";
    box.querySelector("button").onclick = () => modal.classList.add("hidden");
}

async function ensurePrivateKeyPresent() {
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

/* ===============================
   IndexedDB Helpers
================================ */

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

async function storeIdentity(uuid, identity) {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(identity, uuid);
    return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
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

/* ===============================
   Crypto Helpers
================================ */

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

function concatBuffers(a, b) {
    const out = new Uint8Array(a.byteLength + b.byteLength);
    out.set(new Uint8Array(a), 0);
    out.set(new Uint8Array(b), a.byteLength);
    return out.buffer;
}


/* ===============================
   Commit pending private key
================================ */

async function commitPendingKey() {
    if (navigator.storage && navigator.storage.persist) {
        const granted = await navigator.storage.persist();
        console.log("[Vault] Storage persistence:", granted);
        if (!granted) {
            console.log("Warning: Your browser may delete your vault keys.");
        }
    }

    const pendingIdentity = sessionStorage.getItem("pending_identity");
    if (!pendingIdentity) return;

    const uuidMeta = document.querySelector('meta[name="user-uuid"]');
    if (!uuidMeta) return;

    await storeIdentity(uuidMeta.content, JSON.parse(pendingIdentity));
    sessionStorage.removeItem("pending_identity");

    console.log("[Vault] Identity committed to IndexedDB");
}

document.addEventListener("DOMContentLoaded", commitPendingKey);


/* ===============================
   Upload / Encrypt File (Owner Only)
================================ */
document.addEventListener("DOMContentLoaded", () => {
    const uploadForm = document.getElementById("upload-form");
    const fileInput = document.getElementById("file-input");
    const selectBtn = document.getElementById("select-btn");

    if (!uploadForm || !fileInput || !selectBtn) return;

    uploadForm.addEventListener("submit", async e => {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;

        const selfUUID = document.querySelector('meta[name="user-uuid"]').content;

        try {
            // Read file and generate AES-GCM key
            const fileBuf = await file.arrayBuffer();
            const aesKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, fileBuf);

            // Export raw AES key for wrapping
            const rawAes = await crypto.subtle.exportKey("raw", aesKey);

            // Fetch owner's public key
            const pubKeyMap = await fetch("/recipient_keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ recipients: [selfUUID] })
            }).then(r => r.json());

            // Wrap AES key for owner only
            const wrappedKeys = {};
            const ownerPubKey = await importEncryptionPublicKey(pubKeyMap[selfUUID]);
            const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, ownerPubKey, rawAes);
            wrappedKeys[selfUUID] = arrayBufferToBase64(wrapped);

            const identity = await getIdentity();
            if (!identity || !identity.signPriv || !identity.signPub) {
                throw new Error("Signing key missing. Load your identity container or rotate keys.");
            }

            const signingKey = await importSigningPrivateKey(identity.signPriv);
            const payload = concatBuffers(iv.buffer, ciphertext);
            const signature = await crypto.subtle.sign(
                { name: "ECDSA", hash: "SHA-256" },
                signingKey,
                payload
            );

            // Prepare FormData and upload
            const formData = new FormData();
            formData.append("file", new Blob([ciphertext]), file.name);
            formData.append("iv", arrayBufferToBase64(iv));
            formData.append("wrapped_keys", JSON.stringify(wrappedKeys));
            formData.append("signature", arrayBufferToBase64(signature));
            formData.append("signature_alg", "ECDSA_P256_SHA256");
            formData.append("signer_public_key", identity.signPub);

            const resp = await fetch("/upload", { method: "POST", body: formData });
            if (!resp.ok) throw new Error("File upload failed");

            window.location.reload();

        } catch (err) {
            console.error(err);
            showAlert({ title: "Upload Failed", message: err.message || "Failed to upload file.", type: "error" });
        }
    });

    // Bind file selection button
    selectBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) uploadForm.requestSubmit();
    });
});

/* ===============================
   Download / Decrypt File (RECIPIENT-SPECIFIC)
================================ */

document.addEventListener("click", async e => {
    const link = e.target.closest('a[href^="/download/"]');
    if (!link) return;
    e.preventDefault();
    if (!(await ensurePrivateKeyPresent())) return;

    showDecryptProgress("Starting…", 5);

    try {
        const fileId = link.dataset.file;
        if (!fileId) throw new Error("File ID missing");

        showDecryptProgress("Downloading encrypted file…", 10);
        const resp = await fetch(`/download/${fileId}`);
        if (!resp.ok) throw new Error("Download failed");
        const ciphertext = await resp.arrayBuffer();

        showDecryptProgress("Fetching encryption metadata…", 25);
        const ivResp = await fetch(`/file_iv/${fileId}`);
        if (!ivResp.ok) throw new Error("IV fetch failed");

        const ivJson = await ivResp.json();
        const iv = Uint8Array.from(atob(ivJson.iv), c => c.charCodeAt(0));

        showDecryptProgress("Verifying authenticity…", 35);
        const sigResp = await fetch(`/file_signature/${fileId}`);
        if (!sigResp.ok) throw new Error("Signature fetch failed");
        const sigJson = await sigResp.json();
        if (!sigJson.signature || !sigJson.signer_public_key) {
            throw new Error("Missing signature metadata");
        }
        const signerKey = await importSigningPublicKey(sigJson.signer_public_key);
        const signatureBuf = base64ToArrayBuffer(sigJson.signature);
        const payload = concatBuffers(iv.buffer, ciphertext);
        const verified = await crypto.subtle.verify(
            { name: "ECDSA", hash: "SHA-256" },
            signerKey,
            signatureBuf,
            payload
        );
        if (!verified) throw new Error("Authenticity verification failed");

        showAlert({
            title: "Signature Verified",
            message: "The file signature is valid.",
            type: "success"
        });

        showDecryptProgress("Loading private key…", 40);

        const keyResp = await fetch(`/file_key/${fileId}`);
        if (!keyResp.ok) throw new Error("No access to this file");

        const { wrapped_key } = await keyResp.json();
        const wrappedKey = Uint8Array.from(atob(wrapped_key), c => c.charCodeAt(0)).buffer;

        if (!wrapped_key) {
            throw new Error("No wrapped key available for current user");
        }

        const identity = await getIdentity();
        if (!identity || !identity.encPriv) throw new Error("Private key not found");

        const privateKey = await importEncryptionPrivateKey(identity.encPriv);

        showDecryptProgress("Decrypting file key…", 60);
        const rawAes = await crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            wrappedKey
        );

        const aesKey = await crypto.subtle.importKey(
            "raw",
            rawAes,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        showDecryptProgress("Decrypting file contents…", 80);
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            aesKey,
            ciphertext
        );

        showDecryptProgress("Finalizing…", 100);

        const outBlob = new Blob([plaintext]);
        const a = document.createElement("a");
        a.href = URL.createObjectURL(outBlob);
        a.download = link.dataset.filename;
        a.click();

    } catch (err) {
        console.error(err);
        showAlert({ title: "Decryption Failed", message: err.message || "Failed to decrypt file.", type: "error" });
    } finally {
        setTimeout(hideDecryptProgress, 300);
    }
});


function showDecryptProgress(text, percent) {
    const overlay = document.getElementById("decrypt-overlay");
    overlay.classList.remove("hidden");
    document.getElementById("decrypt-status").textContent = text;
    document.getElementById("decrypt-bar").style.width = percent + "%";
}
function hideDecryptProgress() {
    document.getElementById("decrypt-overlay").classList.add("hidden");
}


/* ---------- Edit Access ---------- */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form[data-edit-access]");
    if (!form) return;

    form.addEventListener("submit", async e => {
        e.preventDefault();
        if (!(await ensurePrivateKeyPresent())) return;

        try {
            const fileId = form.dataset.fileId;
            const selfUUID = document.querySelector('meta[name="user-uuid"]').content;

            let submittedRecipients = [...form.querySelectorAll("input[name='recipients']:checked")]
                .map(cb => cb.value);
            if (!submittedRecipients.includes(selfUUID)) submittedRecipients.push(selfUUID);

            // Fetch all current wrapped keys
            const allKeysResp = await fetch(`/file_key/${fileId}?all=true`);
            const currentKeys = await allKeysResp.json();

            // Decrypt AES key with owner's private key
            const ownerWrappedKeyBase64 = currentKeys[selfUUID];
            const rawAes = await (async () => {
                const identity = await getIdentity();
                if (!identity || !identity.encPriv) throw new Error("Private key not found");
                const privateKey = await importEncryptionPrivateKey(identity.encPriv);
                return crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, base64ToArrayBuffer(ownerWrappedKeyBase64));
            })();

            // Wrap AES key for new recipients only
            const wrappedKeys = {};
            wrappedKeys[selfUUID] = ownerWrappedKeyBase64; // owner always

            const newRecipients = submittedRecipients.filter(uuid => !(uuid in currentKeys) && uuid !== selfUUID);
            if (newRecipients.length > 0) {
                const pubKeyMap = await fetch("/recipient_keys", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ recipients: newRecipients })
                }).then(r => r.json());

                for (const [uuid, pubBase64] of Object.entries(pubKeyMap)) {
                    const pubKey = await importEncryptionPublicKey(pubBase64);
                    const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawAes);
                    wrappedKeys[uuid] = arrayBufferToBase64(wrapped);
                }
            }

            // Include unchanged recipients
            for (const uuid of submittedRecipients) {
                if (!(uuid in wrappedKeys)) wrappedKeys[uuid] = currentKeys[uuid];
            }

            // Send to server
            const resp = await fetch(`/rewrap_keys/${fileId}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ wrapped_keys: wrappedKeys })
            });

            if (!resp.ok) throw new Error("Failed to update access keys");

            showAlert({ title: "Access Updated", message: "Keys updated successfully", type: "success" });

        } catch (err) {
            console.error(err);
            showAlert({ title: "Access Update Failed", message: err.message, type: "error" });
        }
    });
});
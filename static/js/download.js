/**
 * @file download.js
 * @description Download, verify, decrypt, and save shared files for the current user.
 */

/**
 * Updates the decryption progress overlay state.
 *
 * @param {string} text - Status message shown to the user.
 * @param {number} percent - Progress percentage from 0 to 100.
 * @returns {void}
 */
function showDecryptProgress(text, percent) {
    const overlay = document.getElementById("decrypt-overlay");
    overlay.classList.remove("hidden");
    document.getElementById("decrypt-status").textContent = text;
    document.getElementById("decrypt-bar").style.width = percent + "%";
}

/**
 * Hides the decryption progress overlay.
 *
 * @returns {void}
 */
function hideDecryptProgress() {
    document.getElementById("decrypt-overlay").classList.add("hidden");
}

document.addEventListener("click", async e => {
    const link = e.target.closest('a[href^="/download/"]');
    if (!link) return;
    e.preventDefault();
    // Decryption requires local private key; block early if identity is missing.
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
        const signatureBuf = base64ToArrayBuffer(sigJson.signature);
        // Verify the same signed payload layout used at upload: IV || ciphertext.
        const payload = concatBuffers(iv.buffer, ciphertext);
        const verified = await verifyPayloadWithSigner(sigJson.signer_public_key, signatureBuf, payload);
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
        // Wrapped FEK is per-recipient and is expected to be opaque server-side data.
        const wrappedKey = Uint8Array.from(atob(wrapped_key), c => c.charCodeAt(0)).buffer;

        if (!wrapped_key) {
            throw new Error("No wrapped key available for current user");
        }

        const identity = await getIdentity();
        if (!identity || !identity.encPriv) throw new Error("Private key not found");

        showDecryptProgress("Decrypting file key…", 60);
        const rawAes = await unwrapRawKeyForOwner(identity.encPriv, wrappedKey);

        showDecryptProgress("Decrypting file contents…", 80);
        const plaintext = await decryptFileWithFek(iv, ciphertext, rawAes);

        showDecryptProgress("Finalizing…", 100);

        const outBlob = new Blob([plaintext]);
        const a = document.createElement("a");
        // Use a temporary object URL so browser download UI can save decrypted bytes locally.
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

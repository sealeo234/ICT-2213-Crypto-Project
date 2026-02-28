/* ===============================
    Upload Flow (Owner)
    - Encrypt file with FEK
    - Wrap FEK for owner
    - Sign encrypted payload
    - Upload ciphertext + metadata
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
            // Encrypt selected file client-side
            const fileBuf = await file.arrayBuffer();
            const { iv, ciphertext, rawAes } = await encryptFileWithFek(fileBuf);

            // Fetch owner public key for FEK wrapping
            const pubKeyMap = await fetch("/recipient_keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ recipients: [selfUUID] })
            }).then(r => r.json());

            // Wrap FEK for owner access
            const wrappedKeys = {};
            const wrapped = await wrapRawKeyForRecipient(pubKeyMap[selfUUID], rawAes);
            wrappedKeys[selfUUID] = arrayBufferToBase64(wrapped);

            const identity = await getIdentity();
            if (!identity || !identity.signPriv || !identity.signPub) {
                throw new Error("Signing key missing. Load your identity container or rotate keys.");
            }

            // Sign (IV || ciphertext) to provide authenticity
            const payload = concatBuffers(iv.buffer, ciphertext);
            const signature = await signPayloadWithIdentity(identity.signPriv, payload);

            // Upload encrypted artifact and cryptographic metadata
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

    // UX: button opens native picker, change auto-submits upload form
    selectBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) uploadForm.requestSubmit();
    });
});

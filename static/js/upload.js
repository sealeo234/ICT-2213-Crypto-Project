/**
 * @file upload.js
 * @description Owner upload workflow for client-side encryption, FEK wrapping, signing, and metadata upload.
 */
document.addEventListener("DOMContentLoaded", () => {
    const uploadForm = document.getElementById("upload-form");
    const fileInput = document.getElementById("file-input");
    const selectBtn = document.getElementById("select-btn");
    const dropzone = document.querySelector(".dropzone");

    if (!uploadForm || !fileInput || !selectBtn) return;

    if (dropzone) {
        // Cancel browser default handling so dropped files stay in this controlled flow.
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            dropzone.classList.add('dragover');
        }

        function unhighlight(e) {
            dropzone.classList.remove('dragover');
        }

        dropzone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                // Mirror native file picker behavior by assigning files to the hidden input.
                fileInput.files = files;
                uploadForm.requestSubmit();
            }
        }
    }

    uploadForm.addEventListener("submit", async e => {
        e.preventDefault();
        const file = fileInput.files[0];
        if (!file) return;

        const selfUUID = document.querySelector('meta[name="user-uuid"]').content;

        try {
            const fileBuf = await file.arrayBuffer();
            // Encrypt once with a fresh per-file FEK before any network request.
            const { iv, ciphertext, rawAes } = await encryptFileWithFek(fileBuf);

            const pubKeyMap = await fetch("/recipient_keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ recipients: [selfUUID] })
            }).then(r => r.json());

            const wrappedKeys = {};
            const wrapped = await wrapRawKeyForRecipient(pubKeyMap[selfUUID], rawAes);
            wrappedKeys[selfUUID] = arrayBufferToBase64(wrapped);

            const identity = await getIdentity();
            if (!identity || !identity.signPriv || !identity.signPub) {
                throw new Error("Signing key missing. Load your identity container or rotate keys.");
            }

            // Sign IV || ciphertext so IV substitution and ciphertext tampering are both detectable.
            const payload = concatBuffers(iv.buffer, ciphertext);
            const signature = await signPayloadWithIdentity(identity.signPriv, payload);

            const formData = new FormData();
            formData.append("file", new Blob([ciphertext]), file.name);
            formData.append("iv", arrayBufferToBase64(iv));
            formData.append("wrapped_keys", JSON.stringify(wrappedKeys));
            formData.append("signature", arrayBufferToBase64(signature));
            formData.append("signature_alg", "ECDSA_P256_SHA256");
            formData.append("signer_public_key", identity.signPub);

            // Server stores encrypted blob and cryptographic metadata; plaintext never leaves browser.
            const resp = await fetch("/upload", { method: "POST", body: formData });
            if (!resp.ok) throw new Error("File upload failed");

            window.location.reload();

        } catch (err) {
            console.error(err);
            showAlert({ title: "Upload Failed", message: err.message || "Failed to upload file.", type: "error" });
        }
    });

    selectBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) uploadForm.requestSubmit();
    });
});

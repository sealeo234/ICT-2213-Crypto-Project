/**
 * @file file-update.js
 * @description Secure in-place file update flow using existing FEK and fresh IV/signature metadata.
 */
document.addEventListener("click", async e => {
    const link = e.target.closest('a[data-update-file]');
    if (!link) return;
    e.preventDefault();

    if (!(await ensurePrivateKeyPresent())) return;

    const fileId = link.dataset.updateFile;
    const expectedFilename = link.dataset.filename;

    const input = document.createElement("input");
    input.type = "file";
    
    input.onchange = async () => {
        const file = input.files[0];
        if (!file) return;

        // Enforce stable filename so updates map to the same logical record.
        if (file.name !== expectedFilename) {
            showAlert({ 
                title: "Filename Mismatch", 
                message: `You must upload a file named exactly "${expectedFilename}" to update this record.`, 
                type: "error" 
            });
            return; // Abort the update process
        }

        try {
            showAlert({ title: "Updating...", message: "Encrypting and signing new file version.", type: "success" });

            const keyResp = await fetch(`/file_key/${fileId}`);
            if (!keyResp.ok) throw new Error("You do not have access to update this file.");
            const { wrapped_key } = await keyResp.json();
            const wrappedKeyBuf = base64ToArrayBuffer(wrapped_key);

            const identity = await getIdentity();
            if (!identity || !identity.encPriv || !identity.signPriv) {
                throw new Error("Full identity required to update files.");
            }
            // Reuse the existing FEK for this file record and only rotate IV/ciphertext/signature.
            const rawAes = await unwrapRawKeyForOwner(identity.encPriv, wrappedKeyBuf);

            const aesKey = await crypto.subtle.importKey(
                "raw", 
                rawAes, 
                { name: "AES-GCM" }, 
                false, 
                ["encrypt"]
            );

            const fileBuf = await file.arrayBuffer();
            // Fresh IV per encryption is mandatory for AES-GCM security with the same key.
            const newIv = generateRandomBytes(12);
            const newCiphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: newIv }, 
                aesKey, 
                fileBuf
            );

            // Sign IV || ciphertext so server-side metadata and blob stay cryptographically bound.
            const payload = concatBuffers(newIv.buffer, newCiphertext);
            const newSignature = await signPayloadWithIdentity(identity.signPriv, payload);

            const formData = new FormData();
            formData.append("file", new Blob([newCiphertext]), file.name);
            formData.append("iv", arrayBufferToBase64(newIv));
            formData.append("signature", arrayBufferToBase64(newSignature));
            formData.append("signature_alg", "ECDSA_P256_SHA256");
            formData.append("signer_public_key", identity.signPub);

            const resp = await fetch(`/update/${fileId}`, { method: "POST", body: formData });
            if (!resp.ok) throw new Error("Server rejected the file update.");

            showAlert({ title: "Success", message: "File updated successfully!", type: "success", onClose: () => window.location.reload()});

        } catch (err) {
            console.error(err);
            showAlert({ title: "Update Failed", message: err.message, type: "error" });
        }
    };

    input.click();
});
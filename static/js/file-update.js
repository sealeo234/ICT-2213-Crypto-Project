/* ===============================
    Update/Modify Flow 
    - Fetch existing wrapped FEK
    - Unwrap FEK using local private key
    - Encrypt new file with SAME FEK but NEW IV
    - Sign new ciphertext
    - Upload and overwrite on server
================================ */
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

            // Fetch the user's wrapped key for this specific file
            const keyResp = await fetch(`/file_key/${fileId}`);
            if (!keyResp.ok) throw new Error("You do not have access to update this file.");
            const { wrapped_key } = await keyResp.json();
            const wrappedKeyBuf = base64ToArrayBuffer(wrapped_key);

            // Load identity and unwrap the raw AES FEK
            const identity = await getIdentity();
            if (!identity || !identity.encPriv || !identity.signPriv) {
                throw new Error("Full identity required to update files.");
            }
            const rawAes = await unwrapRawKeyForOwner(identity.encPriv, wrappedKeyBuf);

            // Import the unwrapped FEK for encryption
            const aesKey = await crypto.subtle.importKey(
                "raw", 
                rawAes, 
                { name: "AES-GCM" }, 
                false, 
                ["encrypt"]
            );

            // Encrypt the NEW file buffer with the existing key and a NEW IV
            const fileBuf = await file.arrayBuffer();
            const newIv = generateRandomBytes(12);
            const newCiphertext = await crypto.subtle.encrypt(
                { name: "AES-GCM", iv: newIv }, 
                aesKey, 
                fileBuf
            );

            // Sign the new (IV || Ciphertext) payload
            const payload = concatBuffers(newIv.buffer, newCiphertext);
            const newSignature = await signPayloadWithIdentity(identity.signPriv, payload);

            // Submit the updated artifact to the server
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

    // Trigger the file picker
    input.click();
});
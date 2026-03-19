/**
 * @file key-rotate.js
 * @description Key rotation workflow for generating new keys and rewrapping owned file keys.
 */

/**
 * Rotates the current user's encryption and signing keys and rewraps accessible FEKs.
 *
 * @returns {Promise<void>}
 */
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

        const oldIdentity = await loadIdentity(uuid);
        if (!oldIdentity || !oldIdentity.encPriv) throw new Error("Old private key not found");

        const { publicKey: newEncPublicKey, privateKey: newEncPrivateKey } = await generateEncryptionKeyPair();
        const { publicKey: newSignPublicKey, privateKey: newSignPrivateKey } = await generateSigningKeyPair();
        const newEncPublicBase64 = await exportPublicKey(newEncPublicKey);
        const newEncPrivateBase64 = await exportPrivateKey(newEncPrivateKey);
        const newSignPublicBase64 = await exportPublicKey(newSignPublicKey);
        const newSignPrivateBase64 = await exportPrivateKey(newSignPrivateKey);

        const fileIds = await fetch("/my_files").then(r => r.json());

        for (const fileId of fileIds) {
            try {
                // Retrieve current user's wrapped FEK for each owned file.
                const keyResp = await fetch(`/file_key/${fileId}`);
                if (!keyResp.ok) continue;

                const { wrapped_key } = await keyResp.json();
                if (!wrapped_key) continue;

                const rawAes = await unwrapRawKeyFromBase64(oldIdentity.encPriv, wrapped_key);
                const rewrappedBuf = await wrapRawKeyWithPublicKey(newEncPublicKey, rawAes);
                const newWrapped = arrayBufferToBase64(rewrappedBuf);

                // Persist only this user's wrapped FEK replacement for the file.
                await fetch(`/rewrap_self/${fileId}`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ wrapped_key: newWrapped })
                });

            } catch (err) {
                console.error("Rewrap failed:", fileId, err);

                // Fail fast: a decrypt mismatch here means old identity cannot safely rewrap remaining files.
                showAlert({
                    title: "Invalid Private Key",
                    message: "The loaded private key cannot decrypt your files. Check your passphrase.",
                    type: "error"
                });

                return;
            }
        }

        const iv = generateRandomBytes(16);
        await fetch("/rotate_key", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                // Publish new public keys only after local rewrap loop succeeds.
                public_key: newEncPublicBase64,
                signing_public_key: newSignPublicBase64,
                iv: arrayBufferToBase64(iv)
            })
        });

        const newIdentity = {
            encPriv: newEncPrivateBase64,
            signPriv: newSignPrivateBase64,
            encPub: newEncPublicBase64,
            signPub: newSignPublicBase64,
            version: 1
        };

        await storeIdentity(uuid, newIdentity);
        // Export immediately so user can recover this newly-rotated identity later.
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

document.addEventListener("DOMContentLoaded", () => {
    const rotateBtn = document.getElementById("rotate-key-btn");
    if (rotateBtn) rotateBtn.addEventListener("click", rotateVaultKey);
});

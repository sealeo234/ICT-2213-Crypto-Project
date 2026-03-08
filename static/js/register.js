/* ===============================
    Registration Flow
    - Username availability check
    - Keypair generation
    - Identity container export
    - Initial key material submit
================================ */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form");
    if (!form) return;

    form.addEventListener("submit", async e => {
        e.preventDefault();

        try {
            if (!checkCryptoSupport()) return;

            const username = form.querySelector('input[name="username"]').value.trim();
            if (!username) {
                showAlert({ title: "Registration Error", message: "Please enter a username", type: "error" });
                return;
            }

            console.log("Checking username:", username);
            const res = await fetch("/check_username", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username })
            });

            console.log("Response status:", res.status);
            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }

            const data = await res.json();
            console.log("Response data:", data);
            if (!data.available) {
                showAlert({ title: "Registration Error", message: "Username already exists. Choose another.", type: "error" });
                return;
            }

            // Generate encryption/signing keypairs and convert to storable base64
        const encPair = await generateEncryptionKeyPair();
        const signPair = await generateSigningKeyPair();
        const encPublicBase64 = await exportPublicKey(encPair.publicKey);
        const encPrivateBase64 = await exportPrivateKey(encPair.privateKey);
        const signPublicBase64 = await exportPublicKey(signPair.publicKey);
        const signPrivateBase64 = await exportPrivateKey(signPair.privateKey);

        const identity = {
            encPriv: encPrivateBase64,
            signPriv: signPrivateBase64,
            encPub: encPublicBase64,
            signPub: signPublicBase64,
            version: 1
        };

        // Require local identity export before allowing registration to proceed
        try {
            await exportIdentityWithPrompt(identity);
        } catch (err) {
            showAlert({
                title: "Identity Export Failed",
                message: err.message,
                type: "error"
            });
            return;
        }

        // Registration metadata IV expected by backend schema
        const iv = generateRandomBytes(16);
        const ivBase64 = arrayBufferToBase64(iv);

        form.insertAdjacentHTML("beforeend", `
            <input type="hidden" name="public_key" value="${encPublicBase64}">
            <input type="hidden" name="signing_public_key" value="${signPublicBase64}">
            <input type="hidden" name="iv" value="${ivBase64}">
        `);

        // Persist identity only after successful export
        const uuidMeta = document.querySelector('meta[name="user-uuid"]');
        if (uuidMeta) {
            await storeIdentity(uuidMeta.content, identity);
        } else {
            // Store to temp pending key in IndexedDB for remote access compatibility
            // This will be migrated to the proper user-uuid after registration completes
            await storeIdentity("__pending__", identity);
            console.log("[Vault] Identity stored as pending for post-registration migration");
        }

        form.submit();
        } catch (err) {
            console.error("Registration error:", err);
            showAlert({ title: "Registration Error", message: err.message || "An unexpected error occurred", type: "error" });
        }
    });
});

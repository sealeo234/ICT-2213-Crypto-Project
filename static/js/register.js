/**
 * @file register.js
 * @description Registration workflow that provisions cryptographic identity and submits public key metadata.
 */
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

            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }

            const data = await res.json();
            if (!data.available) {
                showAlert({ title: "Registration Error", message: "Username already exists. Choose another.", type: "error" });
                return;
            }

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

            try {
                // Force user to export encrypted identity so recovery is possible before account creation.
                await exportIdentityWithPrompt(identity);
            } catch (err) {
                showAlert({
                    title: "Identity Export Failed",
                    message: err.message,
                    type: "error"
                });
                return;
            }

            const iv = generateRandomBytes(16);
            const ivBase64 = arrayBufferToBase64(iv);

            form.insertAdjacentHTML("beforeend", `
                <input type="hidden" name="public_key" value="${encPublicBase64}">
                <input type="hidden" name="signing_public_key" value="${signPublicBase64}">
                <input type="hidden" name="iv" value="${ivBase64}">
            `);

            try {
                // Keep a pending copy before backend registration completes and UUID is finalized.
                await storeIdentity("__pending__", identity);
                
                const verifyIdentity = await loadIdentity("__pending__");
                if (!verifyIdentity) {
                    throw new Error("Identity write verification failed");
                }
                
                sessionStorage.setItem("pending_identity", JSON.stringify(identity));
                // Session fallback helps if IndexedDB write is delayed or blocked.
                sessionStorage.setItem("__pending_migration__", "true");
                console.log("[Vault] Pending migration flag set in sessionStorage");
            } catch (err) {
                console.error("[Vault] Failed to store identity to IndexedDB:", err);
                showAlert({
                    title: "Storage Error",
                    message: "Failed to store cryptographic identity. Please try again.",
                    type: "error"
                });
                return;
            }

            console.log("[Vault] Waiting for database transaction to complete...");
            // Small delay reduces risk of racing form navigation with IndexedDB persistence.
            await new Promise(resolve => setTimeout(resolve, 200));
            console.log("[Vault] Submitting registration form...");
            form.submit();
        } catch (err) {
            console.error("Registration error:", err);
            showAlert({ title: "Registration Error", message: err.message || "An unexpected error occurred", type: "error" });
        }
    });
});
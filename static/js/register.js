document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form");
    if (!form) return;

    form.addEventListener("submit", async e => {
        e.preventDefault();

        const username = form.querySelector('input[name="username"]').value.trim();
        if (!username) {
            showAlert({ title: "Registration Error", message: "Please enter a username", type: "error" });
            return;
        }

        const res = await fetch("/check_username", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username })
        });

        const data = await res.json();
        if (!data.available) {
            showAlert({ title: "Registration Error", message: "Username already exists. Choose another.", type: "error" });
            return;
        }

        // Generate RSA keypair
        const keyPair = await generateKeyPair();
        const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);
        const privateKeyBase64 = await exportPrivateKey(keyPair.privateKey);

        // Force export FIRST
        try {
            await exportPrivateKeyWithPrompt(privateKeyBase64);
        } catch (err) {
            showAlert({
                title: "Private Key Export Failed",
                message: err.message,
                type: "error"
            });
            return; // stop registration completely
        }

        // Generate IV
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const ivBase64 = arrayBufferToBase64(iv);

        form.insertAdjacentHTML("beforeend", `
            <input type="hidden" name="public_key" value="${publicKeyBase64}">
            <input type="hidden" name="iv" value="${ivBase64}">
        `);

        // Store private key only AFTER successful export
        const uuidMeta = document.querySelector('meta[name="user-uuid"]');
        if (uuidMeta) {
            await storePrivateKey(uuidMeta.content, privateKeyBase64);
        } else {
            sessionStorage.setItem("pending_private_key", privateKeyBase64);
        }

        form.submit();
    });
});

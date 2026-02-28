/* ===============================
    Access Update Flow (Owner)
    - Resolve selected recipients
    - Recover FEK from owner wrapped key
    - Rewrap FEK for new recipients
    - Submit updated wrapped key map
================================ */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form[data-edit-access]");
    if (!form) return;

    form.addEventListener("submit", async e => {
        e.preventDefault();
        if (!(await ensurePrivateKeyPresent())) return;

        try {
            const fileId = form.dataset.fileId;
            const selfUUID = document.querySelector('meta[name="user-uuid"]').content;

            // Ensure owner remains in access list
            let submittedRecipients = [...form.querySelectorAll("input[name='recipients']:checked")]
                .map(cb => cb.value);
            if (!submittedRecipients.includes(selfUUID)) submittedRecipients.push(selfUUID);

            // Current wrapped FEKs indexed by recipient UUID
            const allKeysResp = await fetch(`/file_key/${fileId}?all=true`);
            const currentKeys = await allKeysResp.json();

            // Recover raw FEK via owner's wrapped key
            const ownerWrappedKeyBase64 = currentKeys[selfUUID];
            const rawAes = await (async () => {
                const identity = await getIdentity();
                if (!identity || !identity.encPriv) throw new Error("Private key not found");
                return unwrapRawKeyFromBase64(identity.encPriv, ownerWrappedKeyBase64);
            })();

            // Build outgoing wrapped key map, always preserving owner key
            const wrappedKeys = {};
            wrappedKeys[selfUUID] = ownerWrappedKeyBase64;

            // Wrap FEK only for recipients newly added in this submission
            const newRecipients = submittedRecipients.filter(uuid => !(uuid in currentKeys) && uuid !== selfUUID);
            if (newRecipients.length > 0) {
                const pubKeyMap = await fetch("/recipient_keys", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ recipients: newRecipients })
                }).then(r => r.json());

                for (const [uuid, pubBase64] of Object.entries(pubKeyMap)) {
                    const wrapped = await wrapRawKeyForRecipient(pubBase64, rawAes);
                    wrappedKeys[uuid] = arrayBufferToBase64(wrapped);
                }
            }

            // Preserve existing wrapped keys for unchanged recipients
            for (const uuid of submittedRecipients) {
                if (!(uuid in wrappedKeys)) wrappedKeys[uuid] = currentKeys[uuid];
            }

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

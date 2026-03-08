/* ===============================
    Access Update Flow (Owner)
    - Search for users to add
    - Resolve selected recipients
    - Recover FEK from owner wrapped key
    - Rewrap FEK for new recipients
    - Submit updated wrapped key map
================================ */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form[data-edit-access]");
    if (!form) return;

    // --- NEW: User Search Logic ---
    const searchBtn = document.getElementById("search-btn");
    const searchInput = document.getElementById("search-username");
    const container = document.getElementById("recipients-container");
    const searchError = document.getElementById("search-error");
    const emptyState = document.getElementById("empty-state");

    if (searchBtn && searchInput) {
        searchBtn.addEventListener("click", async () => {
            const username = searchInput.value.trim();
            if (!username) return;

            searchError.classList.add("hidden");
            searchBtn.disabled = true;
            searchBtn.textContent = "Searching...";

            try {
                // Expected backend endpoint: GET /search_user?username=XYZ
                const res = await fetch(`/search_user?username=${encodeURIComponent(username)}`);
                
                if (!res.ok) {
                    if (res.status === 404) throw new Error("User not found.");
                    throw new Error("Failed to search for user.");
                }
                
                const user = await res.json();

                // Prevent duplicates in the UI
                if (document.querySelector(`input[value="${user.uuid}"]`)) {
                    throw new Error("User is already in the access list.");
                }

                // Remove empty state text if present
                if (emptyState) emptyState.remove();

                // Append the new user to the form as a checked item
                const userHtml = `
                    <label class="flex items-center justify-between p-4 rounded-xl bg-white/5 hover:bg-white/10 transition cursor-pointer animate-slide-up">
                        <div>
                            <p class="font-medium text-slate-300">${user.username}</p>
                            <p class="text-xs text-slate-500 font-mono">${user.uuid}</p>
                        </div>
                        <div>
                            <input type="checkbox" name="recipients" value="${user.uuid}" checked class="w-5 h-5 accent-yellow-400 cursor-pointer">
                        </div>
                    </label>
                `;
                container.insertAdjacentHTML("beforeend", userHtml);
                searchInput.value = ""; // Clear input on success

            } catch(err) {
                searchError.textContent = err.message;
                searchError.classList.remove("hidden");
            } finally {
                searchBtn.disabled = false;
                searchBtn.textContent = "Find User";
            }
        });

        // Allow pressing Enter in the search bar
        searchInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                searchBtn.click();
            }
        });
    }

    // --- Existing: Save Changes Logic ---
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
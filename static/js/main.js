document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const selectBtn = document.getElementById('select-btn');
    const uploadForm = document.getElementById('upload-form');

    // --- 1. Vault Key Sync Watcher ---
    const body = document.body;
    const isAuthenticated = body.getAttribute('data-authenticated') === 'true';
    const hasKey = body.getAttribute('data-has-key') === 'true';

    if (isAuthenticated && !hasKey) {
        const pollServer = async () => {
            try {
                const response = await fetch('/api/me');
                if (response.ok) {
                    const data = await response.json();
                    if (data.authenticated && data.has_key) {
                        window.location.reload();
                    }
                }
            } catch (err) {
                console.error("Polling error:", err);
            }
        };
        setInterval(pollServer, 2000);
    }

    // --- 2. Centralized Upload Logic (ID-Agnostic + Stack-Safe) ---
    const handleUpload = async () => {
        const file = fileInput.files[0];
        const recipientKey = document.body.getAttribute('data-public-key');
        
        // Check if the key exists and isn't just a placeholder like "None" or ""
        if (!recipientKey || recipientKey === "None" || recipientKey === "") {
            alert("No encryption key found.\n\nPlease open the Secure Vault Extension and click 'Generate/Sync Keys' before uploading.");
            
            // Reset the file input so they can try again after syncing
            fileInput.value = ""; 
            return;
        }

        if (!file) return;
        
        if (!recipientKey) {
            alert("Security Error: No public key found. Please sync your extension first.");
            return;
        }

        if (selectBtn) {
            selectBtn.innerText = "Encrypting...";
            selectBtn.disabled = true;
        }

        // Use FileReader to get Base64 - This avoids "Maximum call stack size exceeded"
        const reader = new FileReader();
        
        reader.onload = async () => {
            // result is "data:application/octet-stream;base64,XXXXX..."
            // We only want the part after the comma
            const base64String = reader.result.split(',')[1];

            // A. Create the listener for the response from the extension
            const onResponse = async (event) => {
                const response = event.detail;
                window.removeEventListener("VAULT_ENCRYPT_RESPONSE", onResponse);
            
                if (!response || response.error) {
                    alert("Encryption failed.");
                    resetUI();
                    return;
                }
            
                // Prepare the final payload for the server
                const finalPayload = response.encryptedPayload;
                
                finalPayload.originalName = file.name; 
            
                try {
                    const uploadRes = await fetch('/upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            filename: file.name + ".json", // The server sees the .json file
                            payload: finalPayload          // The JSON inside contains the original name
                        })
                    });

                    if (uploadRes.ok) {
                        window.location.reload();
                    } else {
                        const errData = await uploadRes.json();
                        alert("Upload failed: " + errData.error);
                        resetUI();
                    }
                } catch (e) {
                    console.error("Network error:", e);
                    resetUI();
                }
            };

            window.addEventListener("VAULT_ENCRYPT_RESPONSE", onResponse);

            // C. Dispatch the encryption request using Base64 string instead of byte array
            window.dispatchEvent(new CustomEvent("VAULT_ENCRYPT_REQUEST", {
                detail: { 
                    plaintextB64: base64String, 
                    recipientPublicKey: recipientKey 
                }
            }));
        };

        reader.onerror = (err) => {
            console.error("FileReader error:", err);
            alert("Failed to read file.");
            resetUI();
        };

        reader.readAsDataURL(file);
    };

    const resetUI = () => {
        if (selectBtn) {
            selectBtn.innerText = "Select File";
            selectBtn.disabled = false;
        }
    };

    // --- 3. UI Interaction Listeners ---
    if (selectBtn && fileInput && uploadForm) {
        selectBtn.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) handleUpload(); 
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.add('border-blue-500', 'bg-blue-500/10');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                dropzone.classList.remove('border-blue-500', 'bg-blue-500/10');
            });
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files; 
                handleUpload(); 
            }
        });

        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            handleUpload();
        });
    }
});
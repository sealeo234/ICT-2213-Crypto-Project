document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const selectBtn = document.getElementById('select-btn');
    const uploadForm = document.getElementById('upload-form');
    const EXTENSION_ID = "igjjekfjfleoeifbaodgfmadfnegdedp";

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

    // --- 2. Centralized Upload Logic (ID-Agnostic Bridge) ---
    const handleUpload = async () => {
        const file = fileInput.files[0];
        const recipientKey = document.body.getAttribute('data-public-key');
        
        if (!file) return;
        
        if (!recipientKey) {
            alert("Security Error: No public key found. Please sync your extension first.");
            return;
        }

        if (selectBtn) {
            selectBtn.innerText = "Encrypting...";
            selectBtn.disabled = true;
        }

        try {
            // Read file into an ArrayBuffer then to a Byte Array
            const arrayBuffer = await file.arrayBuffer();
            const bytes = Array.from(new Uint8Array(arrayBuffer));

            /**
             * NEW: Instead of chrome.runtime.sendMessage(ID), 
             * we dispatch a CustomEvent. content.js will catch this.
             */
            
            // A. Create the listener for the response from the extension
            const onResponse = async (event) => {
                const response = event.detail;
                window.removeEventListener("VAULT_ENCRYPT_RESPONSE", onResponse);

                if (!response || response.error) {
                    alert("Encryption failed: " + (response?.error || "Extension not responding"));
                    resetUI();
                    return;
                }

                // B. Proceed with JSON upload to Flask
                try {
                    const uploadRes = await fetch('/upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            filename: file.name + ".json",
                            payload: response.encryptedPayload
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

            // C. Dispatch the encryption request
            window.dispatchEvent(new CustomEvent("VAULT_ENCRYPT_REQUEST", {
                detail: { 
                    plaintext: bytes, 
                    recipientPublicKey: recipientKey 
                }
            }));

        } catch (e) {
            console.error("File reading error:", e);
            resetUI();
        }
    };

    const resetUI = () => {
        if (selectBtn) {
            selectBtn.innerText = "Select File";
            selectBtn.disabled = false;
        }
    };

    // --- 3. Page Aesthetics and Event Listeners ---
    if (selectBtn && fileInput && uploadForm) {
        
        selectBtn.addEventListener('click', () => {
            fileInput.click();
        });

        // Intercept change event
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleUpload(); 
            }
        });

        // Drag & Drop
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

        // Prevent traditional form submission
        uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            handleUpload();
        });
    }
});
document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const selectBtn = document.getElementById('select-btn');
    const uploadForm = document.getElementById('upload-form');

    if (selectBtn && fileInput && uploadForm) {
        
        // 1. Trigger the file picker when the sleek button is clicked
        selectBtn.addEventListener('click', () => {
            fileInput.click();
        });

        // 2. AUTO-SUBMIT when a file is selected via the picker
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                uploadForm.submit();
            }
        });

        // 3. Drag & Drop Visual Feedback
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

        // 4. Handle files dropped directly onto the zone
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files; // Manual assignment
                uploadForm.submit();    // Trigger upload
            }
        });
    }
});
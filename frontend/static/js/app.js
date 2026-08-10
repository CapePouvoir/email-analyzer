/**
 * Email Forensic Analyzer - Frontend JavaScript
 * Handles drag & drop, file upload, and result display
 */

// ============================================================================
// DOM Elements
// ============================================================================

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const resultsSection = document.getElementById('resultsSection');
const resultsContent = document.getElementById('resultsContent');
const errorSection = document.getElementById('errorSection');
const errorMessage = document.getElementById('errorMessage');
const toast = document.getElementById('toast');

// ============================================================================
// Drag & Drop Functionality
// ============================================================================

// Prevent default drag behaviors
document.addEventListener('dragover', (e) => {
    e.preventDefault();
});

document.addEventListener('drop', (e) => {
    e.preventDefault();
});

// Highlight drop zone when item is dragged over
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    
    if (e.dataTransfer.files.length) {
        handleFiles(e.dataTransfer.files);
    }
});

// Click on drop zone to open file dialog
dropZone.addEventListener('click', () => {
    fileInput.click();
});

// Handle file selection from dialog
fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
        handleFiles(fileInput.files);
    }
});

// ============================================================================
// File Handling
// ============================================================================

/**
 * Handle uploaded files
 * @param {FileList} files - Files to process
 */
function handleFiles(files) {
    // Reset previous state
    resetUpload();
    
    const file = files[0];
    
    // Validate file
    if (!validateFile(file)) {
        return;
    }
    
    // Show loading state
    showLoading();
    
    // Upload file
    uploadFile(file);
}

/**
 * Validate file before upload
 * @param {File} file - File to validate
 * @returns {boolean} - Whether file is valid
 */
function validateFile(file) {
    // Check file type
    if (!file.name.toLowerCase().endsWith('.eml')) {
        showError('Seuls les fichiers .eml sont acceptés.');
        return false;
    }
    
    // Check file size (50MB max)
    const maxSize = 50 * 1024 * 1024; // 50MB
    if (file.size > maxSize) {
        showError(`Le fichier est trop volumineux. Maximum autorisé : 50 Mo.`);
        return false;
    }
    
    return true;
}

/**
 * Upload file to server
 * @param {File} file - File to upload
 */
async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData,
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Erreur lors de l\'upload.');
        }
        
        const result = await response.json();
        displayResults(result);
        showToast(`Fichier ${file.name} uploadé avec succès!`, 'success');
        
    } catch (error) {
        showError(error.message);
    }
}

// ============================================================================
// UI State Management
// ============================================================================

/**
 * Show loading state
 */
function showLoading() {
    dropZone.style.display = 'none';
    resultsSection.style.display = 'block';
    resultsContent.innerHTML = `
        <div style="text-align: center; padding: 2rem;">
            <div class="loading-spinner"></div>
            <p style="margin-top: 1rem; color: var(--text-secondary);">Analyse en cours...</p>
        </div>
    `;
}

/**
 * Display analysis results
 * @param {Object} data - Analysis results from server
 */
function displayResults(data) {
    // Check if we have a full report
    if (data.report && data.report.markdown) {
        // Render markdown to HTML using marked.js
        const renderedHtml = marked.parse(data.report.markdown);
        
        resultsContent.innerHTML = `
            <div class="markdown-report markdown-body">
                ${renderedHtml}
                <div style="margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                    <button class="btn btn-primary" onclick="downloadReport('${data.report.hash}', '${data.report.filename}')">
                        📥 Télécharger le rapport
                    </button>
                </div>
            </div>
        `;
        
        // Update header with severity
        const severityEmoji = getSeverityEmoji(data.report.severity);
        const severityText = data.report.severity.toUpperCase();
        document.querySelector('.results-header h2').innerHTML = 
            `${severityEmoji} Analyse terminée - ${severityText} (Score: ${data.report.score}/100)`;
    } else {
        // Fallback for old responses
        resultsContent.innerHTML = `
            <div class="markdown-report">
                <h2>✅ Analyse terminée</h2>
                <p><strong>Fichier :</strong> ${data.filename}</p>
                <p><strong>Taille :</strong> ${formatFileSize(data.size)}</p>
                <p><strong>Statut :</strong> ${data.status}</p>
                
                <h3>Prochaines étapes</h3>
                <ul>
                    ${data.next_steps ? data.next_steps.map(step => `<li>${step}</li>`).join('') : ''}
                </ul>
            </div>
        `;
    }
}

/**
 * Download report as Markdown file
 */
function downloadReport(hash, filename) {
    // Create a blob with the markdown content
    const markdown = document.querySelector('.markdown-report').textContent;
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    
    // Create download link
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || `report_${hash}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Rapport téléchargé avec succès!', 'success');
}

/**
 * Get severity emoji
 */
function getSeverityEmoji(severity) {
    const emojis = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'benign': '✅'
    };
    return emojis[severity] || '⚠️';
}

/**
 * Show error message
 * @param {string} message - Error message to display
 */
function showError(message) {
    errorMessage.textContent = message;
    errorSection.style.display = 'block';
    dropZone.style.display = 'none';
    resultsSection.style.display = 'none';
}

/**
 * Reset upload state
 */
function resetUpload() {
    dropZone.style.display = 'block';
    resultsSection.style.display = 'none';
    errorSection.style.display = 'none';
    fileInput.value = '';
}

/**
 * Show toast notification
 * @param {string} message - Message to display
 * @param {string} type - Toast type (success, error, warning)
 */
function showToast(message, type = 'info') {
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 5000);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Format file size in human-readable format
 * @param {number} bytes - File size in bytes
 * @returns {string} - Formatted size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 octets';
    
    const k = 1024;
    const sizes = ['octets', 'Ko', 'Mo', 'Go'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// Admin Functions
// ============================================================================

/**
 * Check admin password (for future admin interface)
 */
async function checkAdminPassword(password) {
    // TODO: Implement admin auth
    return true;
}

// ============================================================================
// Keyboard Shortcuts
// ============================================================================

// Allow Ctrl+V to paste file
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'v') {
        e.preventDefault();
        // Get clipboard files
        if (e.clipboardData && e.clipboardData.files.length) {
            handleFiles(e.clipboardData.files);
        }
    }
});

// ============================================================================
// Initialize
// ============================================================================

// Add global function for HTML onclick handlers
window.resetUpload = resetUpload;

console.log('🚀 Email Forensic Analyzer - Frontend initialized');

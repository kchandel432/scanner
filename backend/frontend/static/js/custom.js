/**
 * Custom JavaScript for Cyber Risk Intelligence Platform
 */

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    initClipboard();
    initFileUpload();
    initRiskCharts();
    initScanButtons();
    initThemeToggle();
    initResponsiveTables();
});

// Tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', function(e) {
            const tooltipText = this.getAttribute('data-tooltip');
            if (!tooltipText) return;
            
            const tooltip = document.createElement('div');
            tooltip.className = 'fixed z-50 px-3 py-2 text-sm bg-gray-900 text-white rounded-lg shadow-lg max-w-xs';
            tooltip.textContent = tooltipText;
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.left = `${rect.left + rect.width / 2 - tooltip.offsetWidth / 2}px`;
            tooltip.style.top = `${rect.top - tooltip.offsetHeight - 10}px`;
            
            this._tooltip = tooltip;
        });
        
        element.addEventListener('mouseleave', function() {
            if (this._tooltip) {
                this._tooltip.remove();
                this._tooltip = null;
            }
        });
    });
}

// Clipboard
function initClipboard() {
    const copyButtons = document.querySelectorAll('[data-copy]');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const textToCopy = this.getAttribute('data-copy');
            
            try {
                await navigator.clipboard.writeText(textToCopy);
                
                // Show success feedback
                const originalText = this.innerHTML;
                this.innerHTML = '<span class="text-green-400">✓ Copied!</span>';
                
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            } catch (err) {
                console.error('Failed to copy:', err);
                this.innerHTML = '<span class="text-red-400">✗ Failed</span>';
                
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            }
        });
    });
}

// File Upload
function initFileUpload() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const files = Array.from(this.files);
            const preview = document.getElementById(`${this.id}-preview`);
            
            if (!preview) return;
            
            preview.innerHTML = '';
            
            files.forEach((file, index) => {
                const fileSize = formatFileSize(file.size);
                const fileType = file.type || 'Unknown';
                
                const fileElement = document.createElement('div');
                fileElement.className = 'flex items-center justify-between p-3 bg-gray-800/50 rounded-lg mb-2';
                fileElement.innerHTML = `
                    <div class="flex items-center space-x-3">
                        <div class="p-2 bg-gray-700 rounded-lg">
                            <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                        </div>
                        <div>
                            <p class="font-medium text-white text-sm truncate max-w-xs">${file.name}</p>
                            <p class="text-xs text-gray-400">${fileSize} • ${fileType}</p>
                        </div>
                    </div>
                    <button type="button" class="text-gray-400 hover:text-red-400 remove-file" data-index="${index}">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </button>
                `;
                
                preview.appendChild(fileElement);
            });
            
            // Add remove file functionality
            preview.querySelectorAll('.remove-file').forEach(button => {
                button.addEventListener('click', function() {
                    const index = parseInt(this.getAttribute('data-index'));
                    const dt = new DataTransfer();
                    
                    // Recreate file list without the removed file
                    Array.from(input.files).forEach((file, i) => {
                        if (i !== index) {
                            dt.items.add(file);
                        }
                    });
                    
                    input.files = dt.files;
                    initFileUpload(); // Reinitialize
                });
            });
        });
    });
}

// Risk Charts
function initRiskCharts() {
    const riskCharts = document.querySelectorAll('.risk-chart');
    
    riskCharts.forEach(chartElement => {
        const ctx = chartElement.getContext('2d');
        const riskScore = parseFloat(chartElement.dataset.riskScore) || 0;
        const riskLevel = chartElement.dataset.riskLevel || 'medium';
        
        // Determine colors based on risk level
        const colors = {
            critical: { gradient: ['#ef4444', '#b91c1c'], text: '#ef4444' },
            high: { gradient: ['#f97316', '#ea580c'], text: '#f97316' },
            medium: { gradient: ['#eab308', '#ca8a04'], text: '#eab308' },
            low: { gradient: ['#22c55e', '#16a34a'], text: '#22c55e' },
            clean: { gradient: ['#06b6d4', '#0284c7'], text: '#06b6d4' }
        };
        
        const color = colors[riskLevel] || colors.medium;
        
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [riskScore, 100 - riskScore],
                    backgroundColor: [
                        color.gradient[0],
                        'rgba(75, 85, 99, 0.3)'
                    ],
                    borderWidth: 0,
                    cutout: '80%'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        enabled: false
                    }
                },
                animation: {
                    animateScale: true,
                    animateRotate: true,
                    duration: 1000
                }
            },
            plugins: [{
                id: 'centerText',
                beforeDraw: function(chart) {
                    const width = chart.width;
                    const height = chart.height;
                    const ctx = chart.ctx;
                    
                    ctx.restore();
                    const fontSize = (height / 150).toFixed(2);
                    ctx.font = `${fontSize}em sans-serif`;
                    ctx.textBaseline = 'middle';
                    
                    const text = `${riskScore.toFixed(0)}`;
                    const textX = Math.round((width - ctx.measureText(text).width) / 2);
                    const textY = height / 2 - 10;
                    
                    ctx.fillStyle = color.text;
                    ctx.fillText(text, textX, textY);
                    
                    // Risk level text
                    const levelFontSize = (height / 300).toFixed(2);
                    ctx.font = `bold ${levelFontSize}em sans-serif`;
                    const levelText = riskLevel.toUpperCase();
                    const levelX = Math.round((width - ctx.measureText(levelText).width) / 2);
                    const levelY = height / 2 + 15;
                    
                    ctx.fillText(levelText, levelX, levelY);
                    
                    ctx.save();
                }
            }]
        });
    });
}

// Scan Buttons
function initScanButtons() {
    const scanButtons = document.querySelectorAll('[data-scan-action]');
    
    scanButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const action = this.getAttribute('data-scan-action');
            const scanId = this.getAttribute('data-scan-id');
            
            if (!scanId) return;
            
            // Show loading state
            const originalText = this.innerHTML;
            this.innerHTML = '<span class="spinner-soc"></span>';
            this.disabled = true;
            
            try {
                let response;
                
                switch (action) {
                    case 'cancel':
                        response = await fetch(`/api/v1/scans/${scanId}/cancel`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' }
                        });
                        break;
                        
                    case 'retry':
                        response = await fetch(`/api/v1/scans/${scanId}/retry`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' }
                        });
                        break;
                        
                    case 'download':
                        window.location.href = `/api/v1/scans/${scanId}/report`;
                        return;
                }
                
                if (response && response.ok) {
                    const data = await response.json();
                    
                    // Show success message
                    showToast('Success', data.message || 'Action completed successfully', 'success');
                    
                    // Reload scan status if using HTMX
                    if (window.htmx) {
                        const scanElement = document.querySelector(`[data-scan-id="${scanId}"]`);
                        if (scanElement) {
                            htmx.trigger(scanElement, 'refresh');
                        }
                    }
                } else {
                    throw new Error('Action failed');
                }
                
            } catch (error) {
                console.error('Scan action error:', error);
                showToast('Error', 'Failed to perform action', 'error');
            } finally {
                // Restore button state
                setTimeout(() => {
                    this.innerHTML = originalText;
                    this.disabled = false;
                }, 1000);
            }
        });
    });
}

// Theme Toggle
function initThemeToggle() {
    const themeToggle = document.querySelector('[data-theme-toggle]');
    if (!themeToggle) return;
    
    // Check for saved theme preference or default to dark
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.classList.toggle('dark', savedTheme === 'dark');
    
    themeToggle.addEventListener('click', function() {
        const isDark = document.documentElement.classList.toggle('dark');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        
        // Update icon
        const icon = this.querySelector('svg');
        if (icon) {
            if (isDark) {
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path>';
            } else {
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path>';
            }
        }
    });
}

// Responsive Tables
function initResponsiveTables() {
    const tables = document.querySelectorAll('table');
    
    tables.forEach(table => {
        if (table.scrollWidth > table.clientWidth) {
            table.parentElement.classList.add('overflow-x-auto');
        }
    });
}

// Utility Functions
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showToast(title, message, type = 'info') {
    const toastId = 'toast-' + Date.now();
    
    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ'
    };
    
    const colors = {
        success: 'bg-green-900/90 border-green-700',
        error: 'bg-red-900/90 border-red-700',
        warning: 'bg-yellow-900/90 border-yellow-700',
        info: 'bg-blue-900/90 border-blue-700'
    };
    
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `fixed bottom-4 right-4 z-50 ${colors[type]} border rounded-lg p-4 shadow-lg max-w-sm transform transition-transform duration-300 translate-y-full`;
    toast.innerHTML = `
        <div class="flex items-start">
            <div class="flex-shrink-0 text-xl text-white">${icons[type]}</div>
            <div class="ml-3">
                <h4 class="font-semibold text-white">${title}</h4>
                <p class="text-sm text-gray-200 mt-1">${message}</p>
            </div>
            <button onclick="document.getElementById('${toastId}').remove()" 
                    class="ml-auto text-gray-300 hover:text-white">
                ×
            </button>
        </div>
    `;
    
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => {
        toast.classList.remove('translate-y-full');
    }, 10);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.classList.add('translate-y-full');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Export utilities to window
window.formatFileSize = formatFileSize;
window.showToast = showToast;

// HTMX extensions
if (window.htmx) {
    // Add class to elements being swapped
    htmx.defineExtension('swap-class', {
        onEvent: function(name, evt) {
            if (name === 'htmx:beforeSwap') {
                const target = evt.detail.target;
                target.classList.add('swapping');
            }
            
            if (name === 'htmx:afterSwap') {
                const target = evt.detail.target;
                target.classList.remove('swapping');
            }
        }
    });
    
    // Error handling
    htmx.on('htmx:responseError', function(evt) {
        showToast('Error', 'Request failed. Please try again.', 'error');
    });
    
    // Show loading indicators
    htmx.on('htmx:beforeRequest', function(evt) {
        const target = evt.detail.target;
        const indicator = target.querySelector('.htmx-indicator');
        if (indicator) {
            indicator.classList.remove('hidden');
        }
    });
    
    htmx.on('htmx:afterRequest', function(evt) {
        const target = evt.detail.target;
        const indicator = target.querySelector('.htmx-indicator');
        if (indicator) {
            indicator.classList.add('hidden');
        }
    });
}
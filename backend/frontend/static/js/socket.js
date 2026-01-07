/**
 * WebSocket client for real-time updates
 */

class ScanWebSocket {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.subscriptions = new Map();
        this.messageHandlers = new Map();
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            this.socket = new WebSocket(wsUrl);
            this.setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection failed:', error);
            this.scheduleReconnect();
        }
    }

    setupEventHandlers() {
        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
            this.reconnectDelay = 1000;
            
            // Re-subscribe to all previous subscriptions
            this.subscriptions.forEach((data, channel) => {
                this.subscribe(channel, data.handler);
            });
            
            // Show connection status
            this.showNotification('Connected', 'Real-time updates enabled', 'success');
        };

        this.socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.socket.onclose = (event) => {
            console.log('WebSocket disconnected:', event.code, event.reason);
            
            if (event.code !== 1000) { // Normal closure
                this.scheduleReconnect();
            }
            
            this.showNotification('Disconnected', 'Real-time updates paused', 'warning');
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            this.showNotification('Connection Lost', 'Unable to reconnect. Please refresh the page.', 'error');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
        
        console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
        
        setTimeout(() => {
            this.connect();
        }, delay);
    }

    subscribe(channel, handler) {
        const subscriptionId = Math.random().toString(36).substr(2, 9);
        
        this.subscriptions.set(channel, {
            id: subscriptionId,
            handler: handler
        });

        this.messageHandlers.set(subscriptionId, handler);

        // Send subscription message if connected
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'subscribe',
                channel: channel,
                id: subscriptionId
            }));
        }

        return subscriptionId;
    }

    unsubscribe(subscriptionId) {
        let channelToUnsubscribe = null;
        
        // Find channel for this subscription
        this.subscriptions.forEach((data, channel) => {
            if (data.id === subscriptionId) {
                channelToUnsubscribe = channel;
            }
        });

        if (channelToUnsubscribe) {
            this.subscriptions.delete(channelToUnsubscribe);
            
            if (this.socket && this.socket.readyState === WebSocket.OPEN) {
                this.socket.send(JSON.stringify({
                    type: 'unsubscribe',
                    channel: channelToUnsubscribe,
                    id: subscriptionId
                }));
            }
        }

        this.messageHandlers.delete(subscriptionId);
    }

    handleMessage(data) {
        const { type, channel, payload } = data;

        switch (type) {
            case 'scan_update':
                this.handleScanUpdate(payload);
                break;
            case 'alert':
                this.handleAlert(payload);
                break;
            case 'system_status':
                this.handleSystemStatus(payload);
                break;
            case 'progress':
                this.handleProgressUpdate(payload);
                break;
            default:
                // Check for channel-specific handlers
                if (channel && this.subscriptions.has(channel)) {
                    const subscription = this.subscriptions.get(channel);
                    if (subscription.handler) {
                        subscription.handler(payload);
                    }
                }
        }
    }

    handleScanUpdate(data) {
        const { scan_id, status, progress, message } = data;
        
        // Update scan status in UI
        const scanElement = document.querySelector(`[data-scan-id="${scan_id}"]`);
        if (scanElement) {
            if (progress !== undefined) {
                const progressBar = scanElement.querySelector('.scan-progress-bar');
                if (progressBar) {
                    progressBar.style.width = `${progress}%`;
                }
                
                const progressText = scanElement.querySelector('.scan-progress-text');
                if (progressText) {
                    progressText.textContent = `${progress}%`;
                }
            }
            
            if (message) {
                const statusElement = scanElement.querySelector('.scan-status');
                if (statusElement) {
                    statusElement.textContent = message;
                }
            }
            
            if (status === 'completed' || status === 'failed') {
                scanElement.classList.remove('scan-in-progress');
                
                // Trigger HTMX refresh if available
                if (window.htmx) {
                    htmx.trigger(scanElement, 'scanComplete');
                }
            }
        }
        
        // Show notification for completed scans
        if (status === 'completed') {
            this.showNotification('Scan Complete', `Scan ${scan_id} completed successfully`, 'success');
        } else if (status === 'failed') {
            this.showNotification('Scan Failed', `Scan ${scan_id} failed: ${message}`, 'error');
        }
    }

    handleAlert(data) {
        const { title, message, severity, timestamp } = data;
        
        this.showNotification(title, message, severity.toLowerCase());
        
        // Update alert badge
        const alertBadge = document.querySelector('.alert-badge');
        if (alertBadge) {
            const currentCount = parseInt(alertBadge.textContent) || 0;
            alertBadge.textContent = currentCount + 1;
            alertBadge.classList.remove('hidden');
        }
    }

    handleSystemStatus(data) {
        const { component, status, message } = data;
        
        // Update system status indicators
        const statusElement = document.querySelector(`[data-component="${component}"]`);
        if (statusElement) {
            const indicator = statusElement.querySelector('.status-indicator');
            const text = statusElement.querySelector('.status-text');
            
            if (indicator) {
                indicator.className = 'status-indicator';
                indicator.classList.add(`status-${status}`);
            }
            
            if (text) {
                text.textContent = message || status;
            }
        }
    }

    handleProgressUpdate(data) {
        const { task_id, progress, message } = data;
        
        // Find progress element
        const progressElement = document.querySelector(`[data-task-id="${task_id}"]`);
        if (progressElement) {
            // Update progress bar
            const progressBar = progressElement.querySelector('.progress-bar-fill');
            if (progressBar) {
                progressBar.style.width = `${progress}%`;
                progressBar.setAttribute('aria-valuenow', progress);
            }
            
            // Update progress text
            const progressText = progressElement.querySelector('.progress-text');
            if (progressText) {
                progressText.textContent = `${progress}%`;
            }
            
            // Update message
            const messageElement = progressElement.querySelector('.progress-message');
            if (messageElement) {
                messageElement.textContent = message;
            }
        }
    }

    showNotification(title, message, type = 'info') {
        const container = document.getElementById('notification-container');
        if (!container) return;
        
        const notificationId = 'notification-' + Date.now();
        
        const icons = {
            success: '✓',
            error: '✗',
            warning: '⚠',
            info: 'ℹ'
        };
        
        const colors = {
            success: 'bg-green-900/80 border-green-700 text-green-200',
            error: 'bg-red-900/80 border-red-700 text-red-200',
            warning: 'bg-yellow-900/80 border-yellow-700 text-yellow-200',
            info: 'bg-blue-900/80 border-blue-700 text-blue-200'
        };
        
        const notification = document.createElement('div');
        notification.id = notificationId;
        notification.className = `notification-enter ${colors[type]} border rounded-lg p-4 shadow-lg max-w-sm`;
        notification.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0 text-xl">${icons[type]}</div>
                <div class="ml-3">
                    <h4 class="font-semibold">${title}</h4>
                    <p class="text-sm mt-1 opacity-90">${message}</p>
                </div>
                <button onclick="document.getElementById('${notificationId}').remove()" 
                        class="ml-auto text-gray-400 hover:text-white">
                    ×
                </button>
            </div>
        `;
        
        container.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            const notif = document.getElementById(notificationId);
            if (notif) {
                notif.classList.add('notification-exit');
                setTimeout(() => notif.remove(), 300);
            }
        }, 5000);
    }

    sendMessage(type, data) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: type,
                ...data
            }));
            return true;
        }
        return false;
    }

    disconnect() {
        if (this.socket) {
            this.socket.close(1000, 'User initiated disconnect');
        }
    }
}

// Initialize WebSocket when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.scanWebSocket = new ScanWebSocket();
    window.scanWebSocket.connect();
    
    // Expose subscribe function globally
    window.subscribeToScan = (scanId, callback) => {
        return window.scanWebSocket.subscribe(`scan:${scanId}`, callback);
    };
    
    window.unsubscribeFromScan = (subscriptionId) => {
        window.scanWebSocket.unsubscribe(subscriptionId);
    };
});

// Reconnect when page becomes visible
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && (!window.scanWebSocket.socket || window.scanWebSocket.socket.readyState !== WebSocket.OPEN)) {
        window.scanWebSocket.connect();
    }
});
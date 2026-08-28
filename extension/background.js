// Background Service Worker — v2.1.0
const DEBUG = false;
function log(...args) { if (DEBUG) console.log('[APG]', ...args); }

self.addEventListener('error', (event) => {
    log('Service Worker Error:', event.error);
});

const PROD_URL = "https://anti-phishing-api.onrender.com/analyze";
const DEV_URL = "http://127.0.0.1:8000/analyze";
let BACKEND_URL = DEV_URL; // Default to local for development

const tabStatus = new Map(); // Store status per tabId

// Initialize settings
chrome.storage.sync.get({ devMode: false }, (items) => {
    if (items && items.devMode !== undefined) {
        BACKEND_URL = items.devMode ? DEV_URL : PROD_URL;
    }
});

// Listen for settings changes
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "settings_updated") {
        chrome.storage.sync.get({ devMode: false }, (items) => {
            if (items && items.devMode !== undefined) {
                BACKEND_URL = items.devMode ? DEV_URL : PROD_URL;
                log("Backend URL updated to:", BACKEND_URL);
            }
        });
    }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (tab.url.startsWith('http')) {
            chrome.storage.sync.get({ protectionEnabled: true, whitelist: [] }, (items) => {
                if (items && items.protectionEnabled !== undefined) {
                    if (!items.protectionEnabled) {
                        chrome.action.setBadgeText({ text: "OFF", tabId });
                        chrome.action.setBadgeBackgroundColor({ color: "#555", tabId });
                        return;
                    }

                    try {
                        const hostname = new URL(tab.url).hostname.replace('www.', '');
                        if (items.whitelist && items.whitelist.includes(hostname)) {
                            const result = { status: 'safe', confidence: 100 };
                            tabStatus.set(tabId, result);
                            updateBadge(tabId, 'safe');
                            return;
                        }
                    } catch (e) { }

                    analyzeUrl(tabId, tab.url);
                }
            });
        } else {
            // Mark internal pages (chrome://, about:, file://) as safe immediately
            const result = { status: 'safe', confidence: 100 };
            tabStatus.set(tabId, result);
            updateBadge(tabId, 'safe');
        }
    }
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_status") {
        let status = tabStatus.get(request.tabId);
        if (!status) {
            // If we don't have status (e.g. extension restarted), start analyzing now
            status = { status: "scanning", confidence: 0 };
            tabStatus.set(request.tabId, status);
            analyzeUrl(request.tabId, request.url);
        }
        sendResponse(status);
    }
});

async function analyzeUrl(tabId, url) {
    // Check if already scanning to prevent duplicate calls
    const currentStatus = tabStatus.get(tabId);
    if (currentStatus && currentStatus.status === 'scanning' && currentStatus.url === url) {
        log("Already scanning this URL, skipping duplicate request.");
        return;
    }

    // Set initial loading state
    tabStatus.set(tabId, { status: 'scanning', confidence: 0, url: url });
    chrome.action.setBadgeText({ text: "...", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });

    // Check if protection is enabled before proceeding
    const settings = await chrome.storage.sync.get({ protectionEnabled: true });
    if (!settings.protectionEnabled) {
        log("Protection disabled, skipping analysis for:", url);
        return;
    }

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        log("Skipping internal/non-http URL:", url);
        const safeResult = { status: "safe", confidence: 100 };
        tabStatus.set(tabId, safeResult);
        updateBadge(tabId, "safe");
        return;
    }

    try {
        log(`Analyzing: ${url}`);

        const response = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error('API Error');
        }

        const result = await response.json();
        log("Analysis Result:", result);

        // Store result
        tabStatus.set(tabId, result);

        // Update Badge
        updateBadge(tabId, result.status);

        // --- v2.1: Track scan stats ---
        incrementScanCount();
        addToScanHistory(url, result);

        // Notify Popup if open
        chrome.runtime.sendMessage({
            action: "update_status",
            data: result
        }, () => chrome.runtime.lastError);

        // Active Alert: Send message to Content Script
        if (result.status === 'phishing') {
            chrome.tabs.sendMessage(tabId, {
                action: "SHOW_ALERT",
                type: "phishing",
                reason: result.reason
            }, () => chrome.runtime.lastError);

            // Increment blocked count
            chrome.storage.local.get({ blockedCount: 0 }, (items) => {
                chrome.storage.local.set({ blockedCount: items.blockedCount + 1 });
            });

            // --- v2.1: Chrome notification ---
            showThreatNotification(url, result, 'phishing');

        } else if (result.status === 'suspicious') {
            chrome.tabs.sendMessage(tabId, {
                action: "SHOW_ALERT",
                type: "suspicious",
                reason: result.reason
            }, () => chrome.runtime.lastError);

            // --- v2.1: Chrome notification for suspicious ---
            showThreatNotification(url, result, 'suspicious');
        }


    } catch (error) {
        log("Backend connection failed:", error);
        // Fallback or offline mode could go here
        chrome.action.setBadgeText({ text: "ERR", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#000", tabId });

        // Notify Popup of error
        chrome.runtime.sendMessage({
            action: "update_status",
            data: { status: "error", error: "Backend Disconnected" }
        }, () => chrome.runtime.lastError);
    }
}

function updateBadge(tabId, status) {
    if (status === 'phishing') {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#da3633", tabId });
    } else if (status === 'suspicious') {
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#d29922", tabId });
    } else {
        chrome.action.setBadgeText({ text: "OK", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#238636", tabId });
    }
}

// --- v2.1: Real Scan Counter ---
function incrementScanCount() {
    chrome.storage.local.get({ totalScans: 0 }, (items) => {
        chrome.storage.local.set({ totalScans: items.totalScans + 1 });
    });
}

// --- v2.1: Scan History (last 50 entries) ---
function addToScanHistory(url, result) {
    chrome.storage.local.get({ scanHistory: [] }, (items) => {
        const history = items.scanHistory;
        let hostname = url;
        try { hostname = new URL(url).hostname; } catch (e) { }

        history.unshift({
            url: hostname,
            fullUrl: url,
            status: result.status,
            confidence: result.confidence,
            reason: result.reason || '',
            timestamp: Date.now()
        });

        // Keep only last 50
        if (history.length > 50) history.length = 50;

        chrome.storage.local.set({ scanHistory: history });
    });
}

// --- v2.1: Chrome Notification on Threat ---
function showThreatNotification(url, result, type) {
    let hostname = url;
    try { hostname = new URL(url).hostname; } catch (e) { }

    const title = type === 'phishing'
        ? '🚨 Phishing Site Blocked!'
        : '⚠️ Suspicious Site Detected';

    const message = type === 'phishing'
        ? `${hostname} has been flagged as dangerous.\n${result.reason || 'AI Detection'}`
        : `${hostname} looks suspicious.\n${result.reason || 'Exercise caution'}`;

    chrome.notifications.create(`threat-${Date.now()}`, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: title,
        message: message,
        priority: 2
    }, () => chrome.runtime.lastError);
}

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
const verifiedUrls = new Set(); // Store safely verified hostnames to prevent infinite loops
const allowedUnsafeUrls = new Set(); // Store URLs user explicitly allowed

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

// Intercept navigation before any data is sent
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept main frame navigations
    if (details.frameId !== 0) return;
    
    const url = details.url;
    
    // Skip internal pages
    if (!url.startsWith('http')) return;
    
    // Check if protection is enabled
    const settings = await chrome.storage.sync.get({ protectionEnabled: true, whitelist: [] });
    if (!settings.protectionEnabled) {
        chrome.action.setBadgeText({ text: "OFF", tabId: details.tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#555", tabId: details.tabId });
        return;
    }

    try {
        const parsedUrl = new URL(url);
        const cacheKey = parsedUrl.origin + parsedUrl.pathname;
        const hostname = parsedUrl.hostname;
        
        // Skip if user whitelisted
        if (settings.whitelist && settings.whitelist.includes(hostname.replace('www.', ''))) {
            return;
        }
        
        // Skip if already verified in this session
        if (verifiedUrls.has(cacheKey) || allowedUnsafeUrls.has(cacheKey)) {
            return;
        }

        // Intercept: Redirect to scanning page
        const scanningUrl = chrome.runtime.getURL(`pages/scanning.html?url=${encodeURIComponent(url)}`);
        chrome.tabs.update(details.tabId, { url: scanningUrl });
        
    } catch (e) {
        log("Error in navigation interceptor:", e);
    }
});

// Update badge when a page finishes loading (if it was verified)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (!tab.url.startsWith('http')) {
            if (tab.url.includes('pages/blocked.html')) {
                updateBadge(tabId, 'phishing');
            } else if (tab.url.includes('pages/scanning.html')) {
                chrome.action.setBadgeText({ text: '...', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#fcd34d', tabId: tabId });
            } else {
                updateBadge(tabId, 'safe');
            }
            return;
        }
        
        try {
            const parsedUrl = new URL(tab.url);
            const cacheKey = parsedUrl.origin + parsedUrl.pathname;
            if (verifiedUrls.has(cacheKey) || allowedUnsafeUrls.has(cacheKey)) {
                updateBadge(tabId, 'safe'); // Or previous status
            }
        } catch(e) {}
    }
});

// Listen for messages from popup and scanning pages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_status") {
        let status = tabStatus.get(request.tabId);
        if (!status) {
            status = { status: "scanning", confidence: 0 };
            tabStatus.set(request.tabId, status);
        }
        sendResponse(status);
        return true;
    }
    
    if (request.action === "scan_intercepted_url") {
        const tabId = sender.tab ? sender.tab.id : null;
        if (tabId) {
            analyzeUrl(tabId, request.url).then(result => {
                sendResponse(result);
            }).catch(err => {
                sendResponse({ status: "error" });
            });
            return true; // Indicates async response
        }
    }
    
    if (request.action === "allow_unsafe_url") {
        try {
            const parsedUrl = new URL(request.url);
            const cacheKey = parsedUrl.origin + parsedUrl.pathname;
            allowedUnsafeUrls.add(cacheKey);
            sendResponse({ success: true });
        } catch(e) {
            sendResponse({ success: false });
        }
        return true;
    }
});

async function analyzeUrl(tabId, url) {
    // Set initial loading state
    tabStatus.set(tabId, { status: 'scanning', confidence: 0, url: url });
    chrome.action.setBadgeText({ text: "...", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        log("Skipping internal/non-http URL:", url);
        const safeResult = { status: "safe", confidence: 100 };
        tabStatus.set(tabId, safeResult);
        updateBadge(tabId, "safe");
        return safeResult;
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
        updateBadge(tabId, result.status);

        // --- v2.1: Track scan stats ---
        incrementScanCount();
        addToScanHistory(url, result);

        // Notify Popup if open
        chrome.runtime.sendMessage({
            action: "update_status",
            data: result
        }, () => chrome.runtime.lastError);

        if (result.status === 'safe') {
            try {
                const parsedUrl = new URL(url);
                const cacheKey = parsedUrl.origin + parsedUrl.pathname;
                verifiedUrls.add(cacheKey); // Cache as safe to prevent rescan loops
                
                // Clear cache after 15 minutes to re-verify if needed
                setTimeout(() => {
                    verifiedUrls.delete(cacheKey);
                }, 15 * 60 * 1000);
            } catch(e) {}
        } else {
            // Increment blocked count
            chrome.storage.local.get({ blockedCount: 0 }, (items) => {
                chrome.storage.local.set({ blockedCount: items.blockedCount + 1 });
            });
            showThreatNotification(url, result, result.status);
        }

        return result;

    } catch (error) {
        log("Backend connection failed:", error);
        chrome.action.setBadgeText({ text: "ERR", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#000", tabId });

        chrome.runtime.sendMessage({
            action: "update_status",
            data: { status: "error", error: "Backend Disconnected" }
        }, () => chrome.runtime.lastError);
        
        return { status: "error" };
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

// Background Service Worker — v2.2.0
const DEBUG = false;
function log(...args) { if (DEBUG) console.log('[APG]', ...args); }

self.addEventListener('error', (event) => {
    log('Service Worker Error:', event.error);
});

const PROD_URL = "https://anti-phishing-api.onrender.com/analyze";
const DEV_URL = "http://127.0.0.1:8000/analyze";
let BACKEND_URL = PROD_URL; // Default to production

const tabStatus = new Map(); // Store status per tabId
const verifiedUrls = new Set(); // Store safely verified hostnames to prevent infinite loops
const allowedUnsafeUrls = new Set(); // Store URLs user explicitly allowed
const tabGenerations = new Map(); // Track current scan generation per tab to prevent races

// --- Local Network / Captive Portal Detection ---
// Security note: This bypass allows local/private network destinations to load
// WITHOUT remote phishing analysis. This is required for network bootstrap
// (e.g., Wi-Fi captive portals) because the remote backend is unreachable
// before network authentication completes. Local destinations are NOT classified
// as "safe" — they are classified as "local_network" (a separate category).
function isLocalNetworkUrl(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();

        // 1. Literal "localhost"
        if (hostname === 'localhost') return true;

        // 2. Hostnames ending in ".local" (mDNS / Bonjour)
        if (hostname.endsWith('.local')) return true;

        // 3. Strip brackets from IPv6 literals (e.g., "[::1]" → "::1")
        const bare = hostname.replace(/^\[|\]$/g, '');

        // 4. Try to parse as an IP address
        // IPv4 check
        const ipv4Match = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (ipv4Match) {
            const [, a, b, c, d] = ipv4Match.map(Number);
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;
            // 127.0.0.0/8 — loopback
            if (a === 127) return true;
            // 10.0.0.0/8 — private
            if (a === 10) return true;
            // 172.16.0.0/12 — private (172.16.x.x through 172.31.x.x)
            if (a === 172 && b >= 16 && b <= 31) return true;
            // 192.168.0.0/16 — private
            if (a === 192 && b === 168) return true;
            // 169.254.0.0/16 — link-local
            if (a === 169 && b === 254) return true;
            return false;
        }

        // IPv6 check — expand and test
        if (bare.includes(':')) {
            // ::1 — loopback
            if (bare === '::1') return true;
            // Normalize: expand :: shorthand for prefix checks
            const expanded = expandIPv6(bare);
            if (!expanded) return false;
            const firstWord = parseInt(expanded.substring(0, 4), 16);
            // fc00::/7 — unique local addresses (fc00-fdff)
            if (firstWord >= 0xfc00 && firstWord <= 0xfdff) return true;
            // fe80::/10 — link-local (fe80-febf)
            if (firstWord >= 0xfe80 && firstWord <= 0xfebf) return true;
            return false;
        }

        return false;
    } catch (e) {
        return false;
    }
}

// Helper: expand an IPv6 address to its full 32-hex-char form
function expandIPv6(addr) {
    try {
        // Handle :: expansion
        let parts = addr.split(':');
        const doubleColonIdx = addr.indexOf('::');
        if (doubleColonIdx !== -1) {
            const left = addr.substring(0, doubleColonIdx).split(':').filter(Boolean);
            const right = addr.substring(doubleColonIdx + 2).split(':').filter(Boolean);
            const missing = 8 - left.length - right.length;
            if (missing < 0) return null;
            parts = [...left, ...Array(missing).fill('0'), ...right];
        }
        if (parts.length !== 8) return null;
        return parts.map(p => p.padStart(4, '0')).join('');
    } catch (e) {
        return null;
    }
}

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

    // Clear stale status for new navigation (unless it's our own internal page loading)
    if (!url.includes('pages/scanning.html') && !url.includes('pages/blocked.html')) {
        tabStatus.delete(details.tabId);
        tabGenerations.set(details.tabId, (tabGenerations.get(details.tabId) || 0) + 1);
        chrome.action.setBadgeText({ text: "", tabId: details.tabId });
    }

    // Skip internal pages
    if (!url.startsWith('http')) {
        log("Skipping internal/non-http URL:", url);
        if (!url.includes('pages/scanning.html') && !url.includes('pages/blocked.html')) {
            const safeResult = { status: "not_scanned", confidence: 100, url: url };
            tabStatus.set(details.tabId, safeResult);
            chrome.action.setBadgeText({ text: "---", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#9ca3af", tabId: details.tabId });
        }
        return;
    }

    // Check if protection is enabled
    const settings = await chrome.storage.sync.get({ protectionEnabled: true, whitelist: [] });
    if (!settings.protectionEnabled) {
        tabStatus.set(details.tabId, { status: "disabled", confidence: 0, url: url, reason: "Protection off" });
        chrome.action.setBadgeText({ text: "OFF", tabId: details.tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#555", tabId: details.tabId });
        return;
    }

    try {
        const parsedUrl = new URL(url);
        const cacheKey = parsedUrl.origin + parsedUrl.pathname + parsedUrl.search;
        const hostname = parsedUrl.hostname;

        // --- CAPTIVE PORTAL / LOCAL NETWORK BYPASS ---
        // Local/private network destinations are allowed immediately without
        // remote backend analysis. This prevents the circular dependency where
        // the user cannot authenticate to Wi-Fi because the extension blocks
        // the captive portal login page (which requires internet that doesn't
        // exist yet). These are NOT classified as "safe" — they use a distinct
        // "local_network" status and are never added to verifiedUrls.
        if (isLocalNetworkUrl(url)) {
            log('Local network destination detected, bypassing scan:', hostname);
            tabStatus.set(details.tabId, {
                status: 'local_network',
                confidence: 0,
                url: url,
                reason: 'Local network / captive portal — bypassed remote scan'
            });
            chrome.action.setBadgeText({ text: "LAN", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#6366f1", tabId: details.tabId });
            return; // Allow navigation without interception
        }

        // Skip if user whitelisted
        if (settings.whitelist && settings.whitelist.includes(hostname.replace('www.', ''))) {
            tabStatus.set(details.tabId, { status: "whitelisted", confidence: 100, url: url, reason: "Trusted/allowlisted" });
            chrome.action.setBadgeText({ text: "WHT", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#9ca3af", tabId: details.tabId });
            return;
        }

        // Skip if already verified in this session
        if (verifiedUrls.has(cacheKey)) {
            tabStatus.set(details.tabId, { status: "previously_checked", confidence: 99, url: url, reason: "Previously checked" });
            chrome.action.setBadgeText({ text: "OK", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#238636", tabId: details.tabId });
            return;
        }

        if (allowedUnsafeUrls.has(cacheKey)) {
            tabStatus.set(details.tabId, { status: "suspicious", confidence: 0, url: url, reason: "User bypassed warning" });
            chrome.action.setBadgeText({ text: "?", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#d29922", tabId: details.tabId });
            return;
        }

        // Intercept: Redirect to scanning page
        const scanningUrl = chrome.runtime.getURL(`pages/scanning.html?url=${encodeURIComponent(url)}`);
        chrome.tabs.update(details.tabId, { url: scanningUrl });

    } catch (e) {
        log("Error in navigation interceptor:", e);
    }
});

// Add error listener for DNS/Connection failures
chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (details.frameId !== 0) return;

    // Don't override local_network
    const current = tabStatus.get(details.tabId);
    if (current && current.status === 'local_network') return;

    // Invalidate any in-flight scan for this tab
    tabGenerations.set(details.tabId, (tabGenerations.get(details.tabId) || 0) + 1);

    tabStatus.set(details.tabId, {
        status: 'unable_to_verify',
        confidence: 0,
        url: details.url,
        reason: 'Navigation failed (' + details.error + ')'
    });
    chrome.action.setBadgeText({ text: "ERR", tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId: details.tabId });
});

// Update badge when a page finishes loading (if it was verified)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (!tab.url.startsWith('http')) {
            if (tab.url.includes('pages/blocked.html')) {
                // The interstitial also represents suspicious and
                // unable-to-verify outcomes. Preserve the actual verdict.
                const currentStatus = tabStatus.get(tabId);
                updateBadge(tabId, currentStatus ? currentStatus.status : 'not_scanned');
            } else if (tab.url.includes('pages/scanning.html')) {
                chrome.action.setBadgeText({ text: '...', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#fcd34d', tabId: tabId });
            } else {
                chrome.action.setBadgeText({ text: '---', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#9ca3af', tabId: tabId });
            }
            return;
        }

        try {
            const parsedUrl = new URL(tab.url);
            const cacheKey = parsedUrl.origin + parsedUrl.pathname + parsedUrl.search;
            if (verifiedUrls.has(cacheKey) || allowedUnsafeUrls.has(cacheKey)) {
                const currentStatus = tabStatus.get(tabId);
                if (currentStatus && currentStatus.status === 'unable_to_verify') {
                    // Do not mark safe if it failed to load
                    chrome.action.setBadgeText({ text: "ERR", tabId });
                    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });
                } else {
                    updateBadge(tabId, 'safe');
                }
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
                sendResponse({ status: "unable_to_verify", reason: "Backend Disconnected" });
            });
            return true; // Indicates async response
        }
    }

    if (request.action === "allow_unsafe_url") {
        try {
            const parsedUrl = new URL(request.url);
            const cacheKey = parsedUrl.origin + parsedUrl.pathname + parsedUrl.search;
            allowedUnsafeUrls.add(cacheKey);
            sendResponse({ success: true });
        } catch(e) {
            sendResponse({ success: false });
        }
        return true;
    }

    if (request.action === "close_tab") {
        if (sender.tab && sender.tab.id) {
            chrome.tabs.remove(sender.tab.id).catch(() => {});
        }
        return true;
    }
});

async function analyzeUrl(tabId, url) {
    // Set initial loading state
    tabStatus.set(tabId, { status: 'scanning', confidence: 0, url: url });
    chrome.action.setBadgeText({ text: "...", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });

    const currentGen = (tabGenerations.get(tabId) || 0) + 1;
    tabGenerations.set(tabId, currentGen);

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        log("Skipping internal/non-http URL:", url);
        const safeResult = { status: "not_scanned", confidence: 100 };
        tabStatus.set(tabId, safeResult);
        chrome.action.setBadgeText({ text: "---", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#9ca3af", tabId });
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

        // Check generation to prevent stale race conditions
        if (tabGenerations.get(tabId) !== currentGen) {
            log("Stale scan result discarded for tab", tabId);
            return { status: "stale" };
        }

        // Downgrade model-only predictions to suspicious
        if (result.status === 'phishing' && result.reason === 'AI Model Detection Pattern') {
            result.status = 'suspicious';
            result.reason = 'Unverified AI Model Prediction';
        }

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
                const cacheKey = parsedUrl.origin + parsedUrl.pathname + parsedUrl.search;
                verifiedUrls.add(cacheKey); // Cache as safe to prevent rescan loops

                // Clear cache after 15 minutes to re-verify if needed
                setTimeout(() => {
                    verifiedUrls.delete(cacheKey);
                }, 15 * 60 * 1000);
            } catch(e) {}
        } else if (result.status === 'phishing' || result.status === 'suspicious') {
            // Only actual threat verdicts count as blocked or trigger threat
            // alerts. An incomplete scan must never inflate either metric.
            chrome.storage.local.get({ blockedCount: 0 }, (items) => {
                chrome.storage.local.set({ blockedCount: items.blockedCount + 1 });
            });
            showThreatNotification(url, result, result.status);
        }

        return result;

    } catch (error) {
        log("Backend connection failed:", error);

        if (tabGenerations.get(tabId) !== currentGen) {
            return { status: "stale" };
        }

        chrome.action.setBadgeText({ text: "ERR", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });

        const errorResult = { status: "unable_to_verify", confidence: 0, url: url, reason: "Backend connection failed" };
        tabStatus.set(tabId, errorResult);

        chrome.runtime.sendMessage({
            action: "update_status",
            data: errorResult
        }, () => chrome.runtime.lastError);

        return errorResult;
    }
}

function updateBadge(tabId, status) {
    if (status === 'phishing') {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#da3633", tabId });
    } else if (status === 'suspicious') {
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#d29922", tabId });
    } else if (status === 'safe' || status === 'previously_checked') {
        chrome.action.setBadgeText({ text: "OK", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#238636", tabId });
    } else if (status === 'unable_to_verify' || status === 'error') {
        chrome.action.setBadgeText({ text: "ERR", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });
    } else if (status === 'local_network') {
        chrome.action.setBadgeText({ text: "LAN", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#6366f1", tabId });
    } else if (status === 'disabled') {
        chrome.action.setBadgeText({ text: "OFF", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#555", tabId });
    } else if (status === 'whitelisted') {
        chrome.action.setBadgeText({ text: "WHT", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#9ca3af", tabId });
    } else {
        chrome.action.setBadgeText({ text: "---", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#9ca3af", tabId });
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

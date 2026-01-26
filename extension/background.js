// Background Service Worker
const PROD_URL = "https://anti-phishing-api.onrender.com/analyze";
const DEV_URL = "http://localhost:8000/analyze";
let BACKEND_URL = PROD_URL;

const tabStatus = new Map(); // Store status per tabId

// Initialize settings
chrome.storage.sync.get({ devMode: false }, (items) => {
    BACKEND_URL = items.devMode ? DEV_URL : PROD_URL;
});

// Listen for settings changes
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "settings_updated") {
        chrome.storage.sync.get({ devMode: false }, (items) => {
            BACKEND_URL = items.devMode ? DEV_URL : PROD_URL;
            console.log("Backend URL updated to:", BACKEND_URL);
        });
    }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        if (tab.url.startsWith('http')) {
            chrome.storage.sync.get({ protectionEnabled: true, whitelist: [] }, (items) => {
                if (!items.protectionEnabled) {
                    chrome.action.setBadgeText({ text: "OFF", tabId });
                    chrome.action.setBadgeBackgroundColor({ color: "#555", tabId });
                    return;
                }

                try {
                    const hostname = new URL(tab.url).hostname.replace('www.', '');
                    if (items.whitelist.includes(hostname)) {
                        const result = { status: 'safe', confidence: 100 };
                        tabStatus.set(tabId, result);
                        updateBadge(tabId, 'safe');
                        return;
                    }
                } catch (e) { }

                analyzeUrl(tabId, tab.url);
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
            analyzeUrl(request.tabId, request.url);
        }
        sendResponse(status);
    }
    return true; // Keep channel open
});

async function analyzeUrl(tabId, url) {
    // Set initial loading state
    chrome.action.setBadgeText({ text: "...", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888", tabId });

    try {
        console.log(`Analyzing: ${url}`);

        const response = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error('API Error');
        }

        const result = await response.json();
        console.log("Analysis Result:", result);

        // Store result
        tabStatus.set(tabId, result);

        // Update Badge
        updateBadge(tabId, result.status);

        // Notify Popup if open
        chrome.runtime.sendMessage({
            action: "update_status",
            data: result
        }).catch(() => {
            // Popup likely closed, ignore
        });

        // Active Alert: Send message to Content Script
        if (result.status === 'phishing') {
            chrome.tabs.sendMessage(tabId, { action: "SHOW_ALERT", type: "phishing" })
                .catch(() => console.log("Tab probably not ready for alert"));

            // Increment blocked count
            chrome.storage.local.get({ blockedCount: 0 }, (items) => {
                chrome.storage.local.set({ blockedCount: items.blockedCount + 1 });
            });
        } else if (result.status === 'suspicious') {
            chrome.tabs.sendMessage(tabId, { action: "SHOW_ALERT", type: "suspicious" })
                .catch(() => console.log("Tab probably not ready for alert"));
        }


    } catch (error) {
        console.error("Backend connection failed:", error);
        // Fallback or offline mode could go here
        chrome.action.setBadgeText({ text: "ERR", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#000", tabId });

        // Notify Popup of error
        chrome.runtime.sendMessage({
            action: "update_status",
            data: { status: "error", error: "Backend Disconnected" }
        }).catch(() => { });
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

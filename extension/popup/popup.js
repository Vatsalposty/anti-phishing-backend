document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (tab && tab.url) {
            let hostname;
            try {
                const urlObj = new URL(tab.url);
                hostname = urlObj.hostname;
                // Handle local files or chrome pages where hostname might be empty
                if (!hostname) {
                    if (tab.url.startsWith('file:')) hostname = 'Local File';
                    else if (tab.url.startsWith('chrome:')) hostname = 'Chrome Page';
                    else hostname = tab.url;
                }
            } catch (e) {
                hostname = "Invalid URL";
            }

            document.getElementById('current-url').textContent = hostname;

            // Request status from background script
            chrome.runtime.sendMessage({ action: "get_status", tabId: tab.id, url: tab.url }, (response) => {
                if (response) {
                    updateUI(response);
                } else {
                    console.log("No response yet, scanning...");
                }
            });

            // Fetch Local Stats (Total Blocked)
            chrome.storage.local.get({ blockedCount: 0 }, (items) => {
                const scanCountEl = document.getElementById('scan-count');
                if (scanCountEl) scanCountEl.textContent = items.blockedCount;
            });

            // Fetch Global Stats from Backend
            fetch('https://anti-phishing-api.onrender.com/stats')
                .then(res => res.json())
                .then(stats => {
                    console.log("Global Stats:", stats);
                    // We could use this for something cool in the UI later
                })
                .catch(err => console.log("Stats fetch failed (offline or localhost dev mode)"));
        } else {
            document.getElementById('current-url').textContent = "Restricted Page";
        }
    } catch (err) {
        console.error("Error getting tab:", err);
        document.getElementById('current-url').textContent = "Error";
    }

    // Settings Button Listener
    const settingsBtn = document.querySelector('.settings-icon');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            if (chrome.runtime.openOptionsPage) {
                chrome.runtime.openOptionsPage();
            } else {
                window.open(chrome.runtime.getURL('options/options.html'));
            }
        });
    }

    document.getElementById('report-btn').addEventListener('click', async () => {
        const btn = document.getElementById('report-btn');

        try {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!activeTab || !activeTab.url) return;

            btn.innerHTML = '<span>Reporting...</span>';
            btn.disabled = true;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout

            const response = await fetch('https://anti-phishing-api.onrender.com/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: activeTab.url, reason: "user_manual_report" }),
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                btn.innerHTML = '<span>Reported! ✅</span>';
            } else {
                throw new Error('Server error');
            }
        } catch (e) {
            console.error("Report failed", e);
            btn.innerHTML = '<span>Offline ❌</span>';
        } finally {
            setTimeout(() => {
                btn.innerHTML = '<span>Report Suspicious</span>';
                btn.disabled = false;
            }, 3000);
        }
    });
});

function updateUI(data) {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    const shieldCheck = document.querySelector('.shield-check');
    const shieldAlert = document.querySelector('.shield-alert');
    const trustScore = document.getElementById('trust-score');
    const container = document.querySelector('.container');
    const root = document.documentElement;

    // Reset classes
    statusCard.classList.remove('safe', 'phishing', 'error');
    container.classList.remove('phishing-bg');

    if (data.status === 'phishing') {
        statusCard.classList.add('phishing');
        container.classList.add('phishing-bg');
        statusText.textContent = 'Phishing Detected';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block';
        trustScore.textContent = `${data.confidence || 10}%`;
        root.style.setProperty('--safe-gradient', 'var(--danger-gradient)');
    } else if (data.status === 'suspicious') {
        statusCard.classList.add('phishing'); // Re-use styling but with different text
        statusText.textContent = 'Suspicious Site';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block';
        trustScore.textContent = `${data.confidence || 45}%`;
        root.style.setProperty('--safe-gradient', 'var(--warning-gradient)');
    } else if (data.status === 'scanning') {
        statusText.textContent = 'Analyzing...';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'none';
        trustScore.textContent = '---';
    } else if (data.status === 'error') {
        statusCard.classList.add('error');
        statusText.textContent = 'Offline';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block';
        trustScore.textContent = 'ERR';
    } else {
        // Safe
        statusCard.classList.add('safe');
        statusText.textContent = 'Safe Website';
        shieldCheck.style.display = 'block';
        shieldAlert.style.display = 'none';
        trustScore.textContent = `${data.confidence || 98}%`;
        root.style.setProperty('--safe-gradient', 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)');
    }
}

// Listen for updates from background (real-time)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "update_status") {
        updateUI(message.data);
    }
});

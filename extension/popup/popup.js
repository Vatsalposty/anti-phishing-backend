document.addEventListener('DOMContentLoaded', async () => {
    // Get current tab
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (tab && tab.url) {
            let hostname;
            try {
                const urlObj = new URL(tab.url);
                hostname = urlObj.hostname;
                if (!hostname) {
                    if (tab.url.startsWith('file:')) hostname = 'Local File';
                    else if (tab.url.startsWith('chrome:')) hostname = 'Chrome Page';
                    else if (tab.url.startsWith('chrome-extension:')) hostname = 'Extension Page';
                    else hostname = tab.url;
                }
            } catch (e) {
                hostname = "Invalid URL";
            }

            document.getElementById('current-url').textContent = hostname;

            // Check Protection Status First
            chrome.storage.sync.get({ protectionEnabled: true }, (items) => {
                if (!items.protectionEnabled) {
                    updateUI({ status: 'disabled' });
                } else {
                    if (hostname === "Local File" || hostname === "Chrome Page" || hostname === "Extension Page") {
                        updateUI({ status: 'safe', confidence: 100 });
                    } else {
                        updateUI({ status: 'scanning' });

                        chrome.runtime.sendMessage({ action: "get_status", url: tab.url, tabId: tab.id }, (response) => {
                            if (chrome.runtime.lastError) {
                                updateUI({ status: 'error' });
                            } else {
                                chrome.storage.sync.get({ protectionEnabled: true }, (current) => {
                                    if (current.protectionEnabled) {
                                        updateUI(response);
                                    } else {
                                        updateUI({ status: 'disabled' });
                                    }
                                });
                            }
                        });
                    }
                }
            });

            // --- v2.1: Real Stats from Local Storage ---
            chrome.storage.local.get({ totalScans: 0, blockedCount: 0 }, (items) => {
                const scanCountEl = document.getElementById('scan-count');
                if (scanCountEl) scanCountEl.textContent = items.totalScans;
                const blockedCountEl = document.getElementById('blocked-count');
                if (blockedCountEl) blockedCountEl.textContent = items.blockedCount;
            });

        } else {
            document.getElementById('current-url').textContent = "Restricted Page";
        }
    } catch (err) {
        document.getElementById('current-url').textContent = "Error";
    }

    // Settings Button
    const settingsBtn = document.querySelector('.settings-icon');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const optionsUrl = chrome.runtime.getURL('pages/settings.html');
            window.open(optionsUrl, '_blank');
        });
    }

    // --- v2.1: History Button ---
    const historyBtn = document.getElementById('history-btn');
    if (historyBtn) {
        historyBtn.addEventListener('click', (e) => {
            e.preventDefault();
            const historyUrl = chrome.runtime.getURL('pages/history.html');
            window.open(historyUrl, '_blank');
        });
    }

    // Listen for storage changes to update UI instantly
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'sync' && changes.protectionEnabled !== undefined) {
            if (!changes.protectionEnabled.newValue) {
                updateUI({ status: 'disabled' });
            } else {
                updateUI({ status: 'scanning' });
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    const activeTab = tabs[0];
                    if (activeTab) {
                        chrome.runtime.sendMessage({ action: "get_status", url: activeTab.url, tabId: activeTab.id }, (response) => {
                            if (response) updateUI(response);
                        });
                    }
                });
            }
        }
    });

    // Report Button
    document.getElementById('report-btn').addEventListener('click', async () => {
        const btn = document.getElementById('report-btn');

        try {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!activeTab || !activeTab.url) return;

            if (!activeTab.url.startsWith('http://') && !activeTab.url.startsWith('https://')) {
                btn.textContent = 'Cannot Report This Page';
                setTimeout(() => {
                    btn.textContent = 'Report Suspicious';
                    btn.disabled = false;
                }, 3000);
                return;
            }

            btn.textContent = 'Reporting...';
            btn.disabled = true;

            chrome.storage.sync.get({ devMode: false }, async (items) => {
                const backendUrl = items.devMode ? "http://127.0.0.1:8000" : "https://anti-phishing-api.onrender.com";
                
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);

                try {
                    const response = await fetch(`${backendUrl}/report`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: activeTab.url, reason: "user_manual_report" }),
                        signal: controller.signal
                    });
                    clearTimeout(timeoutId);

                    if (response.ok) {
                        btn.textContent = 'Reported! ✅';
                    } else {
                        throw new Error('Server error');
                    }
                } catch (e) {
                    btn.textContent = 'Offline ❌';
                } finally {
                    setTimeout(() => {
                        btn.textContent = 'Report Suspicious';
                        btn.disabled = false;
                    }, 3000);
                }
            });
        } catch (err) {
            btn.textContent = 'Error';
            setTimeout(() => {
                btn.textContent = 'Report Suspicious';
                btn.disabled = false;
            }, 3000);
        }
    });

    function updateUI(data) {
        const statusCard = document.getElementById('status-card');
        const statusText = document.getElementById('status-text');
        const shieldCheck = document.querySelector('.shield-check');
        const shieldAlert = document.querySelector('.shield-alert');
        const trustScore = document.getElementById('trust-score');
        const container = document.querySelector('.container');
        const root = document.documentElement;

        statusCard.classList.remove('safe', 'phishing', 'error');
        container.classList.remove('phishing-bg');

        const footerText = document.querySelector('footer span');
        const pulseDot = document.querySelector('.pulse-dot');

        if (data.status === 'phishing') {
            statusCard.classList.add('phishing');
            container.classList.add('phishing-bg');
            statusText.textContent = 'Phishing Detected';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'block';
            let trustVal = 100 - (data.confidence || 90);
            trustScore.textContent = `${trustVal}%`;
            root.style.setProperty('--safe-gradient', 'var(--danger-gradient)');

            footerText.textContent = "AI PROTECTION ACTIVE";
            footerText.style.color = "var(--text-muted)";
            pulseDot.style.background = "#f5576c";
            pulseDot.style.animation = "";
        } else if (data.status === 'suspicious') {
            statusCard.classList.add('phishing');
            statusText.textContent = 'Suspicious Site';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'block';
            let trustVal = 100 - (data.confidence || 55);
            trustScore.textContent = `${trustVal}%`;
            root.style.setProperty('--safe-gradient', 'var(--warning-gradient)');

            footerText.textContent = "AI PROTECTION ACTIVE";
            footerText.style.color = "var(--text-muted)";
            pulseDot.style.background = "#f6d365";
            pulseDot.style.animation = "";
        } else if (data.status === 'scanning') {
            statusText.textContent = 'Analyzing...';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'none';
            trustScore.textContent = '---';

            footerText.textContent = "AI PROTECTION ACTIVE";
            footerText.style.color = "var(--text-muted)";
            pulseDot.style.background = "var(--safe-gradient)";
            pulseDot.style.animation = "";
        } else if (data.status === 'error') {
            statusCard.classList.add('error');
            statusText.textContent = 'Offline';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'block';
            trustScore.textContent = 'ERR';

            footerText.textContent = "AI PROTECTION ACTIVE";
            footerText.style.color = "var(--text-muted)";
            pulseDot.style.background = "#555";
        } else if (data.status === 'disabled') {
            statusCard.classList.add('error');
            statusCard.style.border = '1px solid var(--text-muted)';
            statusText.textContent = 'Protection Disabled';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'block';
            trustScore.textContent = 'OFF';
            root.style.setProperty('--safe-gradient', 'linear-gradient(135deg, #e0e0e0 0%, #bdbdbd 100%)');

            footerText.textContent = "PROTECTION DISABLED";
            footerText.style.color = "#f5576c";
            pulseDot.style.background = "#f5576c";
            pulseDot.style.animation = 'none';
        } else {
            statusCard.classList.add('safe');
            statusText.textContent = 'Safe Website';
            shieldCheck.style.display = 'block';
            shieldAlert.style.display = 'none';
            trustScore.textContent = `${data.confidence || 98}%`;
            root.style.setProperty('--safe-gradient', 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)');

            footerText.textContent = "AI PROTECTION ACTIVE";
            footerText.style.color = "var(--text-muted)";
            pulseDot.style.background = "var(--safe-gradient)";
            pulseDot.style.animation = "";
        }
    }

    // Listen for updates from background (real-time)
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === "update_status") {
            chrome.storage.sync.get({ protectionEnabled: true }, (items) => {
                if (!items.protectionEnabled) {
                    updateUI({ status: 'disabled', confidence: 0 });
                } else {
                    updateUI(message.data);
                }
            });
        }
    });

});

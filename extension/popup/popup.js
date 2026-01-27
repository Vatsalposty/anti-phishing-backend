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
                    // We still might want url stats if dev mode, but for main UI:
                } else {
                    // Determine status logic...
                    if (hostname === "Local File" || hostname === "Chrome Page" || hostname === "Extension Page") {
                        updateUI({ status: 'safe', confidence: 100 });
                    } else {
                        // Initial scan state
                        updateUI({ status: 'scanning' });

                        // Request status from background
                        chrome.runtime.sendMessage({ action: "get_status", url: tab.url, tabId: tab.id }, (response) => {
                            if (chrome.runtime.lastError) {
                                console.error("Connection error:", chrome.runtime.lastError);
                                updateUI({ status: 'error' });
                            } else {
                                // Double check protection didn't turn off in the millisecond interim
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
    // Settings Button Listener
    const settingsBtn = document.querySelector('.settings-icon');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', (e) => {
            e.preventDefault();
            // Force open in new tab - most reliable method
            const optionsUrl = chrome.runtime.getURL('settings.html');
            window.open(optionsUrl, '_blank');
        });
    } else {
        console.error("Settings button not found in DOM");
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
        // Initial check for protection status
        updateProtectionFooter();

        // Listen for storage changes to update footer instantly
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === 'sync' && changes.protectionEnabled) {
                updateProtectionFooter();
            }
        });

        // ... existing report button listener ...
        document.getElementById('report-btn').addEventListener('click', async () => {
            // ...
        });
    }); // End of DOMContentLoaded

    function updateProtectionFooter() {
        chrome.storage.sync.get({ protectionEnabled: true }, (items) => {
            const footerText = document.querySelector('footer span');
            const pulseDot = document.querySelector('.pulse-dot');
            const footer = document.querySelector('footer');

            if (!items.protectionEnabled) {
                footerText.textContent = "PROTECTION DISABLED";
                footerText.style.color = "#f5576c"; // Red/Pinkish
                pulseDot.style.background = "#f5576c";
                pulseDot.classList.remove('active-pulse'); // detailed keyframe animation class if needed
                // Optionally stop animation:
                pulseDot.style.animation = 'none';
            } else {
                footerText.textContent = "AI PROTECTION ACTIVE";
                footerText.style.color = "var(--text-muted)";
                pulseDot.style.background = "var(--safe-gradient)";
                pulseDot.style.animation = ""; // Restore animation
            }
        });
    }

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
        } else if (data.status === 'disabled') {
            // New Disabled State
            statusCard.classList.add('error'); // Use error styling or a new 'disabled' style if preferred
            statusCard.style.border = '1px solid var(--text-muted)'; // Optional custom styling
            statusText.textContent = 'Protection Disabled';
            shieldCheck.style.display = 'none';
            shieldAlert.style.display = 'block';
            // In a real disabled state, maybe show a different icon or grayscale the alert
            trustScore.textContent = 'OFF';
            root.style.setProperty('--safe-gradient', 'linear-gradient(135deg, #e0e0e0 0%, #bdbdbd 100%)'); // Grey gradient
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

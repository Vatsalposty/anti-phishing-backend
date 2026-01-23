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

    document.getElementById('report-btn').addEventListener('click', () => {
        // Mock report
        alert('Thank you for reporting this URL. We will analyze it further.');
    });
});

function updateUI(data) {
    const statusCard = document.getElementById('status-card');
    const statusText = document.getElementById('status-text');
    const shieldCheck = document.querySelector('.shield-check');
    const shieldAlert = document.querySelector('.shield-alert');
    const trustScore = document.getElementById('trust-score');
    const footerPulse = document.querySelector('.pulse');
    const root = document.documentElement;

    if (data.status === 'phishing') {
        statusCard.classList.remove('safe');
        statusCard.classList.add('phishing');
        statusText.textContent = 'Phishing Detected';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block';
        trustScore.textContent = `${data.confidence || 10}%`;
        root.style.setProperty('--primary-color', '#da3633');
        footerPulse.style.backgroundColor = '#da3633';
    } else if (data.status === 'suspicious') {
        statusCard.classList.remove('safe');
        statusCard.classList.add('phishing'); // Use warning styling if we had it, reusing phishing for now
        statusText.textContent = 'Suspicious Site';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block'; // Or warning icon
        trustScore.textContent = `${data.confidence || 45}%`;
        root.style.setProperty('--primary-color', '#d29922');
        footerPulse.style.backgroundColor = '#d29922';
    } else if (data.status === 'scanning') {
        statusCard.classList.remove('safe', 'phishing');
        statusText.textContent = 'Analyzing...';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'none';
        trustScore.textContent = '---';
        root.style.setProperty('--primary-color', '#8b949e');
        footerPulse.style.backgroundColor = '#8b949e';
    } else if (data.status === 'error') {
        statusCard.classList.remove('safe', 'phishing');
        statusCard.classList.add('error'); // Add error class
        statusText.textContent = 'Backend Offline';
        shieldCheck.style.display = 'none';
        shieldAlert.style.display = 'block'; // Or warning
        trustScore.textContent = 'ERR';
        root.style.setProperty('--primary-color', '#fff'); // White for error icon
        footerPulse.style.backgroundColor = '#333';
    } else {
        // Safe
        statusCard.classList.add('safe');
        statusCard.classList.remove('phishing');
        statusText.textContent = 'Safe Website';
        shieldCheck.style.display = 'block';
        shieldAlert.style.display = 'none';
        trustScore.textContent = `${data.confidence || 98}%`;
        root.style.setProperty('--primary-color', '#238636');
        footerPulse.style.backgroundColor = '#238636';
    }
}

// Listen for updates from background (real-time)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "update_status") {
        updateUI(message.data);
    }
});

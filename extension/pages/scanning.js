document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');

    if (!targetUrl) {
        document.getElementById('status-desc').innerText = "Error: No target URL provided.";
        return;
    }

    // Display the URL being scanned
    const displayUrl = document.getElementById('target-url-display');
    try {
        const hostname = new URL(targetUrl).hostname;
        displayUrl.innerText = hostname;
    } catch (e) {
        displayUrl.innerText = targetUrl;
    }

    // Request the background script to perform the scan
    chrome.runtime.sendMessage({
        action: "scan_intercepted_url",
        url: targetUrl
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError);
            handleError();
            return;
        }

        if (response && response.status) {
            if (response.status === 'error') {
                handleError();
            } else {
                handleScanResult(response.status, response.reason, targetUrl);
            }
        } else {
            handleError();
        }
    });
});

function handleScanResult(status, reason, targetUrl) {
    if (status === 'safe') {
        // Safe: Add to verified cache via background script and redirect
        document.getElementById('status-title').innerText = "Site is Safe!";
        document.getElementById('status-title').style.background = "linear-gradient(135deg, #10b981, #a7f3d0)";
        document.getElementById('status-title').style.webkitBackgroundClip = "text";
        document.getElementById('status-desc').innerText = "Redirecting you to your destination...";
        
        setTimeout(() => {
            window.location.replace(targetUrl);
        }, 500); // Brief delay for smooth transition
    } else {
        // Phishing or Suspicious: Redirect to blocked page
        const blockedUrl = chrome.runtime.getURL(`pages/blocked.html?url=${encodeURIComponent(targetUrl)}&status=${status}&reason=${encodeURIComponent(reason || '')}`);
        window.location.replace(blockedUrl);
    }
}

function handleError() {
    document.getElementById('status-title').innerText = "Scan Failed";
    document.getElementById('status-desc').innerText = "Unable to reach AI analysis server. Redirecting safely...";
    // In case of error, default to allowing the navigation but maybe show a warning?
    // We'll just allow it to prevent completely breaking the internet if the backend is down.
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    if (targetUrl) {
        setTimeout(() => {
            window.location.replace(targetUrl);
        }, 1500);
    }
}

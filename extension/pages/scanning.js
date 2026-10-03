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
            handleError(targetUrl);
            return;
        }

        if (response && response.status) {
            if (response.status === 'error') {
                handleError(targetUrl);
            } else {
                handleScanResult(response.status, response.reason, targetUrl);
            }
        } else {
            handleError(targetUrl);
        }
    });
});

function handleScanResult(status, reason, targetUrl) {
    // A stale result belongs to an older navigation. Do not redirect or show
    // a verdict for it; the browser's current navigation owns the tab now.
    if (status === 'stale') return;

    if (status === 'unable_to_verify') {
        // A failed fetch is not a phishing verdict. Keep the user in control
        // without presenting an unavailable scan as a confirmed threat.
        handleError(targetUrl, reason || 'The destination could not be reached by the scanner.');
        return;
    }

    // Fail closed on statuses this UI does not understand. Only explicit
    // phishing/suspicious results may reach the threat interstitial.
    if (!['safe', 'phishing', 'suspicious'].includes(status)) {
        handleError(targetUrl, reason || 'The scanner returned an unrecognized result.');
        return;
    }

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
        // Explicit phishing or suspicious result: show the warning page.
        const blockedUrl = chrome.runtime.getURL(`pages/blocked.html?url=${encodeURIComponent(targetUrl)}&status=${status}&reason=${encodeURIComponent(reason || '')}`);
        window.location.replace(blockedUrl);
    }
}

function handleError(targetUrl, scanReason = '') {
    // SECURITY: Do NOT silently redirect to the target URL when the backend
    // is unavailable. That would be a fail-open that defeats phishing protection.
    // Instead, show a clear message and let the user decide.
    const titleEl = document.getElementById('status-title');
    const descEl = document.getElementById('status-desc');
    const progressBar = document.querySelector('.progress-bar');

    titleEl.innerText = scanReason ? "Unable to Verify This Site" : "Protection Unavailable";
    titleEl.style.background = "linear-gradient(135deg, #f59e0b, #ef4444)";
    titleEl.style.webkitBackgroundClip = "text";
    titleEl.style.webkitTextFillColor = "transparent";

    descEl.innerHTML = scanReason
        ? "The scanner could not retrieve the page. Some sites reject automated scan requests; " +
          "network or TLS problems can also interrupt a scan. This is <strong>not a phishing verdict</strong> " +
          "and does not confirm that the site is safe."
        : "Unable to reach the AI analysis server. This usually means your Internet " +
          "connection is not active yet.<br><br>" +
          "<strong>If you need to connect to Wi-Fi:</strong> Open your Wi-Fi captive portal / " +
          "login page directly (local network pages are allowed automatically).<br><br>" +
          "The URL below has NOT been verified as safe.";

    // Stop the progress bar animation
    if (progressBar) {
        progressBar.style.display = 'none';
    }

    // Show action buttons for the user
    const container = document.querySelector('.scan-container');
    if (container && targetUrl) {
        const actionsDiv = document.createElement('div');
        actionsDiv.style.cssText = 'margin-top: 24px; display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;';

        // "Go Back" button — safe default
        const goBackBtn = document.createElement('button');
        goBackBtn.textContent = 'Return to Safety';
        goBackBtn.style.cssText = 'padding: 10px 24px; border-radius: 8px; border: none; background: linear-gradient(135deg, #10b981, #059669); color: white; font-weight: 600; cursor: pointer; font-size: 14px;';
        goBackBtn.addEventListener('click', () => {
            if (window.history.length > 1) {
                const currentPage = window.location.href;
                let fallbackTimer;
                const cancelFallback = () => window.clearTimeout(fallbackTimer);
                window.addEventListener('pagehide', cancelFallback, { once: true });
                fallbackTimer = window.setTimeout(() => {
                    window.removeEventListener('pagehide', cancelFallback);
                    // Only close if history.back() left this extension page active.
                    if (window.location.href === currentPage) {
                        chrome.runtime.sendMessage({ action: "close_tab" });
                    }
                }, 1000);
                window.history.back();
            } else {
                chrome.runtime.sendMessage({ action: "close_tab" });
            }
        });

        // "Proceed Anyway" button — user takes responsibility
        const proceedBtn = document.createElement('button');
        proceedBtn.textContent = 'Proceed Without Protection';
        proceedBtn.style.cssText = 'padding: 10px 24px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.05); color: #aaa; font-weight: 500; cursor: pointer; font-size: 13px;';
        proceedBtn.addEventListener('click', () => {
            const warning = scanReason
                ? "This site could not be verified by the scanner. This is not a phishing verdict, but the site has not been confirmed safe. Continue without protection?"
                : "WARNING: This URL has NOT been scanned for phishing threats. The AI protection server is currently unavailable. Proceed at your own risk?";
            if (confirm(warning)) {
                // Add to temporary allow list so onBeforeNavigate doesn't re-intercept
                chrome.runtime.sendMessage({
                    action: "allow_unsafe_url",
                    url: targetUrl
                }, () => {
                    window.location.replace(targetUrl);
                });
            }
        });

        actionsDiv.appendChild(goBackBtn);
        actionsDiv.appendChild(proceedBtn);
        container.appendChild(actionsDiv);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const reason = urlParams.get('reason');

    const urlDisplay = document.getElementById('blocked-url');
    const reasonDisplay = document.getElementById('block-reason');
    const btnGoBack = document.getElementById('btn-go-back');
    const btnProceed = document.getElementById('btn-proceed');
    const btnCopyDomain = document.getElementById('btn-copy-domain');
    const whitelistHint = document.querySelector('.whitelist-hint');

    const status = urlParams.get('status');

    if (targetUrl) {
        urlDisplay.innerText = targetUrl;
    } else {
        urlDisplay.innerText = "Unknown URL";
    }

    if (reason) {
        reasonDisplay.innerText = reason;
    }

    const modelOnlyWarning = reason === 'Unverified AI Model Prediction' || reason === 'AI Model Detection Pattern';

    if (status === 'unable_to_verify') {
        document.body.classList.add('verification-unavailable');
        const titleEl = document.querySelector('.block-content h1');
        const descEl = document.querySelector('.description');
        if (titleEl) titleEl.innerText = "Unable to Verify This Site";
        if (descEl) descEl.innerText = "The scanner could not retrieve the page. Some sites reject automated scan requests; network or TLS problems can also interrupt a scan. This is not a phishing verdict and does not confirm that the site is safe.";
        if (reasonDisplay) reasonDisplay.innerText = reason || "Scan incomplete";
        if (whitelistHint) whitelistHint.hidden = true;
        btnProceed.textContent = "Proceed Without Protection";
        document.title = "AI Guard - Unable to Verify";
    } else if (status === 'suspicious' || modelOnlyWarning) {
        const titleEl = document.querySelector('.block-content h1');
        const descEl = document.querySelector('.description');
        if (modelOnlyWarning) {
            if (titleEl) titleEl.innerText = "Uncertain AI Warning";
            if (descEl) descEl.innerText = "The URL model flagged this address, but this result is not a confirmed phishing report. Check the domain carefully before entering information.";
            document.title = "AI Guard - Uncertain Warning";
        } else {
            if (titleEl) titleEl.innerText = "Suspicious Site Warning";
            if (descEl) descEl.innerText = "Our analysis detected unusual patterns on this website. This is not a confirmed phishing report; check the address carefully before entering information.";
            document.title = "AI Guard - Suspicious Site";
        }
    }

    btnGoBack.addEventListener('click', () => {
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

    btnProceed.addEventListener('click', () => {
        const proceedWarning = status === 'unable_to_verify'
            ? "This site could not be verified by the scanner. This is not a phishing verdict, but the site has not been confirmed safe. Continue without protection?"
            : modelOnlyWarning
            ? "The URL model flagged this address, but phishing has not been confirmed. Continue only if you recognize and trust the site?"
            : "WARNING: This site may be malicious. Proceeding could put your data at risk. Are you sure you want to continue?";
        if (confirm(proceedWarning)) {
            // Tell the background script to temporarily allow this domain
            if (targetUrl) {
                chrome.runtime.sendMessage({
                    action: "allow_unsafe_url",
                    url: targetUrl
                }, () => {
                    window.location.replace(targetUrl);
                });
            }
        }
    });

    if (btnCopyDomain && targetUrl) {
        btnCopyDomain.addEventListener('click', async () => {
            try {
                const hostname = new URL(targetUrl).hostname.replace('www.', '');
                await navigator.clipboard.writeText(hostname);

                const originalText = btnCopyDomain.innerHTML;
                btnCopyDomain.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
                btnCopyDomain.style.color = '#10b981';

                setTimeout(() => {
                    btnCopyDomain.innerHTML = originalText;
                    btnCopyDomain.style.color = '#fff';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy text: ', err);
            }
        });
    }
});

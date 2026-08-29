document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const reason = urlParams.get('reason');

    const urlDisplay = document.getElementById('blocked-url');
    const reasonDisplay = document.getElementById('block-reason');
    const btnGoBack = document.getElementById('btn-go-back');
    const btnProceed = document.getElementById('btn-proceed');
    const btnCopyDomain = document.getElementById('btn-copy-domain');

    if (targetUrl) {
        urlDisplay.innerText = targetUrl;
    } else {
        urlDisplay.innerText = "Unknown URL";
    }

    if (reason) {
        reasonDisplay.innerText = reason;
    }

    btnGoBack.addEventListener('click', () => {
        // We cannot reliably use history.back() because it often takes the user 
        // back to scanning.html, which re-blocks the page and creates an infinite loop.
        // Returning to a known safe page is the best behavior.
        window.location.replace('https://www.google.com');
    });

    btnProceed.addEventListener('click', () => {
        if (confirm("WARNING: This site is highly likely to be malicious. Proceeding will expose your device to potential risks. Are you sure you want to continue?")) {
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

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const reason = urlParams.get('reason');

    const urlDisplay = document.getElementById('blocked-url');
    const reasonDisplay = document.getElementById('block-reason');
    const btnGoBack = document.getElementById('btn-go-back');
    const btnProceed = document.getElementById('btn-proceed');

    if (targetUrl) {
        urlDisplay.innerText = targetUrl;
    } else {
        urlDisplay.innerText = "Unknown URL";
    }

    if (reason) {
        reasonDisplay.innerText = reason;
    }

    btnGoBack.addEventListener('click', () => {
        // Go back to the previous safe page, or close the tab
        if (window.history.length > 1) {
            window.history.back();
        } else {
            window.close();
        }
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
});

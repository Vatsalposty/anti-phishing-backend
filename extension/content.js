// Anti-Phishing Guard - Content Script

console.log("Anti-Phishing Guard: Content script active");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_ALERT") {
        showOverlay(request.type);
    }
});

function showOverlay(type) {
    chrome.storage.sync.get({ protectionEnabled: true }, (items) => {
        if (!items.protectionEnabled) {
            console.log("Anti-Phishing Guard: Protection disabled, suppressing overlay.");
            return;
        }

        if (document.getElementById('phishing-guard-overlay')) return;

        const overlay = document.createElement('div');
        overlay.id = 'phishing-guard-overlay';

        // Styles
        overlay.style.position = 'fixed';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100vw';
        overlay.style.height = '100vh';
        overlay.style.zIndex = '99999999';
        overlay.style.backgroundColor = 'rgba(255, 255, 255, 0.4)';
        overlay.style.backdropFilter = 'blur(20px)';
        overlay.style.WebkitBackdropFilter = 'blur(20px)';
        overlay.style.color = '#1d1d1f';
        overlay.style.display = 'flex';
        overlay.style.opacity = '0';
        overlay.style.transition = 'opacity 0.6s ease';
        overlay.style.flexDirection = 'column';
        overlay.style.alignItems = 'center';
        overlay.style.justifyContent = 'center';
        overlay.style.fontFamily = "'Inter', -apple-system, sans-serif";
        overlay.style.textAlign = 'center';

        const color = type === 'phishing' ? '#f5576c' : '#fda085';
        const titleText = type === 'phishing' ? 'PHISHING DETECTED' : 'SUSPICIOUS SITE';
        const msgText = type === 'phishing'
            ? 'This website has been identified as a potential phishing attack. Access is restricted to protect your data.'
            : 'This website shows suspicious behavior. Proceed with caution.';

        overlay.innerHTML = `
        <div style="max-width: 550px; padding: 50px 40px; background: rgba(255,255,255,0.7); border: 1px solid rgba(255,255,255,0.5); border-radius: 32px; box-shadow: 0 20px 50px rgba(0,0,0,0.15); backdrop-filter: blur(10px);">
            <div style="display: flex; justify-content: center; margin-bottom: 24px;">
                <div style="padding: 20px; background: white; border-radius: 24px; box-shadow: 0 10px 20px rgba(0,0,0,0.05); color: ${color};">
                    <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                </div>
            </div>
            <h1 style="font-size: 32px; font-weight: 800; margin-bottom: 16px; letter-spacing: -0.04em; color: #000;">${titleText}</h1>
            <p style="font-size: 18px; line-height: 1.6; color: #515154; margin-bottom: 32px; font-weight: 500;">${msgText}</p>
            
            <div style="display: flex; flex-direction: column; gap: 14px; align-items: center;">
                <button id="pg-go-back" style="width: 100%; max-width: 300px; padding: 18px; font-size: 18px; font-weight: 700; border-radius: 20px; border: none; cursor: pointer; background: #000; color: white; transition: all 0.2s ease; box-shadow: 0 10px 20px rgba(0,0,0,0.1);">
                    Go Back to Safety
                </button>
                <button id="pg-ignore" style="padding: 10px 20px; font-size: 14px; font-weight: 600; border-radius: 12px; border: 1px solid rgba(0,0,0,0.1); background: transparent; color: #8b949e; cursor: pointer; transition: all 0.2s;">
                    Bypass Warning (Testing)
                </button>
            </div>
        </div>
    `;

        document.body.appendChild(overlay);

        // Fade in
        setTimeout(() => overlay.style.opacity = '1', 10);

        // Stop scrolling
        document.body.style.overflow = 'hidden';

        // Event Listeners
        document.getElementById('pg-go-back').addEventListener('click', () => {
            if (history.length > 1) {
                history.back();
            } else {
                window.location.href = 'https://www.google.com';
            }
        });

        document.getElementById('pg-ignore').addEventListener('click', () => {
            overlay.remove();
            document.body.style.overflow = '';
            unblockInputs();
        });

        blockInputs();
    });
}

const blockHandlers = {
    handleEvent: function (e) {
        // Allow interaction with the overlay
        const overlay = document.getElementById('phishing-guard-overlay');
        if (overlay && overlay.contains(e.target)) {
            return;
        }

        e.preventDefault();
        e.stopPropagation();
        console.log("Anti-Phishing Guard: Blocked interaction on suspicious site.");
    }
};

function blockInputs() {
    // Stop any pending loads
    window.stop();

    // Capture and block events at the window level
    const eventsToBlock = [
        'submit', 'keydown', 'keyup', 'keypress',
        'input', 'click', 'mousedown', 'mouseup',
        'paste', 'copy', 'cut', 'contextmenu',
        'focus', 'focusin', 'touchstart', 'touchend'
    ];

    eventsToBlock.forEach(eventType => {
        window.addEventListener(eventType, blockHandlers, true);
    });

    // Disable all input elements directly - EXCEPT those in our overlay
    const overlay = document.getElementById('phishing-guard-overlay');
    document.querySelectorAll('input, textarea, select, button, [contenteditable="true"]').forEach(el => {
        // Skip if element is inside our overlay
        if (overlay && overlay.contains(el)) {
            return;
        }
        el.disabled = true;
        el.readOnly = true;
        el.style.pointerEvents = 'none';
        el.style.opacity = '0.5';
    });

    // Disable all forms - EXCEPT those in our overlay
    document.querySelectorAll('form').forEach(form => {
        if (overlay && overlay.contains(form)) {
            return;
        }
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log("Anti-Phishing Guard: Form submission blocked!");
            return false;
        }, true);
    });

    console.log("Anti-Phishing Guard: All inputs BLOCKED (overlay buttons preserved).");
}

function unblockInputs() {
    const eventsToBlock = [
        'submit', 'keydown', 'keyup', 'keypress',
        'input', 'click', 'mousedown', 'mouseup',
        'paste', 'copy', 'cut', 'contextmenu',
        'focus', 'focusin', 'touchstart', 'touchend'
    ];

    eventsToBlock.forEach(eventType => {
        window.removeEventListener(eventType, blockHandlers, true);
    });

    // Re-enable input elements
    document.querySelectorAll('input, textarea, select, button, [contenteditable="true"]').forEach(el => {
        el.disabled = false;
        el.readOnly = false;
        el.style.pointerEvents = '';
        el.style.opacity = '';
    });

    console.log("Anti-Phishing Guard: Inputs UNBLOCKED (bypass).");
}

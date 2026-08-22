// Anti-Phishing Guard - Content Script

console.log("Anti-Phishing Guard: Content script active");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_ALERT") {
        showOverlay(request.type, request.reason);
    }
});

function showOverlay(type, reason) {
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

        // Sanitize reason text to prevent XSS (never use innerHTML with API data)
        const safeReason = reason ? String(reason).substring(0, 200) : '';
        // Safe DOM creation to avoid innerHTML (XSS Vulnerability)
        const container = document.createElement('div');
        container.style.maxWidth = '550px';
        container.style.padding = '50px 40px';
        container.style.background = 'rgba(255,255,255,0.7)';
        container.style.border = '1px solid rgba(255,255,255,0.5)';
        container.style.borderRadius = '32px';
        container.style.boxShadow = '0 20px 50px rgba(0,0,0,0.15)';
        container.style.backdropFilter = 'blur(10px)';

        const iconWrapper = document.createElement('div');
        iconWrapper.style.display = 'flex';
        iconWrapper.style.justifyContent = 'center';
        iconWrapper.style.marginBottom = '24px';
        
        const iconDiv = document.createElement('div');
        iconDiv.style.padding = '20px';
        iconDiv.style.background = 'white';
        iconDiv.style.borderRadius = '24px';
        iconDiv.style.boxShadow = '0 10px 20px rgba(0,0,0,0.05)';
        iconDiv.style.color = color;
        // The SVG is static and perfectly safe to use innerHTML for, but let's use insertAdjacentHTML or createElement
        iconDiv.innerHTML = `<svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
            <line x1="12" y1="9" x2="12" y2="13"></line>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
        </svg>`;
        iconWrapper.appendChild(iconDiv);

        const title = document.createElement('h1');
        title.style.fontSize = '32px';
        title.style.fontWeight = '800';
        title.style.marginBottom = '16px';
        title.style.letterSpacing = '-0.04em';
        title.style.color = '#000';
        title.textContent = titleText;

        const pDesc = document.createElement('p');
        pDesc.style.fontSize = '18px';
        pDesc.style.lineHeight = '1.6';
        pDesc.style.color = '#515154';
        pDesc.style.marginBottom = '32px';
        pDesc.style.fontWeight = '500';
        pDesc.textContent = msgText;

        container.appendChild(iconWrapper);
        container.appendChild(title);
        container.appendChild(pDesc);

        if (safeReason) {
            const reasonWrapper = document.createElement('div');
            reasonWrapper.style.marginTop = '-12px';
            reasonWrapper.style.marginBottom = '24px';
            reasonWrapper.style.padding = '8px 16px';
            reasonWrapper.style.background = 'rgba(0,0,0,0.03)';
            reasonWrapper.style.borderRadius = '8px';
            reasonWrapper.style.display = 'inline-block';

            const reasonTitle = document.createElement('span');
            reasonTitle.style.fontWeight = '700';
            reasonTitle.style.color = color;
            reasonTitle.style.fontSize = '14px';
            reasonTitle.style.textTransform = 'uppercase';
            reasonTitle.style.letterSpacing = '0.5px';
            reasonTitle.textContent = 'DETECTION REASON:';

            const reasonText = document.createElement('span');
            reasonText.id = 'pg-reason-text';
            reasonText.style.fontWeight = '500';
            reasonText.style.color = '#333';
            reasonText.style.fontSize = '15px';
            reasonText.style.marginLeft = '6px';
            reasonText.textContent = safeReason;

            reasonWrapper.appendChild(reasonTitle);
            reasonWrapper.appendChild(reasonText);
            container.appendChild(reasonWrapper);
        }

        const buttonGroup = document.createElement('div');
        buttonGroup.style.display = 'flex';
        buttonGroup.style.flexDirection = 'column';
        buttonGroup.style.gap = '14px';
        buttonGroup.style.alignItems = 'center';

        const btnGoBack = document.createElement('button');
        btnGoBack.id = 'pg-go-back';
        btnGoBack.style.width = '100%';
        btnGoBack.style.maxWidth = '300px';
        btnGoBack.style.padding = '18px';
        btnGoBack.style.fontSize = '18px';
        btnGoBack.style.fontWeight = '700';
        btnGoBack.style.borderRadius = '20px';
        btnGoBack.style.border = 'none';
        btnGoBack.style.cursor = 'pointer';
        btnGoBack.style.background = '#000';
        btnGoBack.style.color = 'white';
        btnGoBack.style.transition = 'all 0.2s ease';
        btnGoBack.style.boxShadow = '0 10px 20px rgba(0,0,0,0.1)';
        btnGoBack.textContent = 'Go Back to Safety';

        const btnIgnore = document.createElement('button');
        btnIgnore.id = 'pg-ignore';
        btnIgnore.style.padding = '10px 20px';
        btnIgnore.style.fontSize = '14px';
        btnIgnore.style.fontWeight = '600';
        btnIgnore.style.borderRadius = '12px';
        btnIgnore.style.border = '1px solid rgba(0,0,0,0.1)';
        btnIgnore.style.background = 'transparent';
        btnIgnore.style.color = '#8b949e';
        btnIgnore.style.cursor = 'pointer';
        btnIgnore.style.transition = 'all 0.2s';
        btnIgnore.textContent = 'Bypass Warning (Testing)';

        const helpText = document.createElement('p');
        helpText.style.marginTop = '8px';
        helpText.style.fontSize = '13px';
        helpText.style.fontWeight = '600';
        helpText.style.color = '#ff6b6b';
        helpText.style.maxWidth = '400px';
        helpText.style.lineHeight = '1.4';
        helpText.textContent = 'If this page is safe, copy its domain and add it to "Trusted Domains (Allowlist)" in Settings to permanently remove this warning.';

        buttonGroup.appendChild(btnGoBack);
        buttonGroup.appendChild(btnIgnore);
        buttonGroup.appendChild(helpText);
        container.appendChild(buttonGroup);
        overlay.appendChild(container);

        // Append to DOM!
        if (document.body) {
            document.body.appendChild(overlay);
        } else {
            document.documentElement.appendChild(overlay);
        }

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
        // Check if target is a valid Node before calling contains (prevents TypeError on window/document events)
        if (overlay && e.target instanceof Node && overlay.contains(e.target)) {
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

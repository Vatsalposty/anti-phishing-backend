// Anti-Phishing Guard - Content Script

console.log("Anti-Phishing Guard: Content script active");

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_ALERT") {
        showOverlay(request.type);
    }
});

function showOverlay(type) {
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
    overlay.style.backgroundColor = 'rgba(13, 17, 23, 0.85)'; // Slightly more transparent
    overlay.style.backdropFilter = 'blur(10px)'; // Premium blur effect
    overlay.style.color = 'white';
    overlay.style.display = 'flex';
    overlay.style.opacity = '0'; // For transition
    overlay.style.transition = 'opacity 0.5s ease-in-out';
    overlay.style.flexDirection = 'column';
    overlay.style.alignItems = 'center';
    overlay.style.justifyContent = 'center';
    overlay.style.fontFamily = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
    overlay.style.textAlign = 'center';

    const color = type === 'phishing' ? '#da3633' : '#d29922'; // Red or Yellow
    const titleText = type === 'phishing' ? 'PHISHING DETECTED' : 'SUSPICIOUS SITE';
    const msgText = type === 'phishing'
        ? 'This website has been identified as a potential phishing attack. Access is restricted to protect your data.'
        : 'This website shows suspicious behavior. Proceed with caution.';

    overlay.innerHTML = `
        <div style="max-width: 600px; padding: 40px; border: 2px solid ${color}; border-radius: 16px; background: #000;">
            <svg style="color: ${color}; margin-bottom: 20px;" width="80" height="80" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12C2 17.52 6.48 22 12 22C17.52 22 22 17.52 22 12C22 6.48 17.52 2 12 2ZM13 17H11V15H13V17ZM13 13H11V7H13V13Z"/>
            </svg>
            <h1 style="font-size: 32px; font-weight: bold; margin-bottom: 16px; color: ${color};">${titleText}</h1>
            <p style="font-size: 18px; line-height: 1.5; color: #ccc; margin-bottom: 30px;">${msgText}</p>
            
            <div style="display: flex; gap: 20px; justify-content: center;">
                <button id="pg-go-back" style="padding: 12px 24px; font-size: 16px; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; background: ${color}; color: white; transition: opacity 0.2s;">
                    Go Back to Safety
                </button>
                <button id="pg-ignore" style="padding: 12px 24px; font-size: 16px; font-weight: bold; border-radius: 8px; border: 1px solid #555; background: transparent; color: #888; cursor: pointer;">
                    Project Testing (Ignore)
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
        history.back();
    });

    document.getElementById('pg-ignore').addEventListener('click', () => {
        overlay.remove();
        document.body.style.overflow = '';
        unblockInputs();
    });

    blockInputs();
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

    // Capture and block events
    window.addEventListener('submit', blockHandlers, true);
    window.addEventListener('keydown', blockHandlers, true);
    window.addEventListener('input', blockHandlers, true);
    window.addEventListener('click', blockHandlers, true);
    window.addEventListener('mousedown', blockHandlers, true);
}

function unblockInputs() {
    window.removeEventListener('submit', blockHandlers, true);
    window.removeEventListener('keydown', blockHandlers, true);
    window.removeEventListener('input', blockHandlers, true);
    window.removeEventListener('click', blockHandlers, true);
    window.removeEventListener('mousedown', blockHandlers, true);
}

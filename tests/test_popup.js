const fs = require('fs');
const assert = require('assert');

// Simple DOM Mock
class ElementMock {
    constructor(id) {
        this.id = id;
        this.textContent = '';
        this.classes = new Set();
        this.classList = {
            add: (...c) => c.forEach(cls => this.classes.add(cls)),
            remove: (...c) => c.forEach(cls => this.classes.delete(cls))
        };
        this.style = {};
    }
    addEventListener() {}
}

const elements = {};
function getOrCreateElement(query) {
    if (!elements[query]) elements[query] = new ElementMock(query);
    return elements[query];
}

global.document = {
    addEventListener: (event, cb) => {
        if (event === 'DOMContentLoaded') global.triggerDOMContentLoaded = cb;
    },
    getElementById: getOrCreateElement,
    querySelector: getOrCreateElement,
    documentElement: { style: { setProperty: () => {} } }
};

global.window = { open: () => {} };

// Mock Chrome API
global.chrome = {
    tabs: {
        query: async (queryInfo) => {
            return [global.mockActiveTab];
        }
    },
    storage: {
        sync: {
            get: (defaults, cb) => cb({ protectionEnabled: true })
        },
        local: {
            get: (defaults, cb) => cb(defaults)
        },
        onChanged: { addListener: () => {} }
    },
    runtime: {
        getURL: () => '',
        sendMessage: () => {},
        onMessage: { addListener: (listener) => { global.popupMessageListener = listener; } }
    }
};

const popupCode = fs.readFileSync('extension/popup/popup.js', 'utf8');
eval(popupCode);

async function runTest() {
    let passed = 0;
    let failed = 0;

    console.log("═══════════════════════════════════════════════════════");
    console.log("  Popup UI Startup Test Suite");
    console.log("═══════════════════════════════════════════════════════\n");

    try {
        // Test 1: Chrome page triggers not_scanned UI immediately
        global.mockActiveTab = { id: 1, url: 'chrome://extensions/' };
        await global.triggerDOMContentLoaded();

        // Wait for microtasks
        await new Promise(r => setTimeout(r, 10));

        const statusText = getOrCreateElement('status-text').textContent;
        const urlText = getOrCreateElement('current-url').textContent;

        if (statusText === 'Not scanned' && urlText === 'Chrome Page') {
            console.log(`  ✅ PASS  Internal chrome:// page immediately shows 'Not scanned' state`);
            passed++;
        } else {
            console.error(`  ❌ FAIL  Expected 'Not scanned' and 'Chrome Page', got statusText='${statusText}' and urlText='${urlText}'`);
            failed++;
        }

        global.popupMessageListener({ action: 'update_status', data: { status: 'unexpected_future_status' } }, {}, () => {});
        const unknownStatusText = getOrCreateElement('status-text').textContent;
        if (unknownStatusText === 'Unable to verify') {
            console.log('  ✅ PASS  Unknown backend status displays Unable to verify, never Safe');
            passed++;
        } else {
            console.error(`  ❌ FAIL  Unknown backend status displayed '${unknownStatusText}'`);
            failed++;
        }

        global.popupMessageListener({ action: 'update_status', data: { status: 'safe', confidence: 90 } }, {}, () => {});
        const safeStatusText = getOrCreateElement('status-text').textContent;
        if (safeStatusText === 'No Threats Detected') {
            console.log('  ✅ PASS  Explicit safe status retains the safe UI');
            passed++;
        } else {
            console.error(`  ❌ FAIL  Explicit safe status displayed '${safeStatusText}'`);
            failed++;
        }
    } catch(e) {
        console.error(e);
        failed++;
    }

    console.log("\n═══════════════════════════════════════════════════════");
    console.log(`  Results: ${passed}/${passed + failed} passed${failed > 0 ? ` — ${failed} FAILED` : ' — ALL PASSED ✅'}`);
    console.log("═══════════════════════════════════════════════════════\n");
    process.exit(failed > 0 ? 1 : 0);
}

runTest();

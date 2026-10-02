// Node.js test runner for complete navigation behavior
// Run: node tests/test_navigation_flow.js

const assert = require('assert');

// Mock chrome API
global.chrome = {
    runtime: {
        getURL: (path) => `chrome-extension://ext-id/${path}`,
        sendMessage: () => {},
        lastError: null
    },
    tabs: {
        update: (tabId, updateProperties) => {
            global.lastTabUpdate = { tabId, updateProperties };
        }
    },
    action: {
        setBadgeText: () => {},
        setBadgeBackgroundColor: () => {}
    },
    storage: {
        sync: {
            get: (defaults, callback) => {
                const res = { protectionEnabled: true, whitelist: [], devMode: false };
                if (global.testStorageSyncGetOverride) {
                    Object.assign(res, global.testStorageSyncGetOverride);
                }
                if (callback) { callback(res); return; }
                return Promise.resolve(res);
            }
        },
        local: {
            get: (defaults, cb) => cb(defaults),
            set: (items) => {}
        }
    },
    notifications: {
        create: () => {}
    },
    webNavigation: {
        onErrorOccurred: { addListener: () => {} }
    }
};

global.tabStatus = new Map();
global.tabGenerations = new Map();
global.verifiedUrls = new Set();
global.allowedUnsafeUrls = new Set();

let mockFetchResponse = null;
let mockFetchError = null;
global.fetch = async (url, options) => {
    if (mockFetchError) throw mockFetchError;
    return mockFetchResponse;
};

// Import code we want to test
const fs = require('fs');
const bgCode = fs.readFileSync('extension/background.js', 'utf8');

// Strip out event listeners that cause problems in node
global.self = { addEventListener: () => {} };
const testableCode = bgCode
    .replace(/chrome\.webNavigation\.onBeforeNavigate\.addListener/g, 'global.test_onBeforeNavigate = ')
    .replace(/chrome\.webNavigation\.onErrorOccurred\.addListener/g, 'global.test_onErrorOccurred = ')
    .replace(/chrome\.tabs\.onUpdated\.addListener/g, 'global.test_onUpdated = ')
    .replace(/chrome\.runtime\.onMessage\.addListener/g, 'global.test_onMessage = ')
    .replace(/chrome\.storage\.onChanged\.addListener/g, 'global.test_storageOnChanged = ')
    .replace(/const tabStatus = new Map\(\);/g, '')
    .replace(/const verifiedUrls = new Set\(\);/g, '')
    .replace(/const allowedUnsafeUrls = new Set\(\);/g, '')
    .replace(/const tabGenerations = new Map\(\);/g, '');

eval(testableCode);

async function runTests() {
    let passed = 0;
    let failed = 0;

    function assertCondition(desc, cond) {
        if (cond) {
            console.log(`  ✅ PASS  ${desc}`);
            passed++;
        } else {
            console.error(`  ❌ FAIL  ${desc}`);
            failed++;
        }
    }

    console.log("═══════════════════════════════════════════════════════");
    console.log("  Navigation Flow & Security Constraints Test Suite");
    console.log("═══════════════════════════════════════════════════════\n");
    console.log("test_onErrorOccurred:", global.test_onErrorOccurred ? global.test_onErrorOccurred.toString() : 'undefined');
    console.log("test_onBeforeNavigate:", global.test_onBeforeNavigate ? global.test_onBeforeNavigate.toString() : 'undefined');

    try {
        // Test 1: Local network URL bypasses scanning
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 1, url: 'http://10.10.10.10/login' });
        assertCondition('Local IP bypassed intercept', global.lastTabUpdate === null);
        let localStatus = null;
        global.test_onMessage({ action: "get_status", tabId: 1 }, {}, (res) => { localStatus = res; });
        assertCondition('Local IP sets local_network status', localStatus && localStatus.status === 'local_network');

        // Test 2: Public URL is intercepted
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 2, url: 'https://example.com' });
        assertCondition('Public URL intercepted', global.lastTabUpdate !== null && global.lastTabUpdate.updateProperties.url.includes('scanning.html'));

        // Test 3: Backend unavailable for public URL
        mockFetchError = new Error('Network error');
        const result3 = await analyzeUrl(3, 'https://example.com');
        assertCondition('Backend unavailable returns unable_to_verify status', result3.status === 'unable_to_verify');
        assertCondition('Backend unavailable does NOT mark safe', result3.status !== 'safe');

        // Test 4: Whitelist allows bypass
        global.testStorageSyncGetOverride = { whitelist: ['whitelisted.com'] };
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 4, url: 'https://whitelisted.com' });
        assertCondition('Whitelisted URL bypassed intercept', global.lastTabUpdate === null);

        // Test 5: Disabled protection allows bypass
        global.testStorageSyncGetOverride = { protectionEnabled: false };
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 5, url: 'https://example.com' });
        assertCondition('Disabled protection bypassed intercept', global.lastTabUpdate === null);

        // Test 6: Backend success (safe)
        global.testStorageSyncGetOverride = { protectionEnabled: true, whitelist: [] };
        mockFetchError = null;
        mockFetchResponse = { ok: true, json: async () => ({ status: 'safe', confidence: 99 }) };
        const result6 = await analyzeUrl(6, 'https://safe.com');
        assertCondition('Backend success returns safe status', result6.status === 'safe');

        // Test 7: Verify caching prevents re-intercept
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 6, url: 'https://safe.com/' });
        assertCondition('Cached URL bypassed intercept', global.lastTabUpdate === null);

        // Test 8: Backend success (phishing)
        mockFetchResponse = { ok: true, json: async () => ({ status: 'phishing', confidence: 99 }) };
        const result8 = await analyzeUrl(8, 'https://evil.com');
        assertCondition('Backend success returns phishing status', result8.status === 'phishing');

        // Test 9: DNS failure sets unable_to_verify and doesn't carry safe
        global.test_onErrorOccurred({ frameId: 0, tabId: 9, url: 'https://bad-dns.com', error: 'net::ERR_NAME_NOT_RESOLVED' });
        let status9 = tabStatus.get(9);
        console.log("status9:", status9);
        assertCondition('DNS failure returns UNABLE_TO_VERIFY', status9 && status9.status === 'unable_to_verify');
        
        // Test 10: Stale tab results cleared on new navigation
        tabStatus.set(10, { status: 'safe', url: 'https://old-site.com' });
        global.test_onBeforeNavigate({ frameId: 0, tabId: 10, url: 'chrome://newtab/' });
        assertCondition('Stale tab results cleared on navigation', !tabStatus.has(10));
        
        let status10 = null;
        global.test_onMessage({ action: "get_status", tabId: 10 }, {}, (res) => { status10 = res; });
        assertCondition('Non-HTTP internal page returns not_scanned', status10.status === 'not_scanned' || status10.status === 'scanning');
        // Wait, onBeforeNavigate for chrome:// just clears status. 
        // When analyzeUrl is called for chrome://:
        const result10 = await analyzeUrl(10, 'chrome://newtab/');
        assertCondition('Internal non-HTTP page is distinctly not_scanned', result10.status === 'not_scanned');

        // Test 11: Race condition where scan finishes after navigation
        global.test_onBeforeNavigate({ frameId: 0, tabId: 11, url: 'https://site-a.com' });
        // Start scan for A
        mockFetchResponse = new Promise(resolve => setTimeout(() => resolve({ ok: true, json: async () => ({ status: 'phishing', confidence: 99 }) }), 100));
        let scanPromise = analyzeUrl(11, 'https://site-a.com');
        
        // Before A completes, user navigates to B
        global.test_onBeforeNavigate({ frameId: 0, tabId: 11, url: 'https://site-b.com' });
        const resultRace = await scanPromise;
        assertCondition('Stale scan race condition returns stale status', resultRace.status === 'stale');
        assertCondition('Stale scan does not overwrite new navigation state', !tabStatus.has(11) || tabStatus.get(11).status !== 'phishing');

    } catch (e) {
        console.error(e);
        failed++;
    }

    console.log("\n═══════════════════════════════════════════════════════");
    console.log(`  Results: ${passed}/${passed + failed} passed${failed > 0 ? ` — ${failed} FAILED` : ' — ALL PASSED ✅'}`);
    console.log("═══════════════════════════════════════════════════════\n");

    process.exit(failed > 0 ? 1 : 0);
}

runTests();

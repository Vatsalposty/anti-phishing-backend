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
        setBadgeText: (details) => { global.lastBadgeText = details; },
        setBadgeBackgroundColor: (details) => { global.lastBadgeColor = details; }
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
            set: (items) => { (global.localWrites || (global.localWrites = [])).push(items); }
        }
    },
    notifications: {
        create: () => { global.notificationCount = (global.notificationCount || 0) + 1; }
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
        assertCondition('Whitelisted URL sets explicitly whitelisted status', tabStatus.get(4) && tabStatus.get(4).status === 'whitelisted');

        // Test 5: Disabled protection allows bypass
        global.testStorageSyncGetOverride = { protectionEnabled: false };
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 5, url: 'https://example.com' });
        assertCondition('Disabled protection bypassed intercept', global.lastTabUpdate === null);
        assertCondition('Disabled protection sets explicit disabled status', tabStatus.get(5) && tabStatus.get(5).status === 'disabled');

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
        assertCondition('Cached URL sets previously_checked status', tabStatus.get(6) && tabStatus.get(6).status === 'previously_checked');

        // Test 7b: Cache includes query string, different query is NOT bypassed
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 66, url: 'https://safe.com/?q=new' });
        assertCondition('Cached URL with different query is intercepted', global.lastTabUpdate !== null && global.lastTabUpdate.updateProperties.url.includes('scanning.html'));

        // Test 8: Backend success (phishing)
        mockFetchResponse = { ok: true, json: async () => ({ status: 'phishing', confidence: 99 }) };
        const result8 = await analyzeUrl(8, 'https://evil.com/?q=warn');
        assertCondition('Backend success returns phishing status', result8.status === 'phishing');

        // An unreachable destination is not a threat verdict or a blocked-site event.
        mockFetchResponse = { ok: true, json: async () => ({ status: 'unable_to_verify', confidence: 0, reason: 'Unreachable Destination' }) };
        global.localWrites = [];
        global.notificationCount = 0;
        const unavailableResult = await analyzeUrl(30, 'https://leetcode.com/');
        assertCondition('Unreachable destination remains unable_to_verify', unavailableResult.status === 'unable_to_verify');
        assertCondition('Unreachable destination uses an error badge, not green safe badge', global.lastBadgeText && global.lastBadgeText.text === 'ERR');
        assertCondition('Unreachable destination does not increment blocked count', !global.localWrites.some(write => Object.prototype.hasOwnProperty.call(write, 'blockedCount')));
        assertCondition('Unreachable destination does not trigger threat notification', global.notificationCount === 0);
        global.test_onUpdated(30, { status: 'complete' }, { url: 'chrome-extension://ext-id/pages/blocked.html?status=unable_to_verify' });
        assertCondition('Unable-to-verify interstitial keeps error badge', global.lastBadgeText && global.lastBadgeText.text === 'ERR');
        tabStatus.set(31, { status: 'suspicious' });
        global.test_onUpdated(31, { status: 'complete' }, { url: 'chrome-extension://ext-id/pages/blocked.html?status=suspicious' });
        assertCondition('Suspicious interstitial keeps warning badge', global.lastBadgeText && global.lastBadgeText.text === '?');

        // Test 8b: Allowing a warning URL doesn't bypass different query
        global.allowedUnsafeUrls.add('https://evil.com/?q=warn');
        global.lastTabUpdate = null;
        await global.test_onBeforeNavigate({ frameId: 0, tabId: 88, url: 'https://evil.com/?q=other' });
        assertCondition('Bypassed warning URL with different query is intercepted', global.lastTabUpdate !== null && global.lastTabUpdate.updateProperties.url.includes('scanning.html'));

        // Test 9: DNS failure sets unable_to_verify and doesn't carry safe
        global.test_onErrorOccurred({ frameId: 0, tabId: 9, url: 'https://bad-dns.com', error: 'net::ERR_NAME_NOT_RESOLVED' });
        let status9 = tabStatus.get(9);
        console.log("status9:", status9);
        assertCondition('DNS failure returns UNABLE_TO_VERIFY', status9 && status9.status === 'unable_to_verify');

        // Test 10: Stale tab results cleared on new navigation
        tabStatus.set(10, { status: 'safe', url: 'https://old-site.com' });
        global.test_onBeforeNavigate({ frameId: 0, tabId: 10, url: 'chrome://newtab/' });
        assertCondition('Stale tab results cleared on navigation', tabStatus.get(10) && tabStatus.get(10).status === 'not_scanned');

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

        // Test 12: onErrorOccurred invalidates in-flight scan
        global.test_onBeforeNavigate({ frameId: 0, tabId: 12, url: 'https://bad-connection.com' });
        mockFetchResponse = new Promise(resolve => setTimeout(() => resolve({ ok: true, json: async () => ({ status: 'safe', confidence: 99 }) }), 100));
        let scanPromise12 = analyzeUrl(12, 'https://bad-connection.com');

        // Before scan completes, browser navigation fails
        global.test_onErrorOccurred({ frameId: 0, tabId: 12, url: 'https://bad-connection.com', error: 'net::ERR_CONNECTION_REFUSED' });

        // Wait for scan to finish
        const resultRace12 = await scanPromise12;
        assertCondition('In-flight scan returns stale when browser navigation fails', resultRace12.status === 'stale');
        assertCondition('Browser error state is not overwritten by delayed scan', tabStatus.get(12) && tabStatus.get(12).status === 'unable_to_verify');

        // Test 13: onBeforeNavigate sets not_scanned explicitly for non-HTTP
        global.test_onBeforeNavigate({ frameId: 0, tabId: 13, url: 'file:///C:/Users/test/index.html' });
        const status13 = tabStatus.get(13);
        assertCondition('onBeforeNavigate explicitly sets not_scanned for non-HTTP schemes', status13 && status13.status === 'not_scanned');
        assertCondition('onBeforeNavigate does not clear status immediately after setting for non-HTTP', tabStatus.has(13));

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

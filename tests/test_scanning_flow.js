const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const source = fs.readFileSync('extension/pages/scanning.js', 'utf8');

function createPage(response, targetUrl = 'https://example.test/login') {
    const elements = new Map();
    const replacements = [];
    const timers = [];
    let domReady;

    class Element {
        constructor() {
            this.innerText = '';
            this.innerHTML = '';
            this.textContent = '';
            this.style = {};
            this.children = [];
            this.listeners = {};
        }
        addEventListener(name, callback) { this.listeners[name] = callback; }
        appendChild(child) { this.children.push(child); }
    }

    const document = {
        addEventListener(name, callback) { if (name === 'DOMContentLoaded') domReady = callback; },
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, new Element());
            return elements.get(id);
        },
        querySelector(selector) {
            if (!elements.has(selector)) elements.set(selector, new Element());
            return elements.get(selector);
        },
        createElement() { return new Element(); }
    };
    const window = {
        location: {
            search: `?url=${encodeURIComponent(targetUrl)}`,
            href: 'chrome-extension://test/pages/scanning.html',
            replace: (url) => replacements.push(url)
        },
        history: { length: 0, back() {} },
        setTimeout: (callback) => { timers.push(callback); return timers.length; },
        clearTimeout() {},
        addEventListener() {},
        removeEventListener() {}
    };
    const chrome = {
        runtime: {
            lastError: null,
            sendMessage(_message, callback) { callback(response); },
            getURL: (path) => `chrome-extension://test/${path}`
        }
    };
    const context = vm.createContext({
        document, window, chrome, URL, URLSearchParams,
        setTimeout: window.setTimeout,
        confirm: () => true,
        console
    });
    vm.runInContext(source, context);

    return {
        async start() { await domReady(); },
        get(id) { return elements.get(id); },
        replacements,
        timers,
        getContainer() { return elements.get('.scan-container'); }
    };
}

async function main() {
    const unavailable = createPage({ status: 'unable_to_verify', reason: 'HTTP Error 403' });
    await unavailable.start();
    assert.equal(unavailable.get('status-title').innerText, 'Unable to Verify This Site');
    assert.equal(unavailable.replacements.length, 0, 'unverified URL must not redirect automatically');
    assert.equal(unavailable.getContainer().children.length, 1, 'unverified screen should offer explicit choices');

    const unknown = createPage({ status: 'unexpected_future_status' });
    await unknown.start();
    assert.equal(unknown.get('status-title').innerText, 'Unable to Verify This Site');
    assert.equal(unknown.replacements.length, 0, 'unknown result must not route to the threat screen');

    const stale = createPage({ status: 'stale' });
    await stale.start();
    assert.equal(stale.replacements.length, 0, 'stale result must not redirect the active tab');

    const phishing = createPage({ status: 'phishing', reason: 'Confirmed test threat' });
    await phishing.start();
    assert.equal(phishing.replacements.length, 1);
    assert.match(phishing.replacements[0], /pages\/blocked\.html/);

    const safe = createPage({ status: 'safe' });
    await safe.start();
    assert.equal(safe.get('status-title').innerText, 'Site is Safe!');
    assert.equal(safe.timers.length, 1);
    safe.timers[0]();
    assert.deepEqual(safe.replacements, ['https://example.test/login']);

    console.log('PASS: scanning page distinguishes unavailable, unknown, stale, phishing, and safe results');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });

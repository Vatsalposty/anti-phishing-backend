const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync(path.join(__dirname, '..', 'extension', 'pages', 'history.html'), 'utf8');
const js = fs.readFileSync(path.join(__dirname, '..', 'extension', 'pages', 'history.js'), 'utf8');
const attackText = '<img src=x onerror="window.pwned=true">';
const history = [{
    url: attackText,
    fullUrl: `https://example.com/?q=${encodeURIComponent(attackText)}`,
    reason: attackText,
    status: 'unable_to_verify',
    confidence: 0,
    timestamp: Date.now()
}];

const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'chrome-extension://test/pages/history.html' });
dom.window.chrome = {
    storage: {
        local: {
            get: (_defaults, callback) => callback({ scanHistory: history, totalScans: 1 }),
            set: () => {}
        }
    }
};
dom.window.confirm = () => false;
dom.window.eval(js);
dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));

const item = dom.window.document.querySelector('.history-item');
assert(item, 'history item should render');
assert.strictEqual(item.querySelector('.status-badge').classList.contains('badge-unverified'), true);
assert.strictEqual(item.querySelector('.item-reason').textContent, attackText);
assert.strictEqual(item.querySelector('.item-domain').textContent, attackText);
assert.strictEqual(item.querySelectorAll('img,svg').length, 0, 'stored URL/reason text must not become markup');
assert.strictEqual(dom.window.pwned, undefined, 'stored URL/reason must not execute script');

console.log('PASS: history renders unable-to-verify neutrally and treats stored URL/reason as text');
dom.window.close();

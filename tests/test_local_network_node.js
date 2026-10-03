// Node.js test runner for isLocalNetworkUrl()
// Run: node tests/test_local_network_node.js

// ========================================
// Copy of isLocalNetworkUrl from background.js
// ========================================
function isLocalNetworkUrl(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();
        if (hostname === 'localhost') return true;
        if (hostname.endsWith('.local')) return true;
        const bare = hostname.replace(/^\[|\]$/g, '');
        const ipv4Match = bare.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (ipv4Match) {
            const [, a, b, c, d] = ipv4Match.map(Number);
            if (a > 255 || b > 255 || c > 255 || d > 255) return false;
            if (a === 127) return true;
            if (a === 10) return true;
            if (a === 172 && b >= 16 && b <= 31) return true;
            if (a === 192 && b === 168) return true;
            if (a === 169 && b === 254) return true;
            return false;
        }
        if (bare.includes(':')) {
            if (bare === '::1') return true;
            const expanded = expandIPv6(bare);
            if (!expanded) return false;
            const firstWord = parseInt(expanded.substring(0, 4), 16);
            if (firstWord >= 0xfc00 && firstWord <= 0xfdff) return true;
            if (firstWord >= 0xfe80 && firstWord <= 0xfebf) return true;
            return false;
        }
        return false;
    } catch (e) {
        return false;
    }
}

function expandIPv6(addr) {
    try {
        let parts = addr.split(':');
        const doubleColonIdx = addr.indexOf('::');
        if (doubleColonIdx !== -1) {
            const left = addr.substring(0, doubleColonIdx).split(':').filter(Boolean);
            const right = addr.substring(doubleColonIdx + 2).split(':').filter(Boolean);
            const missing = 8 - left.length - right.length;
            if (missing < 0) return null;
            parts = [...left, ...Array(missing).fill('0'), ...right];
        }
        if (parts.length !== 8) return null;
        return parts.map(p => p.padStart(4, '0')).join('');
    } catch (e) {
        return null;
    }
}

// ========================================
// Test Cases
// ========================================
const tests = [
    // IPv4 Loopback
    { url: "http://127.0.0.1", expected: true, desc: "127.0.0.1 loopback" },
    { url: "http://127.0.0.1:8000", expected: true, desc: "127.0.0.1:8000 loopback+port" },
    { url: "http://127.0.0.1/path/to/page", expected: true, desc: "127.0.0.1 with path" },
    { url: "http://127.255.255.255", expected: true, desc: "127.255.255.255 end of loopback" },

    // IPv4 Private 10.0.0.0/8
    { url: "http://10.0.0.1", expected: true, desc: "10.0.0.1 Class A private" },
    { url: "http://10.10.20.30", expected: true, desc: "10.10.20.30 typical captive portal" },
    { url: "http://10.255.255.255", expected: true, desc: "10.255.255.255 end of 10/8" },
    { url: "http://10.0.0.1:1000/login?redirect=true", expected: true, desc: "10.x with port+path+query" },

    // IPv4 Private 172.16.0.0/12
    { url: "http://172.16.0.1", expected: true, desc: "172.16.0.1 start of 172.16/12" },
    { url: "http://172.31.255.254", expected: true, desc: "172.31.255.254 end of 172.16/12" },
    { url: "http://172.15.0.1", expected: false, desc: "172.15.0.1 OUTSIDE 172.16/12" },
    { url: "http://172.32.0.1", expected: false, desc: "172.32.0.1 OUTSIDE 172.16/12" },

    // IPv4 Private 192.168.0.0/16
    { url: "http://192.168.0.1", expected: true, desc: "192.168.0.1 common router" },
    { url: "http://192.168.1.1", expected: true, desc: "192.168.1.1 common router" },
    { url: "http://192.168.255.255", expected: true, desc: "192.168.255.255 end of 192.168/16" },
    { url: "http://192.167.0.1", expected: false, desc: "192.167.0.1 NOT private" },

    // IPv4 Link-Local
    { url: "http://169.254.1.1", expected: true, desc: "169.254.1.1 link-local" },
    { url: "http://169.254.169.254", expected: true, desc: "169.254.169.254 cloud metadata" },
    { url: "http://169.253.0.1", expected: false, desc: "169.253.0.1 NOT link-local" },

    // Localhost hostname
    { url: "http://localhost", expected: true, desc: "localhost standard" },
    { url: "http://localhost:3000", expected: true, desc: "localhost:3000 with port" },
    { url: "http://localhost/api/test", expected: true, desc: "localhost with path" },
    { url: "http://LOCALHOST", expected: true, desc: "LOCALHOST uppercase" },

    // .local hostnames
    { url: "http://something.local", expected: true, desc: "something.local mDNS" },
    { url: "http://printer.local:631", expected: true, desc: "printer.local with port" },
    { url: "http://my-server.local/admin", expected: true, desc: "my-server.local with path" },

    // IPv6 Loopback
    { url: "http://[::1]", expected: true, desc: "[::1] IPv6 loopback" },
    { url: "http://[::1]:8080", expected: true, desc: "[::1]:8080 IPv6 loopback+port" },

    // IPv6 ULA (fc00::/7)
    { url: "http://[fc00::1]", expected: true, desc: "[fc00::1] ULA start" },
    { url: "http://[fd12:3456:789a::1]", expected: true, desc: "[fd12:3456:789a::1] ULA" },
    { url: "http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]", expected: true, desc: "fdff:... ULA end" },

    // IPv6 Link-Local (fe80::/10)
    { url: "http://[fe80::1]", expected: true, desc: "[fe80::1] link-local IPv6" },
    { url: "http://[febf::1]", expected: true, desc: "[febf::1] end of fe80::/10" },
    { url: "http://[fec0::1]", expected: false, desc: "[fec0::1] OUTSIDE fe80::/10" },

    // Public domains (MUST return false)
    { url: "https://example.com", expected: false, desc: "example.com public" },
    { url: "https://google.com", expected: false, desc: "google.com public" },
    { url: "https://www.facebook.com/login", expected: false, desc: "facebook.com public" },
    { url: "https://anti-phishing-api.onrender.com/analyze", expected: false, desc: "Render backend public" },

    // Public IPs (MUST return false)
    { url: "http://8.8.8.8", expected: false, desc: "8.8.8.8 Google DNS public" },
    { url: "http://203.0.113.1", expected: false, desc: "203.0.113.1 public IP" },
    { url: "http://1.1.1.1", expected: false, desc: "1.1.1.1 Cloudflare public" },

    // Malformed URLs
    { url: "not-a-url", expected: false, desc: "not-a-url malformed" },
    { url: "", expected: false, desc: "empty string malformed" },
    { url: "ftp://192.168.1.1", expected: true, desc: "ftp://192.168.1.1 non-HTTP private" },

    // URLs with full features
    { url: "http://10.0.0.1:8443/captive?redirect=http://google.com", expected: true, desc: "Private IP+port+query" },
    { url: "https://192.168.1.1:443/admin/login?user=test", expected: true, desc: "Private HTTPS+path+query" },

    // Edge cases
    { url: "http://10.local", expected: true, desc: "10.local — .local suffix" },
    { url: "http://192.168.1.1.evil.com", expected: false, desc: "192.168.1.1.evil.com NOT local" },
    { url: "http://localhost.evil.com", expected: false, desc: "localhost.evil.com NOT local" },
];

// ========================================
// Run
// ========================================
let passed = 0;
let failed = 0;

console.log("═══════════════════════════════════════════════════════");
console.log("  isLocalNetworkUrl() — Test Suite");
console.log("═══════════════════════════════════════════════════════\n");

for (const test of tests) {
    const result = isLocalNetworkUrl(test.url);
    const ok = result === test.expected;
    if (ok) {
        passed++;
        console.log(`  ✅ PASS  ${test.desc}`);
    } else {
        failed++;
        console.log(`  ❌ FAIL  ${test.desc}  (got ${result}, expected ${test.expected})`);
    }
}

console.log("\n═══════════════════════════════════════════════════════");
console.log(`  Results: ${passed}/${passed + failed} passed${failed > 0 ? ` — ${failed} FAILED` : ' — ALL PASSED ✅'}`);
console.log("═══════════════════════════════════════════════════════\n");

process.exit(failed > 0 ? 1 : 0);

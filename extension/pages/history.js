document.addEventListener('DOMContentLoaded', () => {
    let fullHistory = [];
    let currentFilter = 'all';

    // Load history from storage
    chrome.storage.local.get({ scanHistory: [], totalScans: 0 }, (items) => {
        fullHistory = items.scanHistory;

        // Update stats
        document.getElementById('total-count').textContent = items.totalScans;

        const safeCount = fullHistory.filter(h => h.status === 'safe').length;
        const threatCount = fullHistory.filter(h => h.status === 'phishing' || h.status === 'suspicious').length;

        document.getElementById('safe-count').textContent = safeCount;
        document.getElementById('threat-count').textContent = threatCount;

        renderHistory(fullHistory);
    });

    // Clear Button
    document.getElementById('clear-btn').addEventListener('click', () => {
        if(confirm("Are you sure you want to clear your scan history?")) {
            chrome.storage.local.set({ scanHistory: [] }, () => {
                fullHistory = [];
                renderHistory([]);
                document.getElementById('safe-count').textContent = '0';
                document.getElementById('threat-count').textContent = '0';
            });
        }
    });

    // Search Input
    document.getElementById('search-input').addEventListener('input', (e) => {
        applyFilters(e.target.value.toLowerCase(), currentFilter);
    });

    // Filter Tabs
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            // Update active class
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');

            currentFilter = e.target.dataset.filter;
            const searchQuery = document.getElementById('search-input').value.toLowerCase();

            applyFilters(searchQuery, currentFilter);
        });
    });

    function applyFilters(query, filter) {
        let filtered = fullHistory;

        // Apply text search
        if (query) {
            filtered = filtered.filter(item =>
                String(item.url || '').toLowerCase().includes(query) ||
                String(item.reason || '').toLowerCase().includes(query)
            );
        }

        // Apply status filter
        if (filter !== 'all') {
            filtered = filtered.filter(item => item.status === filter);
        }

        renderHistory(filtered);
    }

    function renderHistory(items) {
        const list = document.getElementById('history-list');
        const emptyState = document.getElementById('empty-state');

        list.innerHTML = '';

        if (items.length === 0) {
            list.style.display = 'none';
            emptyState.style.display = 'block';
            return;
        }

        list.style.display = 'flex';
        emptyState.style.display = 'none';

        items.forEach(item => {
            const timeAgo = getTimeAgo(item.timestamp);

            let icon = '';
            let badgeClass = '';
            let confidenceClass = '';

            if (item.status === 'phishing') {
                icon = '🚨';
                badgeClass = 'badge-phishing';
                confidenceClass = 'confidence-phishing';
            } else if (item.status === 'suspicious') {
                icon = '⚠️';
                badgeClass = 'badge-suspicious';
                confidenceClass = 'confidence-suspicious';
            } else if (item.status === 'safe' || item.status === 'previously_checked') {
                icon = '✅';
                badgeClass = 'badge-safe';
                confidenceClass = 'confidence-safe';
            } else {
                icon = 'ℹ️';
                badgeClass = 'badge-unverified';
                confidenceClass = 'confidence-unverified';
            }

            const div = document.createElement('div');
            div.className = 'history-item';

            const badge = document.createElement('div');
            badge.className = `status-badge ${badgeClass}`;
            badge.textContent = icon;

            const info = document.createElement('div');
            info.className = 'item-info';
            const domain = document.createElement('div');
            domain.className = 'item-domain';
            domain.title = String(item.fullUrl || '');
            domain.textContent = String(item.url || 'Unknown URL');
            const reason = document.createElement('div');
            reason.className = 'item-reason';
            const fallbackReason = item.status === 'safe' || item.status === 'previously_checked'
                ? 'No threat detected'
                : item.status === 'phishing'
                ? 'Phishing indicators detected'
                : item.status === 'suspicious'
                ? 'Suspicious indicators detected'
                : item.status === 'unable_to_verify'
                ? 'Unable to verify — scan incomplete'
                : 'Not scanned';
            reason.textContent = String(item.reason || fallbackReason);
            info.append(domain, reason);

            const meta = document.createElement('div');
            meta.className = 'item-meta';
            const confidence = document.createElement('div');
            confidence.className = `item-confidence ${confidenceClass}`;
            const confidenceValue = Number(item.confidence);
            confidence.textContent = Number.isFinite(confidenceValue) ? `${confidenceValue}%` : '—';
            const time = document.createElement('div');
            time.className = 'item-time';
            time.textContent = timeAgo;
            meta.append(confidence, time);

            div.append(badge, info, meta);
            list.appendChild(div);
        });
    }

    function getTimeAgo(timestamp) {
        const seconds = Math.floor((new Date() - timestamp) / 1000);

        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " years ago";

        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " months ago";

        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " days ago";

        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hours ago";

        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " mins ago";

        if (seconds < 10) return "just now";
        return Math.floor(seconds) + " secs ago";
    }
});

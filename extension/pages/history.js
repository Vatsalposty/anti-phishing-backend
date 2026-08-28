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
                item.url.toLowerCase().includes(query) || 
                (item.reason && item.reason.toLowerCase().includes(query))
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
            } else {
                icon = '✅';
                badgeClass = 'badge-safe';
                confidenceClass = 'confidence-safe';
            }

            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
                <div class="status-badge ${badgeClass}">${icon}</div>
                <div class="item-info">
                    <div class="item-domain" title="${item.fullUrl}">${item.url}</div>
                    <div class="item-reason">${item.reason || (item.status === 'safe' ? 'Verified Safe' : 'Detected')}</div>
                </div>
                <div class="item-meta">
                    <div class="item-confidence ${confidenceClass}">${item.confidence}%</div>
                    <div class="item-time">${timeAgo}</div>
                </div>
            `;
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

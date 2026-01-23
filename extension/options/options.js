document.addEventListener('DOMContentLoaded', restoreOptions);
document.getElementById('toggle-protection').addEventListener('change', saveOptions);
document.getElementById('add-btn').addEventListener('click', addWhitelistItem);

// Default settings
const DEFAULT_WHITELIST = ['google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'amazon.com'];

function saveOptions() {
    const protectionEnabled = document.getElementById('toggle-protection').checked;

    chrome.storage.sync.set({
        protectionEnabled: protectionEnabled
    }, () => {
        showToast();
        // Notify background script to update state
        chrome.runtime.sendMessage({ action: "settings_updated" });
    });
}

function restoreOptions() {
    chrome.storage.sync.get({
        protectionEnabled: true,
        whitelist: DEFAULT_WHITELIST
    }, (items) => {
        document.getElementById('toggle-protection').checked = items.protectionEnabled;
        renderWhitelist(items.whitelist);
    });
}

function addWhitelistItem() {
    const input = document.getElementById('whitelist-input');
    const domain = input.value.trim().toLowerCase();

    if (!domain) return;

    chrome.storage.sync.get({ whitelist: DEFAULT_WHITELIST }, (items) => {
        const whitelist = items.whitelist;
        if (!whitelist.includes(domain)) {
            whitelist.push(domain);
            chrome.storage.sync.set({ whitelist: whitelist }, () => {
                restoreOptions(); // Re-render
                input.value = '';
                showToast();
            });
        }
    });
}

function removeWhitelistItem(domain) {
    chrome.storage.sync.get({ whitelist: DEFAULT_WHITELIST }, (items) => {
        const whitelist = items.whitelist.filter(item => item !== domain);
        chrome.storage.sync.set({ whitelist: whitelist }, () => {
            restoreOptions();
            showToast();
        });
    });
}

function renderWhitelist(whitelist) {
    const list = document.getElementById('whitelist-list');
    list.innerHTML = '';

    whitelist.forEach(domain => {
        const li = document.createElement('li');
        li.className = 'whitelist-item';

        const span = document.createElement('span');
        span.textContent = domain;

        const btn = document.createElement('button');
        btn.innerHTML = '&times;';
        btn.className = 'delete-btn';
        btn.onclick = () => removeWhitelistItem(domain);

        li.appendChild(span);
        li.appendChild(btn);
        list.appendChild(li);
    });
}

function showToast() {
    const toast = document.getElementById('toast');
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2000);
}

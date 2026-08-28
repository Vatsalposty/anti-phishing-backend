# Chrome Web Store Metadata
This file contains everything you need to copy/paste into the Chrome Developer Dashboard when publishing the **Anti-Phishing AI Guard v2.1.0**.

## 1. Store Listing (English)

**Name:** Anti-Phishing AI Guard
**Short Name:** Anti-Phishing Guard
**Summary:** (Max 132 chars)
Real-time AI-powered protection that automatically detects and blocks phishing sites, scams, and malicious URLs before they load.

**Detailed Description:**
Anti-Phishing AI Guard is your premium defense against the ever-evolving landscape of online scams, phishing attempts, and malicious websites. Traditional antiviruses rely on outdated blacklists. Our guard uses a cutting-edge 12-layer AI detection pipeline to proactively analyze websites in real-time, catching threats before they are even reported to the public.

**Key Features:**
🛡️ **Real-Time AI Scanning:** Analyzes URLs using advanced machine learning, heuristics, and homoglyph detection (e.g., detecting fake domains like `lnstagram.com`).
⚡ **Zero-Day Protection:** Our AI backend (XGBoost) actively evaluates page characteristics, ensuring protection even against newly created scam sites.
📊 **Scan History & Trust Scores:** Keep track of every site you visit with detailed trust percentages and a beautiful, transparent history dashboard.
🔔 **Instant Notifications:** Get immediate system alerts the moment a malicious page is detected, automatically blocking access to protect your data.
🕵️ **Privacy First:** We only scan URLs for security. We do not track your browsing history or sell your data.
🚨 **Report Suspicious Sites:** Help the community by instantly reporting dangerous sites to our global database with one click.

Browse with absolute confidence, knowing our AI is analyzing every link to keep your passwords, identity, and finances secure.

---

## 2. Privacy practices

**Single purpose description:**
The single purpose of this extension is to protect users from phishing and malicious websites by analyzing the URLs they visit in real-time using an AI-powered detection backend.

**Permissions Justification:**
The extension requests the following permissions, all of which are strictly necessary for the core security function:

*   **`tabs`**: Required to read the URL of the currently active tab so it can be securely sent to our backend AI model for threat analysis.
*   **`storage`**: Required to save the user's scan history, total blocked counts, and application settings locally on their device.
*   **`notifications`**: Required to instantly alert the user with a system notification when a critical phishing threat is detected and blocked.
*   **`activeTab`**: Used to safely interact with the current page when the user clicks the extension popup, without requiring broad access until requested.
*   **Host Permissions (`http://*/*`, `https://*/*`)**: Strictly necessary to inject the blocking script (content.js) into any website the user visits. Without this, the extension cannot physically intercept and block a phishing page before it steals user data.

**Data Usage:**
*   **Does this extension collect or use your data?** Yes.
*   **What data?** Website content (URLs visited).
*   **Why?** The URLs are sent securely to our API for real-time AI analysis. The URLs are not tied to user identities and are not stored permanently unless explicitly reported by the user as malicious.
*   **Do you sell this data?** No.
*   **Do you use it for unrelated purposes?** No.

---

## 3. Preparation Checklist
Before clicking Submit for Review, ensure you have:
- [ ] A 128x128 pixel icon file.
- [ ] A 1280x800 Promotional Marquee image.
- [ ] At least 1-2 screenshots of the popup and history page in action.
- [ ] A published URL for the Privacy Policy (Use the `PRIVACY_POLICY.md` file provided).
- [ ] Zipped the extension folder (do NOT include the `backend/` folder or `.git/` folder in the ZIP).

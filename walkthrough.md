# Anti-Phishing Extension - Walkthrough

This document outlines the completed Anti-Phishing Browser Extension, how to run it, and the results of our verification.

## 1. Features Implemented

### Frontend (Chrome Extension)
- [x] **Real-time Analysis**: Automatically checks every visited URL against the backend.
- [x] **Premium UI**: Dark mode, glassmorphism design, and animated status indicators.
- [x] **Active Alerts**: **Blocks phishing sites** with a full-screen red warning overlay preventing accidental access.
- [x] **Status Reporting**: 
  - 🟢 **Safe**: Verified domains (e.g., Google) or low-risk URLs.
  - 🟠 **Suspicious**: High-risk characteristics (length, keywords) or partially matched heuristics.
  - 🔴 **Phishing**: Known bad domains or IP-based URLs.
  - ⚫ **Backend Offline**: Graceful error handling when the server is down.

### Backend (Python/FastAPI)
- [x] **API Endpoint**: `POST /analyze` receiving URLs.
- [x] **Heuristic Engine**:
  - **Allowlist**: Trusted domains (Google, Facebook, etc.) bypass checks.
  - **Blacklist**: Blocks known bad domains immediately.
  - **Keyword Analysis**: flags "login", "bank", etc., in weird domains.
  - **IP Check**: Flags raw IP access.
- [x] **Firebase Integration**: Logs attempts to Firestore (or mocks if no credentials).

## 2. Setup & Usage

### Step 1: Start Backend
The backend must be running for the extension to work.
1. Run the setup script:
   ```cmd
   e:\anti_phishing_extension\setup_backend.bat
   ```
2. Wait for the success message: `Uvicorn running on http://127.0.0.1:8000`.

### Step 2: Load Extension
1. Open Chrome/Brave.
2. Go to `chrome://extensions`.
3. Enable **Developer Mode**.
4. Click **Load Unpacked**.
5. Select `e:\anti_phishing_extension\extension`.

## 3. Verification Scenarios

### Scenario A: Safe Website (Google)
- **Action**: Visit `https://www.google.com/search?q=hello`
- **Result**: 
  - **Icon Badge** shows Green Shield / "OK".
  - **Popup** (only if clicked) shows **Safe Website**.
  - No overlay blocking the content.
  - Trust Score: **98%**.

### Scenario B: Phishing Simulation
- **Action**: Visit `http://evil.com/login` (Mocked malicious URL).
- **Result**:
  - **Active Alert**: Red full-screen overlay blocks the page immediately.
  - **Blocking**: User inputs (typing, clicking forms) are fully disabled.
  - Message: "PHISHING DETECTED".
  - Icon Badge turns Red `!`.

### Scenario C: Backend Offline
- **Action**: Close the terminal window running uvicorn. Click extension.
- **Result**:
  - Popup shows **Backend Offline**.
  - Prevents "Analyzing..." hang.

### Scenario D: System Logging
- **Action**: Restart the backend server.
- **Result**: `[MOCK-FIREBASE] System Event: startup` logged in the terminal (or Firestore).

## 4. Troubleshooting
- **Failed to Fetch**: Ensure verifying using `127.0.0.1` instead of `localhost` in `background.js` (Fixed).
- **Python Path Error**: Ensure `setup_backend.bat` is run (Fixed pathing issues).

The project is fully functional and verified.

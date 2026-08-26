# 🛡️ Anti-Phishing AI Guard

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.12-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg) ![XGBoost](https://img.shields.io/badge/XGBoost-2.1.3-orange.svg) ![Extension](https://img.shields.io/badge/Chrome-Extension-orange.svg)

**Anti-Phishing AI Guard** is an industry-grade, real-time browser extension that protects users from malicious websites. By combining a global verified database (PhishTank) with a custom XGBoost Machine Learning model trained on massive real-world datasets, it detects both known threats and zero-day phishing attacks that traditional blacklists miss.

## 🚀 Features

*   **Real-Time Scanning**: Intercepts and analyzes URLs instantly before the page fully renders.
*   **AI-Powered Detection (XGBoost)**: Analyzes URL structure (length, entropy, TLD, special chars) and HTML content heuristics to predict malicious intent.
*   **PhishTank Integration**: Queries verified global phishing databases for 100% accuracy on known threats.
*   **Visual Protection**: 
    *   ✅ **Safe**: Verified shield.
    *   ❌ **Phishing Alert**: Red warning badge and a full-screen **Blocking Overlay** to prevent interaction.
*   **User Reporting**: One-click reporting mechanism to flag suspicious sites for manual review.
*   **Cloud Backend**: Powered by a robust Python FastAPI server with structured logging and rate-limiting.
*   **Telemetry**: Securely logs telemetry and system events to Firebase Firestore.

## 🛠️ Security Architecture

The system follows a privacy-preserving, 3-layer security model:

1.  **Extension Layer (Client)**
    *   **Allowlist Check**: `background.js` verifies the domain against the user's local safe list.
    *   **API Relay**: If unknown, the URL is sent to the secure backend via HTTPS.
    
2.  **Detection Engine (Backend)**
    *   **Layer 1 - PhishTank**: Checked against a verified phishing database.
    *   **Layer 2 - Machine Learning**: XGBoost classifier analyzes extracted URL features and live HTML form behaviors.
    *   **Layer 3 - Heuristics**: Fallback pattern matching for highly suspicious keywords (e.g., `secure-login-update`).

3.  **Action Layer**
    *   The backend returns a threat score (`safe`, `suspicious`, `phishing`).
    *   The extension visually updates and injects `content.js` to block the DOM if deemed dangerous.

### Tech Stack
*   **Frontend**: Chrome Extension (Manifest V3), JavaScript, HTML/CSS.
*   **Backend**: Python (FastAPI), Uvicorn.
*   **AI Engine**: XGBoost, Scikit-Learn (trained on 10,000+ real-world URLs).
*   **Database**: Google Firebase (Firestore) for logging and reporting.
*   **Hosting**: Render (Web Service).

## 📦 Installation (Chrome Extension)

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/Vatsalposty/anti-phishing-backend.git
    cd anti-phishing-backend
    ```

2.  **Load the Extension**:
    *   Open `chrome://extensions` in Google Chrome.
    *   Enable **Developer Mode** (top right).
    *   Click **Load Unpacked**.
    *   Select the `extension` folder from this repository.

3.  **Start Browsing**:
    *   The extension defaults to the production cloud backend.
    *   You can toggle Developer Mode in the extension settings to use `localhost:8000`.

## 🔧 Backend Setup (Local Development)

To run the ML backend locally:

1.  **Environment Setup**:
    ```bash
    cd backend
    python -m venv .venv
    
    # Windows
    .venv\Scripts\activate
    # macOS/Linux
    source .venv/bin/activate
    
    pip install -r requirements.txt
    ```

2.  **Environment Variables (`.env`)**:
    Create a `.env` file in the `backend/` directory:
    ```env
    PRODUCTION_MODE=false
    # Optional: FIREBASE_CREDENTIALS={"type": "service_account"...}
    ```
    *Note: For local development, you can place a `serviceAccountKey.json` file in the `backend/` folder instead of using the environment variable.*

3.  **Run Server**:
    ```bash
    uvicorn main:app --reload
    ```
    The API will be available at `http://127.0.0.1:8000`.

## 📈 Model Training

To retrain the XGBoost model on new data:

```bash
cd backend
python train_massive.py
python train_xgboost.py
```
This extracts features from the datasets and generates a new `xgboost_model.json`.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 Privacy & Security
- **No Credentials in Source**: This repository does not contain active API keys or service accounts.
- **Data Privacy**: The extension only transmits the URL to the backend for analysis. No cookies, session tokens, or personal browsing history are logged.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

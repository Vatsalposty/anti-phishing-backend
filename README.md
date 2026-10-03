# 🛡️ Anti-Phishing AI Guard

![Python](https://img.shields.io/badge/python-3.12-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg) ![XGBoost](https://img.shields.io/badge/XGBoost-2.1.3-orange.svg) ![Extension](https://img.shields.io/badge/Chrome-Extension-orange.svg)

**Anti-Phishing AI Guard** is an experimental browser extension and backend that checks URLs using a PhishTank lookup, URL heuristics, and a legacy XGBoost model. It is not a guarantee that a site is safe or malicious. A failed scan is reported as **Unable to verify**, not as a threat verdict.

## 🚀 Features

*   **Pre-navigation scanning**: Intercepts HTTP and HTTPS navigations and asks the configured backend to analyze the URL.
*   **Layered checks**: Uses URL heuristics, an XGBoost model, a limited server-side HTML fetch, and a PhishTank lookup.
*   **Honest scan states**: Shows a separate warning when a site could not be checked; inability to fetch is not treated as proof of phishing or safety.
*   **Navigation warning**: Presents a warning page for phishing or suspicious verdicts and asks before proceeding past uncertain results.
*   **User Reporting**: One-click reporting mechanism to flag suspicious sites for manual review.
*   **Cloud Backend**: Powered by a robust Python FastAPI server with structured logging and rate-limiting.
*   **Storage**: Keeps recent scan history locally and stores phishing/suspicious detections and user reports in Firebase when configured.

## 🛠️ Security Architecture

The current implementation works as follows:

1.  **Extension Layer (Client)**
    *   **Allowlist Check**: `background.js` verifies the domain against the user's local safe list.
    *   **API Relay**: If not bypassed or previously checked, the full URL is sent to the configured backend. Local scan history stores the full URL on-device.
    
2.  **Detection Engine (Backend)**
    *   **PhishTank**: The backend submits the URL to PhishTank for a lookup.
    *   **HTML checks**: The backend makes a separate limited HTTP(S) request to the destination (without browser cookies or JavaScript) and checks selected page features.
    *   **Model and heuristics**: The backend combines a legacy XGBoost model with URL/domain rules. These checks have not established a production accuracy guarantee.

3.  **Action Layer**
    *   The backend returns `safe`, `suspicious`, `phishing`, or `unable_to_verify`.
    *   The extension uses a pre-navigation interstitial; `content.js` is currently passive and does not block a page DOM.

### Tech Stack
*   **Frontend**: Chrome Extension (Manifest V3), JavaScript, HTML/CSS.
*   **Backend**: Python (FastAPI), Uvicorn.
*   **Model**: XGBoost and Scikit-Learn; experimental candidate models are not the active production model.
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

Legacy training scripts remain in `backend/`. They are research code and should not be used to replace the active model without a separately validated dataset and evaluation.

Do not train or replace the active model using these scripts without auditing their inputs and producing a fresh, domain-disjoint evaluation.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 Privacy & Security
- **No Credentials in Source**: This repository does not contain active API keys or service accounts.
- **Data Flow**: The extension sends the full URL to the configured backend. The backend also submits it to PhishTank and makes a limited request to the destination site. URLs with phishing/suspicious results and user reports may be stored in Firebase with query strings and fragments removed; paths can still contain sensitive information. Recent scan history, including full URLs, is stored locally in the browser.

## 📜 License

No `LICENSE` file is currently included. Do not assume a license until one is added by the project owner.

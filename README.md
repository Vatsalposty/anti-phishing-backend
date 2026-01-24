# 🛡️ Anti-Phishing AI Guard

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-0.68+-green.svg) ![Extension](https://img.shields.io/badge/Chrome-Extension-orange.svg)

**Anti-Phishing AI Guard** is a real-time browser extension that protects users from malicious websites using advanced machine learning and heuristic analysis. It detects zero-day phishing attacks that traditional blacklists miss.

## 🚀 Features

*   **Real-Time Scanning**: Analyzes every URL you visit instantly.
*   **AI-Powered Detection**: Uses a Random Forest classifier trained on thousands of phishing URLs to detect suspicious patterns.
*   **Heuristic Fallback**: Instantly blocks known bad keywords and IP-based URLs.
*   **Visual Protection**: Displays a verified "Safe" shield or a "Phishing Alert" warning.
*   **User Reporting**: One-click reporting mechanism to flag suspicious sites for review.
*   **Cloud Backend**: Powered by a robust Python FastAPI server hosted on Render.

## 🛠️ Architecture

*   **Frontend**: Chrome Extension (Manifest V3), JavaScript, HTML/CSS.
*   **Backend**: Python (FastAPI), Uvicorn.
*   **AI Model**: Scikit-Learn (Random Forest) serialized with Joblib.
*   **Database**: Google Firebase (Firestore) for logging attacks and user reports.

## 📦 Installation

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
    *   The extension is pre-configured to use the cloud backend.
    *   Visit any website to see the protection status!

## 🔧 Local Development (Optional)

If you want to run the backend locally:

1.  **Install Dependencies**:
    ```bash
    cd backend
    pip install -r requirements.txt
    ```

2.  **Run Server**:
    ```bash
    uvicorn main:app --reload
    ```

3.  **Update Extension**: Change `API_URL` in `extension/background.js` to `http://127.0.0.1:8000`.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

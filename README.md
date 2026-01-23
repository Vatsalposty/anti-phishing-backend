# Anti-Phishing Browser Extension (AI-Powered)

## Project Overview
This project contains a Chrome Extension and a Python Backend to detect phishing websites in real-time.

## Structure
- `/extension`: Contains the Chrome Extension source code.
- `/backend`: Contains the Python FastAPI server and ML logic.

## Setup Instructions

### 1. Backend Setup
1. Open a terminal in `e:\anti_phishing_extension\backend`.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server:
   ```bash
   uvicorn main:app --reload
   ```
   The API will be available at `http://localhost:8000`.

### 2. Extension Setup
1. Open Google Chrome.
2. Go to `chrome://extensions`.
3. Enable **Developer Mode** (toggle in top right).
4. Click **Load unpacked**.
5. Select the `e:\anti_phishing_extension\extension` folder.
6. The extension icon should appear in your toolbar.

### 3. Usage
- Browse the web. The extension icon will automatically change:
  - 🟢 **Green Shield**: Safe Website
  - 🟠 **Yellow/Red Shield**: Suspicious/Phishing Website
- Click the extension icon to see detailed status.

## Configuration
- **Firebase**: To enable real logging, place your `serviceAccountKey.json` from Firebase Console into the `backend/` folder. Default is Mock Mode.

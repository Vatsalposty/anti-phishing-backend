# Firebase Setup Guide

Follow these steps to generate the required credentials for the Anti-Phishing Extension.

## 1. Create Project
1.  Go to the [Firebase Console](https://console.firebase.google.com/).
2.  Click **"Create a project"**.
3.  **Project Name**: Enter `Anti-Phishing-Guard` (or similar if taken).
4.  Accept terms and click **Continue**.
5.  (Optional) Disable Google Analytics for this project (simpler setup).
6.  Click **Create project**.
7.  Wait for it to be ready and click **Continue**.

## 2. Setup Firestore Database
1.  In the left sidebar, click **Build** -> **Firestore Database**.
2.  Click **Create database**.
3.  **Location**: Choose a location near you (e.g., `nam5 (us-central)`).
4.  **Security Rules**: Select **Start in test mode** (allows read/write for 30 days - easiest for development).
5.  Click **Create**.

## 3. Generate Service Key
1.  Click the **Project Overview** (gear icon) ⚙️ at the top left -> **Project settings**.
2.  Go to the **Service accounts** tab.
3.  Under "Firebase Admin SDK", ensure **Python** is selected.
4.  Click **Generate new private key**.
5.  Click **Generate key** to download the JSON file.

## 4. Install Key
1.  Rename the downloaded file to: `serviceAccountKey.json`.
2.  Move this file into your backend folder:
    `e:\anti_phishing_extension\backend\serviceAccountKey.json`

## 5. Verify Connection
1.  Open your terminal in `e:\anti_phishing_extension`.
2.  Run the test script:
    ```cmd
    backend\venv\Scripts\python backend\test_firebase.py
    ```
3.  If successful, you will see: `[SUCCESS] Connected to Firebase Project: anti-phishing-guard`.

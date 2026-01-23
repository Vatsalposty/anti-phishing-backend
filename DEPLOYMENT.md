# Deploying to Render

Follow these steps to deploy your Anti-Phishing Backend to the cloud (Render.com) for free.

## 1. Prepare Code (GitHub)
Render deploys directly from GitHub.
1.  **Create a Repository**: Go to GitHub and create a new public/private repository (e.g., `anti-phishing-backend`).
2.  **Push Code**: Upload your `backend/` folder contents to this repository.
    *   *Note: Ensure `serviceAccountKey.json` and `venv` are NOT uploaded (use .gitignore).*

## 2. Create Service on Render
1.  Sign up/Log in to [Render.com](https://render.com/).
2.  Click **New +** -> **Web Service**.
3.  **Connect GitHub**: Select your `anti-phishing-backend` repository.
4.  **Settings**:
    *   **Name**: `anti-phishing-api` (or unique name).
    *   **Runtime**: `Python 3`.
    *   **Build Command**: `pip install -r requirements.txt` (Default).
    *   **Start Command**: `uvicorn main:app --host 0.0.0.0 --port 10000`.
    *   **Instance Type**: `Free`.

## 3. Configure Environment Variables
This is the most critical step to connect Firebase securely.
1.  Scroll down to the **Environment Variables** section.
2.  Add a new variable:
    *   **Key**: `FIREBASE_CREDENTIALS`
    *   **Value**: *[Open your `serviceAccountKey.json` file, copy the ENTIRE content, and paste it here as a single line]*
3.  Click **Create Web Service**.

## 4. Verification
1.  Render will start building your app. Watch the logs.
2.  Once deployed, you will see a URL like `https://anti-phishing-api.onrender.com`.
3.  **Update Extension**:
    *   Open `extension/background.js`.
    *   Change `API_URL` from `http://127.0.0.1:8000/analyze` to your new Render URL + `/analyze`.
    *   Reload the extension.

## 5. Troubleshooting
*   **Logs**: Check the "Logs" tab in Render for any Python errors.
*   **Database**: Check Firebase Console to see if new data is appearing.

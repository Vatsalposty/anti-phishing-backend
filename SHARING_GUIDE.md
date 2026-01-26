# 📤 How to Share and Install the Extension

Since the extension is not on the Chrome Web Store yet, you can share it manually using the "ZIP Method".

## 📦 How to Prepare for Sharing (On Your PC)

1.  Open your project folder (`e:\anti_phishing_extension`).
2.  Right-click the `extension` folder.
3.  Select **Compress to ZIP file** (or "Send to -> Compressed (zipped) folder").
4.  You will get a file named `extension.zip`. 
5.  **This ZIP file is what you share** with your teacher or friends!

---

## 💻 How to Install on ANOTHER PC (The Recipient)

If you send the ZIP file to someone else, they must follow these steps:

### 1. Extract the Files
*   Download the `extension.zip`.
*   Right-click it and select **Extract All**. 
*   Now you have a normal folder named `extension`.

### 2. Open Chrome Extensions
*   Open Google Chrome (or Brave/Edge).
*   In the address bar, type `chrome://extensions/` and press Enter.

### 3. Enable Developer Mode
*   In the top right corner, switch the **Developer mode** toggle to **ON**.

### 4. Load the Extension
*   Click the **Load unpacked** button that appeared in the top left.
*   Navigate to the folder you extracted in Step 1.
*   **Select the `extension` folder** and click "Select Folder".

### 💡 Why it works immediately:
Because we deployed your backend to the **Cloud (Render)**, the extension on the other PC will automatically connect to your internet server. They don't need to install Python or anything else!

---

## 🧪 Testing on the new PC
1.  Click the Puzzle icon 🧩 in Chrome and "Pin" the **Anti-Phishing AI Guard**.
2.  Visit `https://www.google.com` -> Should show **Green/Safe**.
3.  Visit `http://testsafebrowsing.appspot.com/s/phishing.html` -> Should show **Red/Phishing**.

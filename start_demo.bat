@echo off
echo Starting Anti-Phishing Demo Server...
echo.
echo 1. Keep this window OPEN.
echo 2. Open Google Chrome.
echo 3. Visit: http://localhost:8080/secure-account-login-verify-update.html
echo.
python -m http.server 8080
pause

@echo off
title Anti-Phishing AI Guard - Local Backend (Port 8000)
color 0A

echo(
echo  ===========================================================
echo     Anti-Phishing AI Guard - Local Backend Launcher
echo  ===========================================================
echo(

:: ---------------------------------------------------------------
:: 1. Activate the root virtual environment
:: ---------------------------------------------------------------
echo  [INFO] Activating virtual environment...
call "%~dp0.venv\Scripts\activate.bat"
if %errorlevel% neq 0 (
    echo  [ERROR] Failed to activate .venv in the project root!
    pause
    exit /b 1
)
echo  [OK] Virtual environment activated

:: ---------------------------------------------------------------
:: 2. Navigate to backend and start server
:: ---------------------------------------------------------------
cd /d "%~dp0backend"
if not exist "main.py" (
    echo  [ERROR] Could not find "main.py" in: %cd%
    pause
    exit /b 1
)

echo(
echo  ===========================================================
echo    Backend is starting on: http://127.0.0.1:8000
echo    API docs available at:  http://127.0.0.1:8000/docs
echo  ===========================================================
echo(
echo  Press Ctrl+C to stop the server.
echo(

python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

echo(
echo  ===========================================================
echo    Server has stopped.
echo  ===========================================================
echo(
pause

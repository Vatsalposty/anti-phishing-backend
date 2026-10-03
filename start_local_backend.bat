@echo off
title Anti-Phishing AI Guard - Local Backend (Port 8000)
color 0A

echo(
echo  ===========================================================
echo     Anti-Phishing AI Guard - Local Backend Launcher
echo  ===========================================================
echo(

set "PYTHON_CMD=python"
if exist "%~dp0backend\venv\Scripts\python.exe" set "PYTHON_CMD=%~dp0backend\venv\Scripts\python.exe"
if exist "%~dp0backend\.venv\Scripts\python.exe" set "PYTHON_CMD=%~dp0backend\.venv\Scripts\python.exe"

echo  [INFO] Checking Python environment: %PYTHON_CMD%
"%PYTHON_CMD%" -c "import uvicorn, fastapi, xgboost" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Backend dependencies are missing from this Python environment.
    echo  [INFO] Create backend\.venv and install backend\requirements.txt, or install dependencies into Python on PATH.
    pause
    exit /b 1
)
echo  [OK] Dependencies verified.

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

"%PYTHON_CMD%" -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

echo(
echo  ===========================================================
echo    Server has stopped.
echo  ===========================================================
echo(
pause

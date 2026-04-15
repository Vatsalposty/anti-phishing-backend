@echo off
title Anti-Phishing AI Guard - Local Backend (Port 8000)
color 0A

echo(
echo  ===========================================================
echo     Anti-Phishing AI Guard - Local Backend Launcher
echo  ===========================================================
echo(

:: ---------------------------------------------------------------
:: 1. Navigate to the backend folder
:: ---------------------------------------------------------------
cd /d "%~dp0backend"
if not exist "main.py" goto :no_main

echo  [OK] Backend folder found: %cd%
goto :check_python

:no_main
echo  [ERROR] Could not find "main.py" in: %cd%
echo  Make sure this .bat file is in the project root folder.
echo(
pause
exit /b 1

:: ---------------------------------------------------------------
:: 2. Check for Python installation
:: ---------------------------------------------------------------
:check_python
where python >nul 2>&1
if %errorlevel% neq 0 goto :no_python

echo  [OK] Python found
goto :check_venv

:no_python
echo(
echo  [ERROR] Python is not installed or not in PATH!
echo  Download Python from https://www.python.org/downloads/
echo  Make sure to check "Add Python to PATH" during install.
echo(
pause
exit /b 1

:: ---------------------------------------------------------------
:: 3. Create virtual environment if it doesn't exist
:: ---------------------------------------------------------------
:check_venv
if exist "venv\Scripts\activate.bat" goto :activate_venv

echo  [INFO] Virtual environment not found. Creating one...
python -m venv venv
if %errorlevel% neq 0 goto :venv_fail

echo  [OK] Virtual environment created
goto :activate_venv

:venv_fail
echo  [ERROR] Failed to create virtual environment!
pause
exit /b 1

:: ---------------------------------------------------------------
:: 4. Activate virtual environment
:: ---------------------------------------------------------------
:activate_venv
echo  [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
echo  [OK] Virtual environment activated

:: ---------------------------------------------------------------
:: 5. Install / update dependencies
:: ---------------------------------------------------------------
echo  [INFO] Checking dependencies (pip install)...
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 goto :pip_retry
goto :pip_done

:pip_retry
echo  [WARNING] Retrying dependency install with verbose output...
pip install -r requirements.txt
if %errorlevel% neq 0 goto :pip_fail
goto :pip_done

:pip_fail
echo  [ERROR] Dependency installation failed! Check errors above.
pause
exit /b 1

:pip_done
echo  [OK] All dependencies installed

:: ---------------------------------------------------------------
:: 6. Start the FastAPI server
:: ---------------------------------------------------------------
echo(
echo  ===========================================================
echo    Backend is starting on: http://127.0.0.1:8000
echo    API docs available at:  http://127.0.0.1:8000/docs
echo  ===========================================================
echo(
echo  Press Ctrl+C to stop the server.
echo(

python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

:: ---------------------------------------------------------------
:: If we get here, the server stopped
:: ---------------------------------------------------------------
echo(
echo  ===========================================================
echo    Server has stopped.
echo  ===========================================================
echo(
pause

@echo off
echo Setting up Anti-Phishing Backend...

cd /d "%~dp0backend"
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate

echo Installing dependencies...
pip install -r requirements.txt

echo Starting Server...
uvicorn main:app --reload

pause

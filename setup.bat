@echo off
cd /d "%~dp0"
echo ==========================================
echo Setting up CyberShield AI Environment
echo ==========================================

echo 1. Creating virtual environment...
python -m venv venv

echo 2. Activating virtual environment...
call venv\Scripts\activate.bat

echo 3. Installing dependencies...
pip install -r requirements.txt

echo ==========================================
echo Setup Complete! You can now run start_all.bat
echo ==========================================
pause
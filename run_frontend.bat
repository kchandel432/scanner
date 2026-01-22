@echo off
cd /d "%~dp0"
echo Starting CyberShield AI Frontend...
echo This script runs in CMD to avoid Git Bash 'TP_NUM_C_BUFS' errors.

if exist "venv\Scripts\activate.bat" (
    call "venv\Scripts\activate.bat"
)

streamlit run frontend/app.py
pause
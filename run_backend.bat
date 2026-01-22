@echo off
title CyberShield Backend
cd /d "%~dp0"
echo Starting CyberShield AI Backend Server...
echo This script runs in CMD to avoid Git Bash environment issues.

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found!
    echo Please run 'setup.bat' first to install dependencies.
    pause
    exit /b
)

echo Activating virtual environment...
call "venv\Scripts\activate.bat"

python -m backend.main
pause

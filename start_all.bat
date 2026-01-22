@echo off
cd /d "%~dp0"
echo ===================================================
echo Starting CyberShield AI System
echo ===================================================

echo 1. Launching Backend Server...
start "CyberShield Backend" cmd /k "run_backend.bat"

echo 2. Waiting for backend to initialize (5s)...
timeout /t 5 /nobreak >nul

echo 3. Launching Frontend App...
start "CyberShield Frontend" cmd /k "run_frontend.bat"
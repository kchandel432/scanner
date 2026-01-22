@echo off
REM Script to install YARA on Windows for the malware scanner

echo ========================================
echo Installing YARA for Windows
echo ========================================

REM Check if YARA is already installed
where yara >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo YARA is already installed!
    yara --version
    pause
    exit /b 0
)

REM Check if Chocolatey is installed
where choco >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Chocolatey is not installed. Installing now...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
)

REM Install YARA using Chocolatey
echo Installing YARA via Chocolatey...
choco install yara -y

echo.
echo ========================================
echo YARA installation complete!
echo ========================================
echo Please restart your terminal and run:
echo   run_backend.bat
echo.
pause

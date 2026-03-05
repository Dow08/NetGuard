@echo off
REM NetGuard v2.1 — Installation Windows

echo.
echo ========================================
echo   NetGuard v2.1 — Installation
echo ========================================
echo.

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo X Python non trouve. Installez-le depuis https://python.org
    echo   IMPORTANT: Cochez "Add Python to PATH"
    pause & exit /b 1
)

echo [1/2] Installation des dependances...
python -m pip install -q requests flask flask-cors
echo   OK

echo [2/2] Scapy (optionnel)...
python -m pip install -q scapy 2>nul
if not exist dashboard mkdir dashboard

echo.
echo ========================================
echo   Installation terminee!
echo ========================================
echo.
echo   Lancer:  python netguard_server.py
echo   Dashboard: http://localhost:8765
echo.
pause

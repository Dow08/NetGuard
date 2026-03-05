@echo off
REM Désinstaller NetGuard du démarrage

echo Suppression de NetGuard du démarrage...

schtasks /delete /tn "NetGuard Dashboard" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NetGuard" /f >nul 2>&1

echo ✓ NetGuard retiré du démarrage automatique.
pause

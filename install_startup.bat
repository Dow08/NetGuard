@echo off
REM ═══════════════════════════════════════════════════
REM NetGuard — Installation au démarrage Windows
REM Crée une tâche planifiée pour lancer NetGuard au login
REM Doit être lancé en tant qu'Administrateur
REM ═══════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════════════╗
echo ║   🔒  NetGuard — Installation démarrage auto ║
echo ╚══════════════════════════════════════════════╝
echo.

REM Vérifier les droits admin
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ⚠️  Ce script doit être lancé en tant qu'Administrateur!
    echo     Clic droit ^> Executer en tant qu'administrateur
    echo.
    pause
    exit /b 1
)

REM Trouver Python
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Python non trouvé dans le PATH
    pause
    exit /b 1
)

REM Chemin du script
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_PATH=%SCRIPT_DIR%netguard_server.py"

REM Vérifier que le script existe
if not exist "%SCRIPT_PATH%" (
    echo ❌ netguard_server.py non trouvé dans %SCRIPT_DIR%
    pause
    exit /b 1
)

REM Supprimer l'ancienne tâche si elle existe
schtasks /delete /tn "NetGuard Dashboard" /f >nul 2>&1

REM Créer la tâche planifiée
echo [1/2] Création de la tâche planifiée...
schtasks /create ^
    /tn "NetGuard Dashboard" ^
    /tr "pythonw \"%SCRIPT_PATH%\"" ^
    /sc onlogon ^
    /rl highest ^
    /f

if %ERRORLEVEL% EQU 0 (
    echo   ✓ Tâche planifiée créée avec succès!
) else (
    echo   ⚠️ Erreur création tâche. Tentative alternative...
    REM Méthode alternative via registre
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NetGuard" /t REG_SZ /d "pythonw \"%SCRIPT_PATH%\"" /f
    if %ERRORLEVEL% EQU 0 (
        echo   ✓ Ajouté au registre de démarrage!
    ) else (
        echo   ❌ Échec. Voir méthode manuelle ci-dessous.
    )
)

REM Créer aussi un raccourci VBS pour démarrage silencieux
echo [2/2] Création du lanceur silencieux...
(
echo Set WshShell = CreateObject("WScript.Shell"^)
echo WshShell.Run "pythonw ""%SCRIPT_PATH%""", 0, False
) > "%SCRIPT_DIR%netguard_silent.vbs"
echo   ✓ Lanceur silencieux créé (netguard_silent.vbs)

echo.
echo ══════════════════════════════════════════════
echo   ✅ NetGuard se lancera automatiquement
echo      à chaque démarrage de Windows!
echo ══════════════════════════════════════════════
echo.
echo   Pour désactiver:
echo     schtasks /delete /tn "NetGuard Dashboard" /f
echo   OU
echo     reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NetGuard" /f
echo.
echo   Le dashboard sera accessible sur:
echo     http://localhost:8765
echo.
pause

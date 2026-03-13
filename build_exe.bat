@echo off
setlocal
echo ========================================================
echo        MALWARE DETECTOR BUILD SYSTEM (ONE-FILE)
echo ========================================================

:: 1. CLEANUP
echo [*] Cleaning old build files...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

:: 2. PRE-BUILD CHECKS
echo [*] Verifying paths...
if not exist "icons\icon.ico" (
    echo [!] WARNING: icon.ico not found in 'icons' folder.
    echo [>] Proceeding with default icon...
    set ICON_CMD=
) else (
    echo [V] Icon found.
    set ICON_CMD=--icon="icons/icon.ico"
)

:: 3. COMPILATION
echo [*] Starting PyInstaller...
echo [*] This will bundle everything into dist/STRIKE.exe

pyinstaller --noconsole --onefile ^
    %ICON_CMD% ^
    --name "STRIKE" ^
    --add-data "models;models" ^
    --add-data "data;data" ^
    --hidden-import "numpy" ^
    --hidden-import "pandas" ^
    --hidden-import "joblib" ^
    --hidden-import "sklearn" ^
    --hidden-import "psutil" ^
    --hidden-import "torch" ^
    --hidden-import "lightgbm" ^
    --hidden-import "onnxruntime" ^
    --hidden-import "matplotlib" ^
    --hidden-import "matplotlib.backends.backend_tkagg" ^
    --hidden-import "dynamic_module" ^
    --hidden-import "static_module" ^
    --hidden-import "network_module" ^
    --hidden-import "resource_manager" ^
    main_ui.py

:: 4. FINALIZATION
echo.
if %ERRORLEVEL% NEQ 0 (
    echo [!] BUILD FAILED! Check the error logs above.
) else (
    echo [V] SUCCESS!
    echo [>] Your standalone app: dist/MalwareDetector.exe
)

echo ========================================================
pause
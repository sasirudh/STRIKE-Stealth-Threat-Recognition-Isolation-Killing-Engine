@echo off
echo =========================================
echo Cleaning up old build files...
echo =========================================
rmdir /s /q build
rmdir /s /q dist
del /q *.spec

echo.
echo =========================================
echo Compiling Malware Detector to .exe...
echo =========================================

:: --noconsole hides the black terminal window behind your UI
:: --add-data bundles your required folders (models and data)
:: --hidden-import forces PyInstaller to include tricky AI/ML libraries

pyinstaller --noconsole ^
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
  --name "STRIKE" main_ui.py

echo.
echo =========================================
echo Build Complete! Look inside the "dist" folder.
echo =========================================
pause


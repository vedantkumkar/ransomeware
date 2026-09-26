@echo off
REM ============================================================
REM  RansomGuard IR - rebuild release\DemoRansomware.exe
REM  (SAFE simulator — see simulator\README.md)
REM ============================================================

REM ---- 1. Python check ---------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python is not installed or not on PATH.
  echo         Install Python 3.11+ and re-run this script.
  pause
  exit /b 1
)

REM ---- 2. PyInstaller check / install ------------------------
pyinstaller --version >nul 2>&1
if errorlevel 1 (
  echo [SETUP] PyInstaller not found - installing ...
  pip install pyinstaller
  if errorlevel 1 (
    echo [ERROR] Could not install PyInstaller. Check your internet/pip setup.
    pause
    exit /b 1
  )
)

REM ---- 3. Build ----------------------------------------------
echo Building release\DemoRansomware.exe ...
cd /d "%~dp0..\simulator"
pyinstaller --onefile --clean --noconfirm --name DemoRansomware ^
  --distpath ../release --workpath build --specpath build demo_ransomware.py
if errorlevel 1 (
  echo [ERROR] PyInstaller build failed - see output above.
  pause
  exit /b 1
)

REM ---- 4. Cleanup + verify -----------------------------------
rd /s /q build 2>nul
if exist "%~dp0..\release\DemoRansomware.exe" (
  echo.
  echo [OK] Built: release\DemoRansomware.exe
  echo      Quick check - the EXE must refuse any non-demo folder:
  echo      DemoRansomware.exe --dir C:\somewhere\else   should print SAFETY REFUSAL
) else (
  echo [ERROR] release\DemoRansomware.exe not found after build.
)
pause

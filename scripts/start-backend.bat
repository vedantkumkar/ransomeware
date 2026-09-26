@echo off
REM ============================================================
REM  RansomGuard IR - start the FastAPI backend (port 8000)
REM ============================================================

REM ---- 1. Python check ---------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python is not installed or not on PATH.
  echo         Install Python 3.11+ from https://www.python.org/downloads/
  pause
  exit /b 1
)

REM ---- 2. Dependency check / install --------------------------
python -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
  echo [SETUP] Backend dependencies missing - installing from requirements.txt ...
  cd /d "%~dp0..\backend"
  pip install -r requirements.txt
  if errorlevel 1 (
    echo [ERROR] Could not install backend dependencies. Check your internet/pip setup.
    pause
    exit /b 1
  )
)

REM ---- 3. Start -----------------------------------------------
cd /d "%~dp0..\backend"
echo Starting RansomGuard IR backend on http://localhost:8000
echo   API docs: http://localhost:8000/docs
echo   Stop: Ctrl+C
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
pause

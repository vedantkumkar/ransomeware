@echo off
REM RansomGuard IR - start the frontend dev server on http://localhost:5173
cd /d "%~dp0..\frontend"
if not exist node_modules (
  echo Installing frontend dependencies ...
  call npm install
)
echo Starting RansomGuard IR frontend on http://localhost:5173 ...
call npm run dev
pause

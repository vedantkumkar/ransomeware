@echo off
REM RansomGuard IR - reset the demo so it can be repeated.
REM Pass --with-db to also clear the backend database and evidence storage.
cd /d "%~dp0.."
python simulator\reset_demo.py %*
pause

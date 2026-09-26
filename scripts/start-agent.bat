@echo off
REM RansomGuard IR - start the VM detection agent.
REM Run this INSIDE VICTIM-PC-01 for the live demo (backend_url then points at
REM the VirtualBox host-only gateway, default http://192.168.56.1:8000).
REM For host-side testing, set backend_url=http://localhost:8000 in vm-agent\config.ini
cd /d "%~dp0..\vm-agent"
if not exist config.ini (
  echo No config.ini found - copying config.example.ini ...
  copy config.example.ini config.ini
)
echo Starting RansomGuard VM detection agent ...
python detector\main.py
pause

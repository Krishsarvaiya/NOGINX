@echo off
REM Starts the demo in CSV mode (Flask + live_analyzer + dashboard; no NGINX).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_demo.ps1" -Mode csv

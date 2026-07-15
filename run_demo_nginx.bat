@echo off
REM Starts the demo in NGINX mode (NGINX + Flask + live_analyzer + dashboard).
REM Requires nginx\nginx.exe to already exist -- run
REM   powershell -ExecutionPolicy Bypass -File scripts\setup_nginx_windows.ps1
REM once first if it doesn't (see docs\NGINX_SETUP.md).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_demo.ps1" -Mode nginx

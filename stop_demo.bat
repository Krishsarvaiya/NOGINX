@echo off
REM Stops everything started by run_demo.bat / run_demo_csv.bat / run_demo_nginx.bat.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop_demo.ps1"

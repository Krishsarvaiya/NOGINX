@echo off
REM One-command demo startup. Default mode is CSV; pass "nginx" to switch:
REM     run_demo.bat
REM     run_demo.bat nginx
setlocal
set MODE=%1
if "%MODE%"=="" set MODE=csv
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_demo.ps1" -Mode %MODE%
endlocal

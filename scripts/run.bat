@echo off
set SCRIPT_DIR=%~dp0
REM Activate venv if available
if exist "%SCRIPT_DIR%..\.venv\Scripts\activate.bat" (
  call "%SCRIPT_DIR%..\.venv\Scripts\activate.bat"
)

echo Starting Streamlit dashboard...
start "Streamlit" python -m streamlit run src/app.py --server.headless true

echo Starting live analyzer...
start "LiveAnalyzer" python src\live_analyzer.py

echo Launched Streamlit and Live Analyzer.

#!/usr/bin/env pwsh
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$venv_activate = Join-Path $root '..\.venv\Scripts\Activate.ps1'
if (Test-Path $venv_activate) {
    & $venv_activate
}

Write-Host "Starting Streamlit dashboard..."
Start-Process -NoNewWindow -FilePath python -ArgumentList '-m', 'streamlit', 'run', 'src/app.py', '--server.headless', 'true'

Write-Host "Starting live analyzer..."
Start-Process -NoNewWindow -FilePath python -ArgumentList 'src\live_analyzer.py'

Write-Host "Launched processes. Check terminal output for local URLs."

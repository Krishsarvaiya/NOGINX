<#
.SYNOPSIS
    Stops exactly what run_demo.ps1 started (tracked via .demo_pids.json),
    without touching any other Python/NGINX process on the machine.
#>

$ErrorActionPreference = "Continue"
$RepoRoot = $PSScriptRoot
Set-Location $RepoRoot
$PidFile = Join-Path $RepoRoot ".demo_pids.json"

Write-Host "====================================="
Write-Host " Stopping demo"
Write-Host "====================================="

if (-not (Test-Path $PidFile)) {
    Write-Host "No .demo_pids.json found -- nothing was started via run_demo.ps1/.bat (or it was already stopped)."
    Write-Host "Demo stopped successfully"
    exit 0
}

$demoPids = Get-Content $PidFile -Raw | ConvertFrom-Json

function Stop-IfRunning {
    param([string]$Name, $ProcId)
    if ($null -eq $ProcId) {
        Write-Host "$Name ............ (not started by this script, left untouched)"
        return
    }
    $proc = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if ($proc) {
        # /T kills the whole process tree, not just this PID -- confirmed
        # necessary by testing: "streamlit.exe" (the PID Start-Process
        # returns) launches a *child* python.exe that actually binds the
        # server port, so Stop-Process on the parent alone leaves that
        # child (and the port) running.
        taskkill /PID $ProcId /T /F *> $null
        Write-Host "$Name ............ stopped (PID $ProcId)"
    } else {
        Write-Host "$Name ............ already stopped"
    }
}

Stop-IfRunning "Dashboard" $demoPids.dashboard
Stop-IfRunning "Analyzer " $demoPids.analyzer
Stop-IfRunning "Website  " $demoPids.flask
Stop-IfRunning "NGINX    " $demoPids.nginx

Remove-Item $PidFile -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 1
$stillUp = @()
foreach ($port in 80, 5000, 8765, 8501) {
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        $stillUp += $port
    }
}
if ($stillUp.Count -gt 0) {
    Write-Host ""
    Write-Host "Note: port(s) $($stillUp -join ', ') still show as listening -- if that's unexpected, check Task Manager for a lingering process."
}

Write-Host ""
Write-Host "Demo stopped successfully"

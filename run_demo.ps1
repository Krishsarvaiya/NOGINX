<#
.SYNOPSIS
    One-command startup for the NGINX Web Server Log Anomaly Detection demo.
    Starts (as needed) NGINX, the Flask demo site, the live analyzer, and the
    Streamlit dashboard, waits for each to come up, and opens the dashboard
    in your browser.

.PARAMETER Mode
    "csv" (default) -- live_analyzer.py tails the Flask demo site's own CSV
                       access log. No NGINX required.
    "nginx"         -- starts NGINX as a reverse proxy in front of Flask;
                       live_analyzer.py tails NGINX's access.log instead.
                       Requires nginx/nginx.exe to already exist -- run
                       scripts\setup_nginx_windows.ps1 once first if it
                       doesn't (see docs\NGINX_SETUP.md).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File run_demo.ps1
    powershell -ExecutionPolicy Bypass -File run_demo.ps1 -Mode nginx
#>

param(
    [ValidateSet("csv", "nginx")]
    [string]$Mode = "csv"
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot
Set-Location $RepoRoot

$FlaskPort     = if ($env:FLASK_PORT) { [int]$env:FLASK_PORT } else { 5000 }
$NginxPort     = if ($env:NGINX_PORT) { [int]$env:NGINX_PORT } else { 80 }
$AnalyzerPort  = 8765
$DashboardPort = 8501
$PidFile       = Join-Path $RepoRoot ".demo_pids.json"
$LogDir        = Join-Path $RepoRoot "logs_demo"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
# "mode" is read back by demo\_common.py as a fallback when LOG_SOURCE
# isn't set in *its own* process's environment -- $env:LOG_SOURCE set
# below is only ever inherited by this script's own child processes (the
# analyzer), never by a separate terminal a user opens afterward to run a
# demo/simulate_*.py script. Confirmed by reproducing exactly that: a
# fresh shell with LOG_SOURCE unset resolved BASE_URL to Flask directly,
# and simulated attack traffic never reached nginx\logs\access.log at
# all. Persisting the active mode here, in the same state file
# stop_demo.ps1 already deletes on shutdown, lets any later terminal find
# the real running mode without relying on env var inheritance.
$startedPids = @{ nginx = $null; flask = $null; analyzer = $null; dashboard = $null; mode = $Mode }

function Test-PortInUse {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Get-PortOwnerPid {
    # Used to verify the *actual* running instance behind a port, not just
    # whatever PID Start-Process happened to return -- see the health-check
    # notes below.
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) { return $conn.OwningProcess } else { return $null }
}

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSeconds = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortInUse -Port $Port) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Wait-ForHttp {
    param([string]$Url, [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Fail {
    param([string]$Message)
    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red
    Write-Host "See the logs_demo\ folder for details, or docs\RUN_PROJECT.md for troubleshooting."
    Write-Host "====================================="
    exit 1
}

# Always use THIS project's own virtual environment -- never a bare
# "python"/"streamlit" command name resolved via PATH. Confirmed by testing
# that bare PATH lookups are not reliable: on a machine with more than one
# Python installation, "python" and "streamlit" can each resolve to a
# *different* installation (Windows resolves each command name
# independently, first match wins per directory on PATH) -- one had this
# project's dependencies (including plotly), the other didn't, so the
# dashboard crashed with ModuleNotFoundError while Flask/the analyzer
# started fine.
#
# venv\Scripts\python.exe is deliberately NOT invoked directly, even though
# it's this venv's own interpreter path -- confirmed by testing (file
# VersionInfo: InternalName "Python Launcher", OriginalFilename "py.exe";
# reproduced with a trivial `python.exe -c "..."` completely unrelated to
# this project's own code) that on this Python version, venv's Windows
# "copies" mode installs a *launcher stub* at that path, not a real
# interpreter copy: every process started through it shows up as TWO OS
# processes (the stub, plus the real interpreter it spawns as a child with
# an identical command line) -- harmless (only the child ever binds a port
# or does real work), but confusing to inspect, and exactly what produced
# the "two Flask / two live_analyzer / two Streamlit processes" symptom.
# Windows has no in-place exec(), so a launcher stub can never avoid this
# extra layer -- it must always spawn a child.
#
# The fix: invoke the *base* interpreter this venv points to (read from
# venv\pyvenv.cfg's own "executable ="/"home =" line -- never hardcoded)
# directly, with PYTHONPATH set to this venv's site-packages so it still
# resolves every installed dependency. Confirmed by testing to produce
# exactly one OS process per component, with the exact same packages
# available as venv\Scripts\python.exe would have provided.
$VenvPython = Join-Path $RepoRoot "venv\Scripts\python.exe"
$VenvCfg = Join-Path $RepoRoot "venv\pyvenv.cfg"
$VenvSitePackages = Join-Path $RepoRoot "venv\Lib\site-packages"
if (-not (Test-Path $VenvPython) -or -not (Test-Path $VenvCfg) -or -not (Test-Path $VenvSitePackages)) {
    Write-Host "ERROR: Project virtual environment not found (expected venv\Scripts\python.exe, venv\pyvenv.cfg, venv\Lib\site-packages)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Create it first:"
    Write-Host "  python -m venv venv"
    Write-Host "  venv\Scripts\activate"
    Write-Host "  pip install -r requirements.txt"
    Write-Host ""
    Write-Host "See docs\RUN_PROJECT.md."
    exit 1
}

$cfgLines = Get-Content $VenvCfg
$executableLine = $cfgLines | Where-Object { $_ -match '^\s*executable\s*=\s*(.+)$' } | Select-Object -First 1
$homeLine = $cfgLines | Where-Object { $_ -match '^\s*home\s*=\s*(.+)$' } | Select-Object -First 1
if ($executableLine -match '^\s*executable\s*=\s*(.+)$') {
    $BasePython = $Matches[1].Trim()
} elseif ($homeLine -match '^\s*home\s*=\s*(.+)$') {
    $BasePython = Join-Path $Matches[1].Trim() "python.exe"
} else {
    Fail "Could not determine the base Python interpreter from venv\pyvenv.cfg."
}
if (-not (Test-Path $BasePython)) {
    Fail "Base interpreter referenced by venv\pyvenv.cfg does not exist: $BasePython (was the base Python moved or uninstalled since the venv was created?)"
}
# Makes every subsequent Start-Process call in this script (which inherits
# the current environment) resolve this venv's packages under $BasePython.
$env:PYTHONPATH = $VenvSitePackages

Write-Host "====================================="
Write-Host " NGINX Web Server Log Anomaly Detection"
Write-Host " Starting demo in '$Mode' mode..."
Write-Host "====================================="

# --- Pre-flight: don't clobber an already-running demo -----------------
if (Test-Path $PidFile) {
    Write-Host "A .demo_pids.json from a previous run already exists."
    Write-Host "Run stop_demo.bat first if a demo is already running, or delete .demo_pids.json if it's stale."
    Fail "Refusing to start a second demo on top of a possibly-running one."
}

# --- NGINX (nginx mode only) --------------------------------------------
if ($Mode -eq "nginx") {
    $existing = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "NGINX ............ ALREADY RUNNING (PID $($existing[0].Id)) -- reusing, not starting a duplicate"
        $startedPids.nginx = $null
    } else {
        if (Test-PortInUse -Port $NginxPort) {
            Fail "Port $NginxPort is already in use by something else. Free it, or set `$env:NGINX_PORT to a different value and retry."
        }
        $nginxExe = Join-Path $RepoRoot "nginx\nginx.exe"
        if (-not (Test-Path $nginxExe)) {
            Fail "nginx.exe not found at nginx\nginx.exe. Run: powershell -ExecutionPolicy Bypass -File scripts\setup_nginx_windows.ps1 (see docs\NGINX_SETUP.md)."
        }
        & $BasePython (Join-Path $RepoRoot "scripts\generate_nginx_conf.py") | Out-Null
        try {
            $p = Start-Process -FilePath $nginxExe -ArgumentList "-p", "nginx", "-c", "conf\nginx.conf" -PassThru -WindowStyle Hidden
        } catch {
            Fail "Could not launch nginx.exe: $_"
        }
        if (Wait-ForPort -Port $NginxPort -TimeoutSeconds 10) {
            # NGINX's own master/worker model is a SEPARATE, well-known,
            # expected process pair (worker_processes 1; in our conf) --
            # unrelated to the venv-launcher issue above, not something
            # this script tries to collapse to one PID.
            Write-Host "NGINX ............ OK"
            $startedPids.nginx = $p.Id
        } else {
            Fail "NGINX did not start listening on port $NginxPort. Check nginx\logs\error.log."
        }
    }
}

# --- Flask demo website (both modes) ------------------------------------
if (Test-PortInUse -Port $FlaskPort) {
    Fail "Port $FlaskPort is already in use -- is site\app.py already running? Run stop_demo.bat first."
}
try {
    $flaskOut = Join-Path $LogDir "flask.out.log"
    $flaskErr = Join-Path $LogDir "flask.err.log"
    $p = Start-Process -FilePath $BasePython -ArgumentList "site\app.py" -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $flaskOut -RedirectStandardError $flaskErr
} catch {
    Fail "Could not launch 'site\app.py' via the project's venv: $_. See docs\RUN_PROJECT.md."
}
if (Wait-ForHttp -Url "http://127.0.0.1:$FlaskPort/" -TimeoutSeconds 20) {
    # Verify the actual running instance behind the port, not just assume
    # $p.Id is it -- with the base-interpreter approach above these now
    # match, but this check stays as a genuine health verification rather
    # than a blind assumption.
    $realPid = Get-PortOwnerPid -Port $FlaskPort
    Write-Host "Website .......... OK (PID $realPid)"
    $startedPids.flask = $p.Id
} else {
    Fail "Flask site did not respond on http://127.0.0.1:$FlaskPort/ -- see logs_demo\flask.err.log"
}

# --- Live analyzer (both modes) -----------------------------------------
if (Test-PortInUse -Port $AnalyzerPort) {
    Fail "Port $AnalyzerPort is already in use -- is src\live_analyzer.py already running? Run stop_demo.bat first."
}
$env:LOG_SOURCE = $Mode
try {
    $analyzerOut = Join-Path $LogDir "analyzer.out.log"
    $analyzerErr = Join-Path $LogDir "analyzer.err.log"
    $p = Start-Process -FilePath $BasePython -ArgumentList "src\live_analyzer.py" -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $analyzerOut -RedirectStandardError $analyzerErr
} catch {
    Fail "Could not launch 'src\live_analyzer.py' via the project's venv: $_"
}
if (Wait-ForPort -Port $AnalyzerPort -TimeoutSeconds 15) {
    $realPid = Get-PortOwnerPid -Port $AnalyzerPort
    Write-Host "Analyzer ......... OK (PID $realPid)"
    $startedPids.analyzer = $p.Id
} else {
    Fail "Analyzer did not start its WebSocket server on port $AnalyzerPort -- see logs_demo\analyzer.err.log"
}

# --- Streamlit dashboard (both modes) ------------------------------------
if (Test-PortInUse -Port $DashboardPort) {
    Fail "Port $DashboardPort is already in use -- is the dashboard already running? Run stop_demo.bat first."
}
try {
    $dashOut = Join-Path $LogDir "dashboard.out.log"
    $dashErr = Join-Path $LogDir "dashboard.err.log"
    # "-m streamlit" (module invocation), not the separate "streamlit.exe"
    # entry-point script -- avoids a second, unrelated wrapper-process
    # layer that entry-point .exe stubs introduce on top of the
    # venv-launcher issue described above.
    $p = Start-Process -FilePath $BasePython -ArgumentList "-m", "streamlit", "run", "src\app.py", "--server.headless", "true", "--server.port", "$DashboardPort" `
        -PassThru -WindowStyle Hidden -RedirectStandardOutput $dashOut -RedirectStandardError $dashErr
} catch {
    Fail "Could not launch the Streamlit dashboard via the project's venv: $_. Run: pip install -r requirements.txt"
}
if (Wait-ForHttp -Url "http://127.0.0.1:$DashboardPort/" -TimeoutSeconds 30) {
    # A responding HTTP port is NOT proof the dashboard actually rendered --
    # confirmed by testing that Streamlit still returns 200 while showing a
    # traceback for a script-level exception (e.g. ModuleNotFoundError):
    # the dev server itself started fine, only the app script failed. Give
    # the script runner a moment to finish executing, then check its own
    # log for exactly that failure mode before declaring success.
    Start-Sleep -Seconds 2
    $dashLogText = ""
    if (Test-Path $dashOut) { $dashLogText += Get-Content $dashOut -Raw }
    if (Test-Path $dashErr) { $dashLogText += Get-Content $dashErr -Raw }
    if ($dashLogText -match "Traceback \(most recent call last\)" -or $dashLogText -match "ModuleNotFoundError") {
        Fail "Dashboard server started, but src\app.py raised an error on load -- see logs_demo\dashboard.out.log for the traceback."
    }
    $realPid = Get-PortOwnerPid -Port $DashboardPort
    Write-Host "Dashboard ........ OK (PID $realPid)"
    $startedPids.dashboard = $p.Id
} else {
    Fail "Dashboard did not respond on http://127.0.0.1:$DashboardPort/ -- see logs_demo\dashboard.err.log"
}

# --- Persist what we started, for stop_demo.bat to clean up -------------
$startedPids | ConvertTo-Json | Set-Content -Path $PidFile -Encoding utf8

Write-Host "====================================="
Write-Host "Demo Ready"
Write-Host "====================================="
Write-Host ""
if ($Mode -eq "nginx") {
    $nginxUrlPort = if ($NginxPort -eq 80) { "" } else { ":$NginxPort" }
    Write-Host "Website:   http://127.0.0.1$nginxUrlPort/   (via NGINX)"
} else {
    Write-Host "Website:   http://127.0.0.1:$FlaskPort/"
}
Write-Host "Dashboard: http://127.0.0.1:$DashboardPort/"
Write-Host "Log source: $Mode"
Write-Host ""
Write-Host "To generate attack traffic (activate the venv first: venv\Scripts\activate), run scripts like:"
Write-Host "  python demo\simulate_sql_injection.py"
Write-Host ""
Write-Host "To stop everything: stop_demo.bat"
Write-Host ""

Start-Process "http://127.0.0.1:$DashboardPort/"

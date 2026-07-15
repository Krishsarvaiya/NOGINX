<#
.SYNOPSIS
    Downloads the official nginx-for-Windows stable build and sets it up
    as a project-local reverse proxy in front of the Flask demo site
    (site/app.py), living entirely inside nginx/ at the repo root.

.DESCRIPTION
    No admin rights, no system-wide install, no Docker/VPS/cloud/domain
    -- this only ever touches this repo's own nginx/ folder. Safe to
    re-run: skips the download/extract step if nginx/nginx.exe already
    exists, and always regenerates nginx/conf/nginx.conf from the
    current core/config.py values.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\setup_nginx_windows.ps1
#>

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$NginxVersion = "1.30.3"
$ZipUrl = "https://nginx.org/download/nginx-$NginxVersion.zip"
$DownloadPath = Join-Path $env:TEMP "nginx-$NginxVersion.zip"
$ExtractTemp = Join-Path $env:TEMP "nginx-$NginxVersion-extract"
$TargetDir = Join-Path $RepoRoot "nginx"

if (Test-Path (Join-Path $TargetDir "nginx.exe")) {
    Write-Host "nginx.exe already present at $TargetDir -- skipping download."
} else {
    Write-Host "Downloading nginx $NginxVersion (official stable Windows build) from $ZipUrl ..."
    Invoke-WebRequest -Uri $ZipUrl -OutFile $DownloadPath

    if (Test-Path $ExtractTemp) { Remove-Item -Recurse -Force $ExtractTemp }
    Expand-Archive -Path $DownloadPath -DestinationPath $ExtractTemp -Force

    $ExtractedNginxDir = Join-Path $ExtractTemp "nginx-$NginxVersion"
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
    }
    Copy-Item -Path (Join-Path $ExtractedNginxDir "*") -Destination $TargetDir -Recurse -Force

    Remove-Item -Force $DownloadPath
    Remove-Item -Recurse -Force $ExtractTemp
    Write-Host "nginx $NginxVersion installed to $TargetDir"
}

Write-Host "Generating nginx/conf/nginx.conf from core/config.py ..."
python (Join-Path $RepoRoot "scripts\generate_nginx_conf.py")
if (-not $?) {
    Write-Host "generate_nginx_conf.py failed -- fix the error above and re-run this script before starting nginx."
    exit 1
}

New-Item -ItemType Directory -Force -Path (Join-Path $TargetDir "logs") | Out-Null

# NGINX defaults its "prefix" (where it looks for conf/nginx.conf) to
# the current working directory it's launched from, NOT the directory
# nginx.exe itself lives in -- confirmed by testing this script's own
# output. Passing -p/-c explicitly makes every command below work
# regardless of which directory it's run from, instead of requiring a
# `cd nginx` first.
Write-Host ""
Write-Host "Setup complete. Next steps (run each in its own terminal, from the repo root):"
Write-Host "  1. Start Flask:        python site\app.py"
Write-Host "  2. Test the config:    nginx\nginx.exe -p nginx -c conf\nginx.conf -t"
Write-Host "  3. Start NGINX:        nginx\nginx.exe -p nginx -c conf\nginx.conf"
Write-Host "  4. Switch log source:  `$env:LOG_SOURCE = 'nginx'"
Write-Host "  5. Start the analyzer: python src\live_analyzer.py"
Write-Host "  6. Visit the site:     http://127.0.0.1:<NGINX_PORT>/  (default 80)"
Write-Host ""
Write-Host "Reload after any config change: nginx\nginx.exe -p nginx -c conf\nginx.conf -s reload"
Write-Host "Stop NGINX:                     nginx\nginx.exe -p nginx -c conf\nginx.conf -s quit"
Write-Host ""
Write-Host "See docs\NGINX_SETUP.md for full details, folder layout, and the CSV-mode fallback."

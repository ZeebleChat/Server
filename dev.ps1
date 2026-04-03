# dev.ps1 - Zeeble dev lifecycle helper
# Usage:
#   .\dev.ps1          - bring up all services
#   .\dev.ps1 down     - tear down
#   .\dev.ps1 restart  - tear down then bring back up

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$action = if ($args.Count -gt 0) { $args[0] } else { "up" }

function Dev-Up {
    Push-Location $PSScriptRoot
    Write-Host "Starting Zeeble..." -ForegroundColor Cyan
    docker compose up -d --build
    Write-Host "Ready at http://localhost:4000" -ForegroundColor Green
    Pop-Location
}

function Dev-Down {
    Write-Host "Stopping Zeeble..." -ForegroundColor Cyan
    Push-Location $PSScriptRoot
    docker compose down
    Pop-Location
}

switch ($action) {
    "up"      { Dev-Up }
    "down"    { Dev-Down }
    "restart" { Dev-Down; Dev-Up }
    default   {
        Write-Host "Unknown action '$action'. Use: up | down | restart" -ForegroundColor Red
        exit 1
    }
}

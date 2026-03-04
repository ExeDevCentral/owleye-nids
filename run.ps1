param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,

    [string]$Interface = "",
    [string]$LogPath = ".\network_lowlevel_log.jsonl",
    [int]$DashboardPort = 8787
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".\net_lowlevel_monitor.py")) {
    throw "No se encontro net_lowlevel_monitor.py en el directorio actual."
}

if (-not (Test-Path ".\net_lowlevel_dashboard.py")) {
    throw "No se encontro net_lowlevel_dashboard.py en el directorio actual."
}

$ifaceArg = ""
if ($Interface -and $Interface.Trim().Length -gt 0) {
    $ifaceArg = "--iface `"$Interface`""
}

$monitorCmd = "python .\net_lowlevel_monitor.py --server-ip $ServerIp --out `"$LogPath`" $ifaceArg"
$dashCmd = "python .\net_lowlevel_dashboard.py --log `"$LogPath`" --port $DashboardPort"

Write-Host "Lanzando capturador en nueva terminal (ejecutar PowerShell como administrador)."
Start-Process pwsh -ArgumentList "-NoExit", "-Command", $monitorCmd | Out-Null

Write-Host "Lanzando dashboard en nueva terminal."
Start-Process pwsh -ArgumentList "-NoExit", "-Command", $dashCmd | Out-Null

Write-Host "Dashboard: http://127.0.0.1:$DashboardPort"

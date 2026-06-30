param(
    [string]$DeployDir = "C:\inetpub\ThreatMap"
)

$ErrorActionPreference = "Stop"
$SourceDir = $PSScriptRoot

Write-Host "Starting ThreatMap Redeployment to $DeployDir" -ForegroundColor Cyan

# 1. Check if destination exists
if (-not (Test-Path $DeployDir)) {
    Write-Host "Destination directory $DeployDir does not exist. Creating it..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $DeployDir | Out-Null
}

# 2. Backup local environment configs
$BackupDir = "$env:TEMP\ThreatMap_Backup"
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$FilesToBackup = @("appsettings.Production.json")
Write-Host "Backing up configuration files..."
foreach ($file in $FilesToBackup) {
    if (Test-Path "$DeployDir\$file") {
        Copy-Item "$DeployDir\$file" -Destination "$BackupDir\$file" -Force
    }
}

# 3. Gracefully take IIS app offline
# This releases file locks on .dll files and avoids needing an iisreset
Write-Host "Taking application offline (graceful app pool release)..."
$AppOffline = "$DeployDir\app_offline.htm"
Set-Content -Path $AppOffline -Value "<html><body><h1 style='font-family:sans-serif;text-align:center;margin-top:20%;'>ThreatMap is updating... Please wait.</h1></body></html>"
Start-Sleep -Seconds 2

# 4. Build and Publish directly to IIS directory
# Note: This does NOT delete unreferenced folders (like 'uploads' or 'logs'), so persistent data is safe.
Write-Host "Publishing application..."
dotnet publish "$SourceDir\ThreatMap.Api.csproj" -c Release -o $DeployDir

# 5. Restore local environment configs
Write-Host "Restoring configuration files..."
foreach ($file in $FilesToBackup) {
    if (Test-Path "$BackupDir\$file") {
        Copy-Item "$BackupDir\$file" -Destination "$DeployDir\$file" -Force
    }
}

# 6. Bring application back online
Write-Host "Bringing application online..."
if (Test-Path $AppOffline) {
    Remove-Item -Path $AppOffline -Force
}

Write-Host "Redeployment completed successfully! No iisreset was required." -ForegroundColor Green

#requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Sentinel Cyber Security Suite Agent on a Windows endpoint.
.DESCRIPTION
    Downloads/installs the Sentinel Agent executable, configures it to report
    to the CS Department Management Server, and sets up auto-start.
.PARAMETER MgmtUrl
    URL of the Sentinel Management Server (default: http://127.0.0.1:8000)
.PARAMETER AgentToken
    Shared agent token for registration with the management server.
.PARAMETER AgentId
    Optional custom agent ID. If omitted, a machine-based ID is generated.
#>
param(
    [string]$MgmtUrl = "http://127.0.0.1:8000",
    [string]$AgentToken = "sentinel-agent-token-change-me",
    [string]$AgentId = ""
)

$InstallDir = "$env:ProgramData\Sentinel Cyber Security Suite\Agent"
$ExeName = "SentinelAgent.exe"
$ConfigFile = Join-Path $InstallDir "config.json"

Write-Host "=== Sentinel Cyber Security Suite - Agent Installer ===" -ForegroundColor Cyan

# Create install directory
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Copy agent executable (assumes SentinelAgent.exe is alongside this script)
$SourceExe = Join-Path $PSScriptRoot $ExeName
if (Test-Path $SourceExe) {
    Copy-Item $SourceExe -Destination (Join-Path $InstallDir $ExeName) -Force
    Write-Host "Installed agent to $InstallDir" -ForegroundColor Green
} else {
    Write-Warning "Agent executable not found at $SourceExe. Build it first with PyInstaller."
}

# Write agent configuration
$config = @{
    SENTINEL_MGMT_URL = $MgmtUrl
    SENTINEL_AGENT_TOKEN = $AgentToken
} | ConvertTo-Json -Depth 3

if ($AgentId) {
    $config = @{
        SENTINEL_MGMT_URL = $MgmtUrl
        SENTINEL_AGENT_TOKEN = $AgentToken
        SENTINEL_AGENT_ID = $AgentId
    } | ConvertTo-Json -Depth 3
}

Set-Content -Path $ConfigFile -Value $config -Encoding UTF8
Write-Host "Configuration written to $ConfigFile" -ForegroundColor Green

# Generate agent ID from machine GUID if not provided
if (-not $AgentId) {
    $MachineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $AgentId = "sentinel-" + $MachineGuid.Substring(0, 12)
    Write-Host "Generated agent ID: $AgentId" -ForegroundColor Yellow
}

# Register scheduled task for auto-start
$TaskName = "SentinelAgent"
$TaskCmd = Join-Path $InstallDir $ExeName
$TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $TaskExists) {
    $Action = New-ScheduledTaskAction -Execute $TaskCmd
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
    Write-Host "Scheduled task '$TaskName' created for auto-start." -ForegroundColor Green
} else {
    Write-Host "Scheduled task '$TaskName' already exists." -ForegroundColor Yellow
}

Write-Host "=== Installation complete. Launch SentinelAgent.exe or reboot to start. ===" -ForegroundColor Cyan

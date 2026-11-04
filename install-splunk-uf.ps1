
# ============================================
# CCDC Splunk Universal Forwarder Installer
# Version: 10.0.2
# Windows Server 2019 / 2022 / Windows 11
# ============================================

$ErrorActionPreference = "Stop"

# Configuration
$SplunkServer = "172.20.240.20:9997"
$SplunkVersion = "10.0.2"

$MsiName = "splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi"

$DownloadURL = "https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/$MsiName"

$MsiPath = Join-Path $env:TEMP $MsiName

# Check administrator privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdmin) {
    Write-Host "ERROR: Run PowerShell as Administrator."
    exit 1
}

Write-Host "============================================"
Write-Host " CCDC Splunk Forwarder Installation"
Write-Host "============================================"

    # Download installer
    Write-Host "[1/5] Downloading Splunk Universal Forwarder..."

    Invoke-WebRequest -Uri $DownloadURL -OutFile $MsiPath

    if (!(Test-Path $MsiPath)) {
        throw "Installer download failed."
    }

    # Install Splunk
    Write-Host "[2/5] Installing Splunk Universal Forwarder..."

    $Arguments = @(
        "/i"
        "`"$MsiPath`""
        "AGREETOLICENSE=Yes"
        "SPLUNKUSERNAME=admin"
        "SPLUNKPASSWORD=`"$SplunkPassword`""
        "RECEIVING_INDEXER=`"$SplunkServer`""
        "USE_LOCAL_SYSTEM=1"
        "WINEVENTLOG_SEC_ENABLE=1"
        "WINEVENTLOG_SYS_ENABLE=1"
        "WINEVENTLOG_APP_ENABLE=1"
        "PRIVILEGESECURITY=1"
        "SERVICESTARTTYPE=auto"
        "LAUNCHSPLUNK=1"
        "/quiet"
        "/norestart"
    ) -join " "

    $Process = Start-Process msiexec.exe `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru

    if ($Process.ExitCode -notin @(0, 3010)) {
        throw "Installation failed. Exit code: $($Process.ExitCode)"
    }

    # Start service
    Write-Host "[3/5] Starting Splunk Forwarder..."

    Set-Service -Name SplunkForwarder -StartupType Automatic

    Start-Service -Name SplunkForwarder

    # Test connectivity
    Write-Host "[4/5] Testing connection to Splunk..."

    Test-NetConnection 172.20.240.20 -Port 9997

    # Check service
    Write-Host "[5/5] Checking Splunk service..."

    Get-Service SplunkForwarder

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Installation completed!"
    Write-Host " Forwarding to: $SplunkServer"
    Write-Host "============================================"
}
finally {
    $SplunkPassword = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $SecurePassword.Dispose()
}

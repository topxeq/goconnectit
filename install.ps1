$ErrorActionPreference = "Stop"

$REPO = "topxeq/goconnectit"
$BINARY_NAME = "goconnectit.exe"
$INSTALL_DIR = "$env:USERPROFILE\bin"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Get-OS {
    if ($IsWindows -or $env:OS -match "Windows") {
        return "windows"
    } elseif ($IsMacOS) {
        return "darwin"
    } elseif ($IsLinux) {
        return "linux"
    }
    return "unknown"
}

function Get-Arch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64" { return "amd64" }
        "Arm64" { return "arm64" }
        default { return "unknown" }
    }
}

function Get-LatestVersion {
    $url = "https://api.github.com/repos/$REPO/releases/latest"
    $response = Invoke-RestMethod -Uri $url -UseBasicParsing
    return $response.tag_name
}

function Main {
    Write-Info "Installing goconnectit..."

    $os = Get-OS
    $arch = Get-Arch

    if ($os -eq "unknown" -or $arch -eq "unknown") {
        Write-Error-Custom "Unsupported OS or architecture: $os/$arch"
        exit 1
    }

    Write-Info "Detected OS: $os, Architecture: $arch"

    $version = Get-LatestVersion
    if (-not $version) {
        Write-Error-Custom "Failed to get latest version"
        exit 1
    }
    Write-Info "Latest version: $version"

    $archiveName = "$BINARY_NAME-$os-$arch.zip"
    $downloadUrl = "https://github.com/$REPO/releases/download/$version/$archiveName"
    Write-Info "Downloading from: $downloadUrl"

    $tmpDir = [System.IO.Path]::GetTempPath()
    $archivePath = Join-Path $tmpDir $archiveName

    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing

    Write-Info "Extracting..."
    $extractDir = Join-Path $tmpDir "goconnectit-extract"
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

    if (-not (Test-Path $INSTALL_DIR)) {
        New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
    }

    $binaryPath = Join-Path $extractDir $BINARY_NAME
    $destPath = Join-Path $INSTALL_DIR $BINARY_NAME
    Copy-Item -Path $binaryPath -Destination $destPath -Force

    Remove-Item -Path $archivePath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Info "Installation complete!"
    Write-Info "Binary installed to: $destPath"

    $pathEnv = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($pathEnv -notlike "*$INSTALL_DIR*") {
        Write-Info "Adding $INSTALL_DIR to PATH..."
        [Environment]::SetEnvironmentVariable("PATH", "$pathEnv;$INSTALL_DIR", "User")
        Write-Info "Please restart your terminal to update PATH"
    }

    Write-Info "Run 'goconnectit -h' for usage information."
}

Main

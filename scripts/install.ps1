#Requires -Version 5.1
<#
.SYNOPSIS
    One-line installer for the GRYM CLI and TUI on Windows.
.DESCRIPTION
    Downloads the latest (or a specific) GRYM release from GitHub, extracts it,
    installs it into a user directory, and adds that directory to the user PATH.

    Run with:
        irm https://raw.githubusercontent.com/owner/grym/main/scripts/install.ps1 | iex

    Or with parameters:
        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Karmanya03/grym/main/scripts/install.ps1))) -Version v0.1.0 -Bin grym-tui

    Or via environment variables:
        $env:GRYM_VERSION = "v0.1.0"; $env:GRYM_BIN = "grym-tui"; irm .../install.ps1 | iex
#>
param(
    [string]$InstallDir = "",
    [string]$Version = "",
    [ValidateSet("grym", "grym-tui")]
    [string]$Bin = "",
    [switch]$NoModifyPath,
    [string]$Owner = ""
)

if ([string]::IsNullOrWhiteSpace($Version)) { $Version = $env:GRYM_VERSION }
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = "latest" }

if ([string]::IsNullOrWhiteSpace($Bin)) { $Bin = $env:GRYM_BIN }
if ([string]::IsNullOrWhiteSpace($Bin)) { $Bin = "grym" }

if ([string]::IsNullOrWhiteSpace($Owner)) { $Owner = $env:GRYM_OWNER }
if ([string]::IsNullOrWhiteSpace($Owner)) { $Owner = "Karmanya03" }

if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = $env:GRYM_INSTALL_DIR }

$ErrorActionPreference = "Stop"

$Repo = "grym"

function Get-LatestRelease {
    param([string]$Owner, [string]$Repo)
    $uri = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $release = Invoke-RestMethod -Uri $uri -UseBasicParsing
    return $release.tag_name
}

function Get-Architecture {
    if ([Environment]::Is64BitOperatingSystem) {
        return "x86_64"
    }
    # Fallback for older 32-bit Windows; not published by default.
    return "x86"
}

function Get-InstallDirectory {
    if ($InstallDir) { return $InstallDir }
    $candidate = Join-Path $env:LOCALAPPDATA "Programs\Grym"
    return $candidate
}

function Add-ToPath {
    param([string]$Directory)
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = $current -split ";" | Where-Object { $_ -and $_ -ne $Directory }
    $newPath = ($parts + $Directory) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added $Directory to your user PATH." -ForegroundColor Green
    Write-Host "Open a new PowerShell window to use it." -ForegroundColor Green
}

# --- Resolve version ---------------------------------------------------------
if ($Version -eq "latest" -or [string]::IsNullOrWhiteSpace($Version)) {
    Write-Host "Resolving latest release..."
    $Version = Get-LatestRelease -Owner $Owner -Repo $Repo
    if (-not $Version) {
        throw "Could not determine the latest release for $Owner/$Repo."
    }
}

# --- Detect platform ---------------------------------------------------------
$arch = Get-Architecture
$target = "$arch-pc-windows-msvc"
$asset = "$Bin-$Version-$target.zip"
$url = "https://github.com/$Owner/$Repo/releases/download/$Version/$asset"

Write-Host "Installing $Bin $Version for $target" -ForegroundColor Cyan

# --- Prepare install directory -----------------------------------------------
$installDir = Get-InstallDirectory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# --- Download and extract ----------------------------------------------------
$tmp = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $archive = Join-Path $tmp $asset
    Write-Host "Downloading $asset..."
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing

    Write-Host "Extracting..."
    Expand-Archive -Path $archive -DestinationPath $tmp -Force

    $exe = "$Bin.exe"
    $extracted = Join-Path $tmp $exe
    if (-not (Test-Path $extracted)) {
        throw "Expected binary '$exe' not found in the downloaded archive."
    }

    $destination = Join-Path $installDir $exe
    Copy-Item -Path $extracted -Destination $destination -Force
    Write-Host "Installed: $destination" -ForegroundColor Green
}
finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Update PATH -------------------------------------------------------------
if (-not $NoModifyPath) {
    Add-ToPath -Directory $installDir
}

# --- Verify ------------------------------------------------------------------
$installed = Join-Path $installDir "$Bin.exe"
& $installed --version
Write-Host "Done." -ForegroundColor Green

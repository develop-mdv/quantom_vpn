param(
    [string]$Configuration = "Release",
    [switch]$SkipDependencyInstall,
    [switch]$SkipRustBuild,
    [switch]$NoAutostart,
    [string]$Target = "",
    [string]$ArtifactsRoot = "",
    [string]$RustTargetDir = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageScript = Join-Path $RepoRoot "omega-client-app/package-windows-client.ps1"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message"
}

function Test-CommandAvailable {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Refresh-ProcessPath {
    $parts = @(
        (Join-Path $env:ProgramFiles "dotnet"),
        (Join-Path $env:USERPROFILE ".cargo\bin"),
        [Environment]::GetEnvironmentVariable("Path", "Machine"),
        [Environment]::GetEnvironmentVariable("Path", "User"),
        $env:Path
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $env:Path = ($parts -join ";")
}

function Assert-Windows {
    if ($env:OS -ne "Windows_NT") {
        throw "This installer bootstrap is intended for Windows."
    }
}

function Assert-Winget {
    if (-not (Test-CommandAvailable "winget")) {
        throw "winget is required for automatic dependency installation. Install App Installer from Microsoft Store, or rerun with -SkipDependencyInstall after installing dependencies manually."
    }
}

function Install-WingetPackage {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Override = ""
    )

    Write-Step "Installing $Name with winget"
    $args = @(
        "install",
        "--id", $Id,
        "--exact",
        "--source", "winget",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        $args += @("--override", $Override)
    } else {
        $args += "--silent"
    }

    & winget @args
    if ($LASTEXITCODE -ne 0) {
        throw "winget install failed for $Name with exit code $LASTEXITCODE."
    }

    Refresh-ProcessPath
}

function Join-ProcessArguments {
    param([string[]]$Arguments)

    return (($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_.Replace('"', '\"')) + '"'
        } else {
            $_
        }
    }) -join " ")
}

function Test-DotNet9Sdk {
    if (-not (Test-CommandAvailable "dotnet")) {
        return $false
    }

    $sdks = & dotnet --list-sdks 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return $null -ne ($sdks | Where-Object { $_ -match "^9\." } | Select-Object -First 1)
}

function Ensure-DotNet9Sdk {
    if (Test-DotNet9Sdk) {
        Write-Host "Found .NET 9 SDK."
        return
    }

    if ($SkipDependencyInstall) {
        throw ".NET 9 SDK is missing. Install Microsoft.DotNet.SDK.9 or rerun without -SkipDependencyInstall."
    }

    Assert-Winget
    Install-WingetPackage -Id "Microsoft.DotNet.SDK.9" -Name ".NET 9 SDK"

    if (-not (Test-DotNet9Sdk)) {
        throw ".NET 9 SDK still was not found after installation. Open a new PowerShell window and rerun this script."
    }
}

function Ensure-Rust {
    $hasCargo = Test-CommandAvailable "cargo"
    $hasRustup = Test-CommandAvailable "rustup"

    if (-not $hasCargo -or -not $hasRustup) {
        if ($SkipDependencyInstall) {
            throw "Rust toolchain is missing. Install Rustlang.Rustup or rerun without -SkipDependencyInstall."
        }

        Assert-Winget
        Install-WingetPackage -Id "Rustlang.Rustup" -Name "Rustup"
        $hasCargo = Test-CommandAvailable "cargo"
        $hasRustup = Test-CommandAvailable "rustup"
    }

    if ($hasRustup) {
        Write-Step "Ensuring Rust stable MSVC toolchain"
        & rustup toolchain install stable-x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) {
            throw "rustup toolchain install failed with exit code $LASTEXITCODE."
        }

        & rustup default stable-x86_64-pc-windows-msvc
        if ($LASTEXITCODE -ne 0) {
            throw "rustup default failed with exit code $LASTEXITCODE."
        }
    }

    Refresh-ProcessPath
    if (-not (Test-CommandAvailable "cargo")) {
        throw "cargo was not found after Rust setup. Open a new PowerShell window and rerun this script."
    }

    $rustVersion = & rustc -vV
    if ($LASTEXITCODE -ne 0) {
        throw "rustc is not available."
    }

    if (($rustVersion -join "`n") -notmatch "host: x86_64-pc-windows-msvc") {
        throw "Omega Windows builds require the stable-x86_64-pc-windows-msvc Rust toolchain."
    }
}

function Get-VsWherePath {
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ([string]::IsNullOrWhiteSpace($programFilesX86)) {
        return ""
    }

    return Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
}

function Test-VctoolsInstalled {
    $vswhere = Get-VsWherePath
    if ([string]::IsNullOrWhiteSpace($vswhere) -or -not (Test-Path $vswhere)) {
        return $false
    }

    $installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    return $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($installation | Select-Object -First 1))
}

function Ensure-Vctools {
    if (Test-VctoolsInstalled) {
        Write-Host "Found Visual Studio C++ Build Tools."
        return
    }

    if ($SkipDependencyInstall) {
        throw "Visual Studio C++ Build Tools are missing. Install Microsoft.VisualStudio.2022.BuildTools with the VCTools workload or rerun without -SkipDependencyInstall."
    }

    Assert-Winget
    Install-WingetPackage `
        -Id "Microsoft.VisualStudio.2022.BuildTools" `
        -Name "Visual Studio 2022 Build Tools" `
        -Override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --norestart"

    if (-not (Test-VctoolsInstalled)) {
        throw "Visual Studio C++ Build Tools still were not found after installation. Reboot if the installer requested it, then rerun this script."
    }
}

function Invoke-PackageBuild {
    if (-not (Test-Path $PackageScript)) {
        throw "Package script not found: $PackageScript"
    }

    $args = @("-Configuration", $Configuration)
    if ($SkipRustBuild) {
        $args += "-SkipRustBuild"
    }
    if (-not [string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
        $args += @("-ArtifactsRoot", $ArtifactsRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($RustTargetDir)) {
        $args += @("-RustTargetDir", $RustTargetDir)
    }

    Write-Step "Building Windows client package"
    & $PackageScript @args
    if ($LASTEXITCODE -ne 0) {
        throw "Windows client packaging failed with exit code $LASTEXITCODE."
    }
}

function Get-InstallerRoot {
    if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
        return Join-Path $RepoRoot "omega-client-app\artifacts\windows-client\installer"
    }

    if ([System.IO.Path]::IsPathRooted($ArtifactsRoot)) {
        return Join-Path $ArtifactsRoot "installer"
    }

    return Join-Path (Join-Path $RepoRoot $ArtifactsRoot) "installer"
}

function Invoke-Setup {
    $installerRoot = Get-InstallerRoot
    $setupExe = Join-Path $installerRoot "Omega.Client.Setup.exe"
    if (-not (Test-Path $setupExe)) {
        throw "Setup executable not found: $setupExe"
    }

    $setupLog = Join-Path $installerRoot "OmegaVPN-setup.log"
    $hostTraceLog = Join-Path $installerRoot "OmegaVPN-corehost.log"
    $stdoutLog = Join-Path $installerRoot "OmegaVPN-stdout.log"
    $stderrLog = Join-Path $installerRoot "OmegaVPN-stderr.log"
    Remove-Item -LiteralPath $setupLog -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $hostTraceLog -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stdoutLog -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stderrLog -Force -ErrorAction SilentlyContinue

    $args = @("--log", $setupLog)
    if ($NoAutostart) {
        $args += "--no-autostart"
    }
    if (-not [string]::IsNullOrWhiteSpace($Target)) {
        $args += @("--target", $Target)
    }

    Write-Step "Launching Omega VPN setup"
    $previousCoreHostTrace = $env:COREHOST_TRACE
    $previousCoreHostTraceFile = $env:COREHOST_TRACEFILE
    $previousCoreHostTraceVerbosity = $env:COREHOST_TRACE_VERBOSITY
    try {
        $env:COREHOST_TRACE = "1"
        $env:COREHOST_TRACEFILE = $hostTraceLog
        $env:COREHOST_TRACE_VERBOSITY = "4"
        $process = Start-Process `
            -FilePath $setupExe `
            -ArgumentList (Join-ProcessArguments $args) `
            -RedirectStandardOutput $stdoutLog `
            -RedirectStandardError $stderrLog `
            -Wait `
            -PassThru
    } finally {
        $env:COREHOST_TRACE = $previousCoreHostTrace
        $env:COREHOST_TRACEFILE = $previousCoreHostTraceFile
        $env:COREHOST_TRACE_VERBOSITY = $previousCoreHostTraceVerbosity
    }
    if ($process.ExitCode -ne 0) {
        $diagnostics = @()
        foreach ($logPath in @($setupLog, $hostTraceLog, $stdoutLog, $stderrLog)) {
            if (Test-Path -LiteralPath $logPath) {
                $diagnostics += "--- $logPath ---"
                $diagnostics += (Get-Content -LiteralPath $logPath -Raw)
            } else {
                $diagnostics += "Diagnostic log was not created: $logPath"
            }
        }
        throw "Omega VPN setup failed with exit code $($process.ExitCode).`n$($diagnostics -join [Environment]::NewLine)"
    }
}

Assert-Windows
Set-Location $RepoRoot
Refresh-ProcessPath

Write-Step "Checking Windows client build dependencies"
Ensure-DotNet9Sdk
if ($SkipRustBuild) {
    Write-Host "Skipping Rust and C++ Build Tools checks because -SkipRustBuild was supplied."
} else {
    Ensure-Rust
    Ensure-Vctools
}

Invoke-PackageBuild
Invoke-Setup

Write-Host ""
Write-Host "Omega VPN setup finished. Start Omega VPN from the Desktop or Start menu shortcut, then paste your omega://connect/... code."

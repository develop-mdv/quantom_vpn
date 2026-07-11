param(
    [string]$Configuration = "Release",
    [switch]$SkipRustBuild,
    [string]$ArtifactsRoot = "",
    [string]$RustTargetDir = ""
)

$ErrorActionPreference = "Stop"

$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $AppRoot
if ([string]::IsNullOrWhiteSpace($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $AppRoot "artifacts\windows-client"
} elseif (-not [System.IO.Path]::IsPathRooted($ArtifactsRoot)) {
    $ArtifactsRoot = Join-Path $RepoRoot $ArtifactsRoot
}
$PortableRoot = Join-Path $ArtifactsRoot "portable\OmegaVPN"
$PortableBuildRoot = Join-Path $ArtifactsRoot (".portable-build-" + [Guid]::NewGuid().ToString("N"))
$InstallerRoot = Join-Path $ArtifactsRoot "installer"
$PayloadRoot = Join-Path $InstallerRoot "payload"
$DotnetHome = Join-Path $RepoRoot ".dotnet-home"
$UserProfile = Join-Path $DotnetHome "userprofile"

function Remove-BuildDirectory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $attempts = 5
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($attempt -eq $attempts) {
                throw "Unable to clean build directory after $attempts attempts: $Path. Close any app using this folder and retry. $($_.Exception.Message)"
            }

            Start-Sleep -Milliseconds (250 * $attempt)
        }
    }
}

New-Item -ItemType Directory -Force `
    $ArtifactsRoot, `
    $InstallerRoot, `
    (Join-Path $UserProfile "AppData\Local"), `
    (Join-Path $UserProfile "AppData\Roaming"), `
    (Join-Path $RepoRoot ".nuget-packages") | Out-Null

if (-not $SkipRustBuild) {
    Push-Location $RepoRoot
    $previousCargoTargetDir = $env:CARGO_TARGET_DIR
    try {
        if (-not [string]::IsNullOrWhiteSpace($RustTargetDir)) {
            if (-not [System.IO.Path]::IsPathRooted($RustTargetDir)) {
                $RustTargetDir = Join-Path $RepoRoot $RustTargetDir
            }
            $env:CARGO_TARGET_DIR = $RustTargetDir
        }
        cargo build --release -p omega-client
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE"
        }
    } finally {
        $env:CARGO_TARGET_DIR = $previousCargoTargetDir
        Pop-Location
    }
}

$EnvironmentVariableNames = @(
    "USERPROFILE",
    "DOTNET_CLI_HOME",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE",
    "DOTNET_CLI_TELEMETRY_OPTOUT",
    "LOCALAPPDATA",
    "APPDATA",
    "NUGET_PACKAGES"
)
$PreviousProcessEnvironment = @{}
foreach ($name in $EnvironmentVariableNames) {
    $PreviousProcessEnvironment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        [EnvironmentVariableTarget]::Process)
}

try {
    $env:USERPROFILE = $UserProfile
    $env:DOTNET_CLI_HOME = $DotnetHome
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"
    $env:LOCALAPPDATA = Join-Path $UserProfile "AppData\Local"
    $env:APPDATA = Join-Path $UserProfile "AppData\Roaming"
    $env:NUGET_PACKAGES = Join-Path $RepoRoot ".nuget-packages"

if (-not [string]::IsNullOrWhiteSpace($RustTargetDir)) {
    if (-not [System.IO.Path]::IsPathRooted($RustTargetDir)) {
        $RustTargetDir = Join-Path $RepoRoot $RustTargetDir
    }
    $RuntimeExe = Join-Path $RustTargetDir "release\omega-client.exe"
} else {
    $RuntimeExe = Join-Path $RepoRoot "target\release\omega-client.exe"
}
if (-not (Test-Path $RuntimeExe)) {
    throw "Missing runtime binary: $RuntimeExe. Run cargo build --release -p omega-client or rerun without -SkipRustBuild."
}

$Wintun = Join-Path $RepoRoot "wintun.dll"
if (-not (Test-Path $Wintun)) {
    throw "Missing wintun.dll in repository root."
}

$AppPublish = Join-Path $ArtifactsRoot "publish-app"
$SetupPublish = Join-Path $ArtifactsRoot "publish-setup"
foreach ($path in @($AppPublish, $SetupPublish, $InstallerRoot)) {
    Remove-BuildDirectory $path
}
New-Item -ItemType Directory -Force $PortableBuildRoot, $InstallerRoot, $PayloadRoot | Out-Null

dotnet publish (Join-Path $AppRoot "src\Omega.Client.App\Omega.Client.App.csproj") `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -o $AppPublish
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish Omega.Client.App failed with exit code $LASTEXITCODE"
}

dotnet publish (Join-Path $AppRoot "src\Omega.Client.Setup\Omega.Client.Setup.csproj") `
    -c $Configuration `
    -r win-x64 `
    --self-contained true `
    -o $SetupPublish
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish Omega.Client.Setup failed with exit code $LASTEXITCODE"
}

foreach ($publishDir in @($AppPublish, $SetupPublish)) {
    foreach ($runtimeFile in @("hostfxr.dll", "hostpolicy.dll", "coreclr.dll")) {
        if (-not (Test-Path (Join-Path $publishDir $runtimeFile))) {
            throw "Self-contained publish is missing $runtimeFile in $publishDir"
        }
    }
}

Copy-Item -Recurse -Force (Join-Path $AppPublish "*") $PortableBuildRoot
Copy-Item -Force $RuntimeExe (Join-Path $PortableBuildRoot "omega-client.exe")
Copy-Item -Force $Wintun (Join-Path $PortableBuildRoot "wintun.dll")

@"
# Omega VPN Portable

Run `Omega.Client.App.exe` as administrator.

Required fields:
- connection code

The code can be an omega://connect/... link or pasted OMEGA_* env text.
Saved connections can be selected from the profile list later.

Portable runs store runtime state in `omega-client\state`.
The installed app stores profiles and runtime state in `%LocalAppData%\Omega VPN\state`
so reinstalling or updating program files does not remove saved connections.

No separate .NET Desktop Runtime install is required.

If the VPN is active, closing the main window hides Omega VPN to the Windows tray.
"@ | Set-Content -Encoding UTF8 (Join-Path $PortableBuildRoot "README.txt")

Copy-Item -Recurse -Force (Join-Path $PortableBuildRoot "*") $PayloadRoot
$BundledConfigs = @(Get-ChildItem -Path $PayloadRoot -Recurse -File -Filter "app-config*.json")
if ($BundledConfigs.Count -gt 0) {
    throw "Unsafe installer payload: user app-config.json must never be bundled."
}
Copy-Item -Recurse -Force (Join-Path $SetupPublish "*") $InstallerRoot

    $PortableOutput = $PortableRoot
    try {
        Remove-BuildDirectory $PortableRoot
        New-Item -ItemType Directory -Force (Split-Path -Parent $PortableRoot) | Out-Null
        Move-Item -LiteralPath $PortableBuildRoot -Destination $PortableRoot
    } catch {
        $PortableOutput = $PortableBuildRoot
        Write-Warning "Portable output is in use and was not replaced. The installer is current and safe to use. New portable output: $PortableOutput"
    }

    Write-Host "Portable: $PortableOutput"
    Write-Host "Installer: $InstallerRoot"
} finally {
    foreach ($name in $EnvironmentVariableNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $PreviousProcessEnvironment[$name],
            [EnvironmentVariableTarget]::Process)
    }
}

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
$InstallerRoot = Join-Path $ArtifactsRoot "installer"
$PayloadRoot = Join-Path $InstallerRoot "payload"
$DotnetHome = Join-Path $RepoRoot ".dotnet-home"
$UserProfile = Join-Path $DotnetHome "userprofile"

New-Item -ItemType Directory -Force `
    $ArtifactsRoot, `
    $PortableRoot, `
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
$ExistingConfig = Join-Path $PortableRoot "omega-client\state\app-config.json"
$PreservedConfig = Join-Path $ArtifactsRoot "app-config.preserve.json"
if (Test-Path $ExistingConfig) {
    New-Item -ItemType Directory -Force $ArtifactsRoot | Out-Null
    Copy-Item -Force $ExistingConfig $PreservedConfig
}
Remove-Item -Recurse -Force $AppPublish, $SetupPublish, $PortableRoot, $PayloadRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $PortableRoot, $PayloadRoot | Out-Null

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

Copy-Item -Recurse -Force (Join-Path $AppPublish "*") $PortableRoot
Copy-Item -Force $RuntimeExe (Join-Path $PortableRoot "omega-client.exe")
Copy-Item -Force $Wintun (Join-Path $PortableRoot "wintun.dll")
New-Item -ItemType Directory -Force (Join-Path $PortableRoot "omega-client\state") | Out-Null
if (Test-Path $PreservedConfig) {
    Copy-Item -Force $PreservedConfig (Join-Path $PortableRoot "omega-client\state\app-config.json")
    Remove-Item -Force $PreservedConfig -ErrorAction SilentlyContinue
}

@"
# Omega VPN Portable

Run `Omega.Client.App.exe` as administrator.

Required fields:
- server endpoint
- device id
- device token

The app stores runtime state in `omega-client\state`.

No separate .NET Desktop Runtime install is required.

If the VPN is active, closing the main window hides Omega VPN to the Windows tray.
"@ | Set-Content -Encoding UTF8 (Join-Path $PortableRoot "README.txt")

Copy-Item -Recurse -Force (Join-Path $PortableRoot "*") $PayloadRoot
Copy-Item -Recurse -Force (Join-Path $SetupPublish "*") $InstallerRoot

Write-Host "Portable: $PortableRoot"
Write-Host "Installer: $InstallerRoot"

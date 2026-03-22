@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"

REM 1) Elevate to Administrator (required for Wintun and routing)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM 2) Load .env file if present
if exist ".env" (
    echo [INFO] Loading environment from .env
    for /f "usebackq tokens=* delims=" %%L in (".env") do (
        set "line=%%L"
        if not "!line!"=="" (
            if not "!line:~0,1!"=="#" (
                for /f "tokens=1,* delims==" %%A in ("!line!") do (
                    set "key=%%A"
                    set "val=%%B"
                    if defined key (
                        if defined val (
                            if "!val:~0,1!"=="\"" if "!val:~-1!"=="\"" set "val=!val:~1,-1!"
                        )
                        set "!key!=!val!"
                    )
                )
            )
        )
    )
) else (
    echo [WARN] .env not found. You can copy .env.example to .env
)

REM 3) Validate required variables
if "%OMEGA_SERVER%"=="" (
    echo [ERROR] OMEGA_SERVER is required.
    goto :show_help
)
if "%OMEGA_DEVICE_ID%"=="" (
    echo [ERROR] OMEGA_DEVICE_ID is required.
    goto :show_help
)
if "%OMEGA_DEVICE_TOKEN%"=="" (
    echo [ERROR] OMEGA_DEVICE_TOKEN is required.
    goto :show_help
)
if "%OMEGA_DEVICE_NAME%"=="" set "OMEGA_DEVICE_NAME=%COMPUTERNAME%"
if "%OMEGA_PLATFORM%"=="" set "OMEGA_PLATFORM=windows"

REM 4) Ensure wintun.dll exists
if not exist "wintun.dll" (
    echo [WARN] wintun.dll not found, downloading...
    powershell -Command "Invoke-WebRequest -Uri https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile wintun.zip"
    if errorlevel 1 goto :download_failed
    powershell -Command "Expand-Archive wintun.zip -DestinationPath wintun_temp -Force"
    if errorlevel 1 goto :download_failed
    copy /Y wintun_temp\wintun\bin\amd64\wintun.dll . >nul
    rmdir /s /q wintun_temp >nul 2>&1
    del /q wintun.zip >nul 2>&1
)

REM 5) Start client
echo [INFO] Starting Omega VPN client
echo [INFO] Server: %OMEGA_SERVER%
echo [INFO] Device ID: %OMEGA_DEVICE_ID%
echo [INFO] Device Name: %OMEGA_DEVICE_NAME%

if exist "omega-client.exe" (
    omega-client.exe
) else if exist "Cargo.toml" (
    cargo run --release -p omega-client
) else (
    echo [ERROR] omega-client.exe and Cargo.toml not found.
    goto :show_help
)

goto :end

:download_failed
echo [ERROR] Failed to download/setup wintun.dll
pause
goto :end

:show_help
echo.
echo Required variables:
echo   OMEGA_SERVER=host:port
echo   OMEGA_DEVICE_ID=uuid
echo   OMEGA_DEVICE_TOKEN=hex_token
echo Optional:
echo   OMEGA_DEVICE_NAME=my-laptop

echo   OMEGA_PLATFORM=windows
echo   OMEGA_DNS_SERVERS=1.1.1.1,8.8.8.8
echo   OMEGA_DISABLE_IPV6=1
echo   OMEGA_NETWORK_DIAG=1

echo.
echo Example .env:
echo   OMEGA_SERVER=203.0.113.1:51820
echo   OMEGA_DEVICE_ID=11111111-2222-3333-4444-555555555555
echo   OMEGA_DEVICE_TOKEN=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
echo   OMEGA_DEVICE_NAME=home-pc
echo   OMEGA_DNS_SERVERS=1.1.1.1,8.8.8.8
echo   OMEGA_DISABLE_IPV6=1
echo   OMEGA_NETWORK_DIAG=1
pause
goto :end

:end
endlocal

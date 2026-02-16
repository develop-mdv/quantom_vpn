@echo off
setlocal enabledelayedexpansion
:: Установка кодировки UTF-8
chcp 65001 >nul

:: ==========================================
:: 0. Проверка прав Администратора (Auto-Elevate)
:: ==========================================
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [INFO] Запрашиваю права администратора для работы с Wintun...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

:: Настройка адреса сервера

:: Настройка адреса сервера
:: Замените 127.0.0.1 на IP вашего VPS
if "%OMEGA_SERVER%"=="" set OMEGA_SERVER=127.0.0.1:51820

echo [INFO] Запуск Omega VPN Клиента...
echo [INFO] Сервер: %OMEGA_SERVER%
echo.

:: 1. Проверка наличия Wintun
if not exist "wintun.dll" (
    echo [WARNING] Файл wintun.dll не найден!
    echo [INFO] Для работы нужен драйвер Wintun. Скачиваю автоматически...
    powershell -Command "Invoke-WebRequest -Uri https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile wintun.zip"
    powershell -Command "Expand-Archive wintun.zip -DestinationPath wintun_temp"
    copy wintun_temp\wintun\bin\amd64\wintun.dll . >nul
    rmdir /s /q wintun_temp
    del wintun.zip
    echo [INFO] wintun.dll успешно загружен.
)

:: 2. Поиск исполняемого файла или исходников
if exist "omega-client.exe" (
    echo [INFO] Нашел omega-client.exe, запускаю напрямую...
    omega-client.exe
) else if exist "Cargo.toml" (
    echo [INFO] Исходный код найден, компилирую и запускаю через Cargo...
    cargo run --release -p omega-client
) else (
    echo [ERROR] Не найден ни omega-client.exe, ни Cargo.toml!
    echo [HELP] Вы скопировали только bat-файл?
    echo [HELP] 1. Если у вас есть исходники: запускайте скрипт из папки проекта.
    echo [HELP] 2. Если вы хотите перенести клиент: скопируйте файл 
    echo [HELP]    target/release/omega-client.exe в эту папку вместе с start_client.bat.
    echo.
)

pause

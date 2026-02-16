@echo off
setlocal
:: Укажите IP вашего сервера и порт (см. DEPLOY.md)
:: Если сервер локальный, оставьте 127.0.0.1
set OMEGA_SERVER=127.0.0.1:51820

echo [INFO] Запуск Omega VPN Клиента...
echo [INFO] Сервер: %OMEGA_SERVER%
echo.

:: Проверка наличия Wintun
if not exist "wintun.dll" (
    echo [WARNING] Файл wintun.dll не найден!
    echo [INFO] Для работы на Windows необходим драйвер Wintun.
    echo [INFO] Скачайте его с https://www.wintun.net/ и положите wintun.dll рядом с этим скриптом.
    echo.
    echo [INFO] Пытаюсь скачать wintun.dll автоматически...
    powershell -Command "Invoke-WebRequest -Uri https://www.wintun.net/builds/wintun-0.14.1.zip -OutFile wintun.zip"
    powershell -Command "Expand-Archive wintun.zip -DestinationPath wintun_temp"
    copy wintun_temp\wintun\bin\amd64\wintun.dll .
    rmdir /s /q wintun_temp
    del wintun.zip
    echo [INFO] Готово.
)

:: Запуск клиента
cargo run --release -p omega-client

pause

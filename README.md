# Omega VPN

`Omega VPN` - Rust workspace с собственным UDP-туннелем, STUN/RTP cover traffic, post-quantum handshake, device-based auth и встроенными runtime/admin surface-ами.

## Скачать клиент

Готовые пакеты доступны в [последнем релизе](https://github.com/develop-mdv/quantom_vpn/releases/latest):

| Платформа | Скачать | Как установить |
| --- | --- | --- |
| Windows x64 | [Установщик ZIP](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-windows-x64-setup.zip) | Распакуйте **весь архив** и запустите `Omega.Client.Setup.exe`. Соседние файлы и папка `payload` нужны установщику. |
| Windows x64 portable | [Portable ZIP](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-windows-x64-portable.zip) | Распакуйте и запустите `Omega.Client.App.exe` от администратора. |
| Android 6.0+ (ARM64 / x86_64) | [Тестовый APK](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-android-debug.apk) | Скачайте на телефон, разрешите установку из выбранного источника и откройте APK. |

На Windows отдельно ставить Rust или .NET не нужно. После установки вставьте
код `omega://connect/...`, выданный для вашего устройства в админке сервера.
Android APK пока debug-сборка с тестовой подписью; при смене подписи обновление
потребует удаления старой тестовой версии. Клиента для iOS в проекте пока нет.

## Быстрый старт: установка сервера

На Debian 12+ / Ubuntu 22.04+ с systemd и доступным TUN выполните от root
(`sudo -i`, если вошли обычным пользователем):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh)
```

Чтобы установить конкретную версию, добавьте её тег (например, `v0.1.0`):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh) v0.1.0
```

Скрипт скачивает готовый Linux-сервер для x86_64 или ARM64 из GitHub Releases,
проверяет SHA-256, устанавливает зависимости, настраивает NAT и запускает
службу `omega-server`. Rust и сборка на VPS не нужны.
При повторном запуске сохраняются `/opt/omega/state` и существующие настройки
`/etc/default/omega-server`.

По умолчанию VPN использует **443/UDP и 443/TCP**, IPv6 внутри туннеля отключён.
Разрешите эти порты также в сетевом экране хостинга. Для IPv6 задайте
`OMEGA_IPV6_MODE=nat66` в `/etc/default/omega-server` и повторите установку
на VPS с работающим внешним IPv6.
SSH-порт определяется из текущего подключения; при необходимости укажите его
явно: `OMEGA_SSH_PORT=2222 bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh)`.

После установки укажите публичный адрес VPS для генерации кодов подключения.
Добавьте в `/etc/default/omega-server` строку ниже, заменив `203.0.113.1`
на IP или домен своего сервера, затем перезапустите службу:

```ini
OMEGA_CLIENT_SERVER=203.0.113.1:443
```

```bash
systemctl restart omega-server
```

Если строка уже существует, измените её. Без этой настройки коды подключения
будут содержать placeholder `<SERVER_IP>`.

Админка новой установки слушает `127.0.0.1:8081`. Откройте SSH-туннель на своём ПК:

```bash
ssh -N -L 8081:127.0.0.1:8081 root@<server_ip>
```

Для нестандартного SSH-порта добавьте `-p 2222`.
Затем откройте `http://127.0.0.1:8081`, создайте пользователя и устройство,
скопируйте код подключения в клиент. У админки пока нет авторизации, поэтому
её следует использовать через SSH-туннель. При обновлении существующая
конфигурация доступа к админке сохраняется.

Состояние и логи:

```bash
systemctl status omega-server
journalctl -u omega-server -f
```

## Что уже есть в проекте

- `omega-core`: wire protocol, crypto, anti-replay, ARQ, chaos-based packet morphing, FEC primitives.
- `omega-server`: UDP server runtime, TUN, identity store, session manager, web admin, metrics, snapshots.
- `omega-client`: client runtime, dual-stack handshake/TUN, Windows/Linux/macOS routing and DNS orchestration, diagnostics.
- `omega-client-app`: Windows GUI поверх `omega-client.exe`, portable package и setup package.

## Важная честная оговорка по текущему состоянию

Сейчас проект нужно воспринимать так:

- это **не** WireGuard и не OpenVPN, а собственный `Omega` protocol;
- datapath по умолчанию **UDP-first**, плюс есть framed TCP fallback для `OMEGA_TRANSPORT=tcp|auto`;
- tunnel family теперь умеет **dual-stack IPv4 + IPv6** при `OMEGA_IPV6_MODE=nat66` на сервере и `OMEGA_IPV6_POLICY=tunnel` на клиенте;
- client networking теперь сам ставит и убирает dual-stack full/split routes на Windows, Linux и macOS;
- рабочая надежность сегодня строится вокруг **ARQ/NACK + retransmit cache + adaptive redundancy**;
- в кодовой базе уже есть `RaptorQ/FEC` примитивы, но полноценный FEC packet path пока не доведен до живого runtime.

## Документация

Основная база знаний теперь лежит в `docs/`:

- `docs/README.md` - навигация по документации.
- `docs/PROJECT_CONTEXT.md` - короткий контекст проекта для быстрых обсуждений.
- `docs/ARCHITECTURE.md` - handshake, datapath, identity, sessions, observability.
- `docs/CONFIG_REFERENCE.md` - все важные `OMEGA_*` переменные и defaults.
- `docs/OPERATIONS.md` - запуск, администрирование, диагностика, deploy, GitHub Actions.
- `docs/REPO_MAP.md` - карта репозитория и где лежит какая логика.

Специализированные материалы:

- `docs/GAMING_NETWORKING.md`
- `DEPLOY.md`
- `resource_budget.md`

## Запуск из исходного кода

### 1. Создать пользователя

```bash
cargo run -p omega-server -- admin create_user --max-devices 5 --max-sessions 3
```

### 2. Зарегистрировать устройство

```bash
cargo run -p omega-server -- admin register_device \
  --user-id <user_uuid> \
  --device-name "laptop" \
  --platform windows
```

Для Windows GUI используйте `connection_code` из вывода команды или скопируйте
его позже из карточки устройства во встроенной web-админке. Там же доступен
`OMEGA_DEVICE_TOKEN` для ручной настройки.

### 3. Запустить сервер

```bash
cargo run -p omega-server
```

### 4. Запустить клиент

```bash
OMEGA_SERVER=<server_ip>:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME="laptop" \
cargo run -p omega-client
```

### Windows GUI

Для обычного пользователя есть WPF-клиент:

```powershell
powershell -ExecutionPolicy Bypass -File omega-client-app/package-windows-client.ps1
```

Пользователь вставляет один `omega://connect/...` код в клиент, а дальше
выбирает сохраненный профиль из списка.

Артефакты:

- `omega-client-app/artifacts/windows-client/portable/OmegaVPN` - portable-папка для тестов.
- `omega-client-app/artifacts/windows-client/installer` - setup package с `Omega.Client.Setup.exe` и `payload/`.

Для ручного прикрепления к релизу упакуйте **всё содержимое** `installer`
в `OmegaVPN-windows-x64-setup.zip`. Отдельный `Omega.Client.Setup.exe`
не является автономным установщиком.
Android APK после `cd omega-android && ./gradlew :app:assembleDebug` находится
в `omega-android/app/build/outputs/apk/debug/app-debug.apk`.
Старый `omega-android/omega-vpn-reality-debug.apk` — сохранённая ранее сборка;
для релиза используйте APK, заново собранный из нужного тега.

Workflow [Release Omega VPN](.github/workflows/release.yml) при отправке тега
`vX.Y.Z` собирает Windows, Android и серверы Linux, выполняет проверки и
публикует релиз со всеми пакетами и `SHA256SUMS`. Перед тегом добавьте
заметки о версии в `docs/releases/vX.Y.Z.md`. Подробности —
в [инструкции по релизу](docs/RELEASING.md).

GUI требует права администратора, как и `start_client.bat`, потому что Windows-клиент управляет Wintun, routes, DNS и kill switch.

Установленная версия хранит сохранённые подключения отдельно от файлов программы
в `%LocalAppData%\Omega VPN\state`. При обновлении setup корректно останавливает
запущенный клиент, сначала пытается атомарно заменить каталог программы и
сохраняет профили. Если Windows запрещает переименование каталога в
`Program Files`, используется in-place обновление с временным backup и
восстановлением старой версии при ошибке.
Повторный запуск ярлыка не создаёт второе окно, а открывает уже работающий клиент.

## Ключевые runtime-файлы

- `state/identity.json` - users/devices/audit
- `state/sessions.json` - активные сессии
- `state/runtime.json` - runtime snapshot сервера
- `state/admin_commands.ndjson` - очередь admin-команд
- `omega-client/state/diagnostics.json` - diagnostics snapshot клиента

## Для следующей работы по проекту

Если нужно быстро включиться в разработку или обсуждение, лучший маршрут такой:

1. `docs/PROJECT_CONTEXT.md`
2. `docs/ARCHITECTURE.md`
3. `docs/REPO_MAP.md`
4. `docs/CONFIG_REFERENCE.md` или `docs/OPERATIONS.md` по ситуации

## Windows: простая установка клиента одной командой

Из PowerShell в корне репозитория:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1
```

Скрипт проверит и при необходимости поставит через `winget` нужные зависимости
для сборки Windows-клиента:

- `.NET 9 SDK` (`Microsoft.DotNet.SDK.9`);
- `Rustup` со stable MSVC toolchain (`stable-x86_64-pc-windows-msvc`);
- `Visual Studio 2022 Build Tools` с C++ workload.

После этого он соберет `omega-client.exe`, опубликует self-contained WPF-клиент,
создаст installer package и запустит `Omega.Client.Setup.exe`. Установщик
попросит права администратора, скопирует Omega VPN в `%ProgramFiles%\Omega VPN`,
создаст ярлыки и включит автозапуск при входе в Windows.

После установки откройте `Omega VPN` с рабочего стола или из меню Start и
вставьте свой `omega://connect/...` код подключения.

Перед первым обновлением со старой версии закройте через системный трей все
старые и portable-копии Omega VPN. После перехода на новую версию последующие
обновления смогут штатно остановить установленный клиент автоматически.

Если setup завершился с `exit code 1`, полный тип исключения, inner exception и
stack trace выводятся корневым скриптом. Логи `OmegaVPN-setup.log` и
`OmegaVPN-corehost.log` сохраняются рядом с `Omega.Client.Setup.exe`, поэтому
они доступны даже при запуске UAC под другой учётной записью администратора.
Дополнительно сохраняются `OmegaVPN-stdout.log` и `OmegaVPN-stderr.log`.
PowerShell можно запускать без прав администратора: если Windows возвращает
`ERROR_ELEVATION_REQUIRED`, bootstrap автоматически повторяет setup через UAC.

Полезные варианты:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -SkipDependencyInstall
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -SkipRustBuild
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -NoAutostart
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -Target "D:\Apps\Omega VPN"
```

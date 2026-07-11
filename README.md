# Omega VPN

`Omega VPN` - Rust workspace с собственным UDP-туннелем, STUN/RTP cover traffic, post-quantum handshake, device-based auth и встроенными runtime/admin surface-ами.

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

## Быстрый старт

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

Полезные варианты:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -SkipDependencyInstall
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -SkipRustBuild
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -NoAutostart
powershell -ExecutionPolicy Bypass -File .\install-windows-client.ps1 -Target "D:\Apps\Omega VPN"
```

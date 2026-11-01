# Omega VPN

`Omega VPN` - Rust workspace с собственным UDP-туннелем, STUN/RTP cover traffic, post-quantum handshake, device-based auth и встроенными runtime/admin surface-ами.

## Скачать клиент

Готовые пакеты доступны в [последнем релизе](https://github.com/develop-mdv/quantom_vpn/releases/latest):

| Платформа | Скачать | Как установить |
| --- | --- | --- |
| Windows x64 | [Установщик EXE](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-windows-x64-setup.exe) | Скачайте один файл и запустите. Всё необходимое уже внутри; setup запросит права администратора. |
| Windows x64 portable | [Portable ZIP](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-windows-x64-portable.zip) | Распакуйте и запустите `Omega.Client.App.exe` от администратора. |
| Android 6.0+ (ARM64 / x86_64) | [Тестовый APK](https://github.com/develop-mdv/quantom_vpn/releases/latest/download/OmegaVPN-android-debug.apk) | Скачайте на телефон, разрешите установку из выбранного источника и откройте APK. |

На Windows отдельно ставить Rust или .NET не нужно. После установки вставьте
код `omega://connect/...`, выданный для вашего устройства в админке сервера.
Android APK пока debug-сборка с тестовой подписью; при смене подписи обновление
потребует удаления старой тестовой версии. Клиента для iOS в проекте пока нет.

## Быстрый старт: установка сервера

На Debian 12+ / Ubuntu 22.04+ с systemd и доступным TUN выполните от root
(`sudo -i`, если вошли обычным пользователем):

Перед установкой разрешите входящие **80/TCP**, **8443/TCP**, **443/TCP** и
**443/UDP** в firewall хостинга. Порт 80 нужен для проверки IP и продления
сертификата Let’s Encrypt; оставьте его доступным и после установки.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh)
```

Чтобы установить конкретную версию, добавьте её тег (например, `v0.1.0`):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh) v0.1.0
```

Скрипт скачивает готовый Linux-сервер для x86_64 или ARM64 из GitHub Releases,
проверяет SHA-256, устанавливает зависимости, настраивает NAT и запускает
службу `omega-server`. Он также устанавливает Certbot, получает **доверенный
сертификат Let’s Encrypt для IP** и включает автоматическое продление.
Домен не обязателен. Rust и сборка на VPS не нужны.
При повторном запуске сохраняются `/opt/omega/state` и существующие настройки
`/etc/default/omega-server`.

По умолчанию VPN использует **443/UDP и 443/TCP**, IPv6 внутри туннеля отключён.
Разрешите эти порты также в сетевом экране хостинга. Для IPv6 задайте
`OMEGA_IPV6_MODE=nat66` в `/etc/default/omega-server` и повторите установку
на VPS с работающим внешним IPv6.
SSH-порт определяется из текущего подключения; при необходимости укажите его
явно: `OMEGA_SSH_PORT=2222 bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh)`.

После первой установки консоль покажет:

```text
Admin URL: https://<IP_СЕРВЕРА>:8443
Login: <сгенерированный логин>
Password: <сгенерированный пароль>
```

Откройте ссылку с ПК или телефона и войдите. В обычном режиме используется
доверенный сертификат с полной цепочкой, поэтому подтверждать самоподписанный
сертификат в браузере не требуется. Если TCP 80 занят существующим веб-сервером,
задайте `OMEGA_ACME_WEBROOT=/var/www/html` с его реальным webroot перед командой
установки. Установщик не останавливает чужой веб-сервер.

В блоке **«Доступ к админке → Изменить логин или пароль»** можно изменить данные
входа, указав текущий пароль. После изменения все сессии завершаются.
В файле учётной записи пароль хранится как солёный PBKDF2-SHA256 хеш; исходный пароль выводится
один раз при создании. Повторная установка сохраняет ваши данные входа.
При автодеплое первоначальные данные сохраняются в защищённом файле
`/opt/omega/state/admin-bootstrap.json` (доступен только root), без вывода пароля
в GitHub Actions. Установщик покажет их и удалит файл; смена пароля тоже удаляет его.

Посмотреть первоначальные логин и пароль после автодеплоя на сервере:

```bash
sudo cat /opt/omega/state/admin-bootstrap.json
```

Если файл уже удалён после установки или смены пароля, используйте команду
сброса доступа ниже: она выдаст новые логин и пароль.

IP определяется из настроенного адреса клиента, SSH-подключения или внешнего
сервиса определения IP. При необходимости укажите его явно:

```bash
OMEGA_PUBLIC_HOST=203.0.113.1 bash <(curl -fsSL https://raw.githubusercontent.com/develop-mdv/quantom_vpn/main/install.sh)
```

Замените `203.0.113.1` на IP VPS. Порт админки можно задать через
`OMEGA_ADMIN_HTTPS_PORT=8443`. Адрес для кодов подключения
`OMEGA_CLIENT_SERVER` настраивается автоматически, если ещё не был задан.
Создайте пользователя и устройство в админке, затем скопируйте код в клиент.

Если забыли пароль, выполните от root на сервере:

```bash
cd /opt/omega
./omega-server admin reset_web
systemctl restart omega-server
```

Команда покажет новые логин и пароль. В обновлённой версии публичная админка работает
только через HTTPS; все страницы и API требуют входа, действия защищены CSRF-токеном.

IP-сертификаты Let’s Encrypt действуют около шести дней. Таймер
`omega-admin-tls-renew.timer` проверяет сертификат **каждые четыре часа** и
продлевает его заранее. `Persistent=true` и проверка после загрузки обеспечивают
повторный запуск после простоя. Админка подхватывает обновлённую полную цепочку и
ключ при следующем подключении, без перезапуска VPN и обрыва сессий.
Это автоматически настраивается при быстром старте и при серверном деплое.
[Поддержка IP-сертификатов в Certbot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot.html).

Для изолированных тестов без доступа к центру сертификации предусмотрен явный
режим `OMEGA_ADMIN_TLS_MODE=self-signed`; только в нём браузер потребует
подтвердить собственный сертификат. В обычной установке используется `letsencrypt`.

Состояние и логи:

```bash
systemctl status omega-server
journalctl -u omega-server -f
systemctl list-timers omega-admin-tls-renew.timer
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
cargo run -p omega-server -- admin init_web
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
- `omega-client-app/artifacts/windows-client/OmegaVPN-windows-x64-setup.exe` - автономный установщик одним файлом.
- `omega-client-app/artifacts/windows-client/installer/Omega.Client.Setup.exe` - тот же установщик для локального bootstrap-скрипта.

Для прикрепления к релизу используйте `OmegaVPN-windows-x64-setup.exe`:
клиент, Wintun и .NET runtime встроены в него. При установке содержимое
распаковывается во временный каталог, после установки временные файлы удаляются.
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

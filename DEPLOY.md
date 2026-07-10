# Omega VPN: Руководство по развертыванию

Это руководство описывает процесс установки и настройки сервера Omega VPN на Linux VPS (рекомендуется Ubuntu 22.04+).

## Предварительные требования
- VPS с публичным IP-адресом.
- Доступ root или sudo.
- Ядро Linux версии 5.15+ (для лучшей производительности TUN/eBPF).

## 1. Подготовка системы

Включите пересылку пакетов (IP forwarding) для маршрутизации трафика через VPN-туннель.

```bash
# Включить пересылку IPv4 немедленно
sysctl -w net.ipv4.ip_forward=1

# Сделать настройку постоянной
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-omega.conf
```

Настройте фаервол (UFW), чтобы разрешить SSH и VPN трафик.

```bash
# Настройка NAT и MSS Clamping (ОБЯЗАТЕЛЬНО)
# Без этого шага у клиента не будет доступа в интернет!

# Мы подготовили автоматический скрипт настройки.
# Просто запустите его на сервере:

curl -sSL https://raw.githubusercontent.com/your-repo/omega-vpn/main/deploy/setup_nat.sh | sudo bash

# Или, если вы клонировали репозиторий:
# cd ~/omega-vpn/deploy
# sudo bash setup_nat.sh

```

## 2. Установка (Сборка из исходного кода)

Установите Rust и необходимые зависимости.

```bash
apt update && apt install -y build-essential curl pkg-config libssl-dev clang
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Клонируйте репозиторий и соберите сервер.

```bash
git clone https://github.com/your-repo/omega-vpn.git
cd omega-vpn
cargo build --release -p omega-server
```

Скопируйте бинарный файл в системную директорию.

```bash
mkdir -p /opt/omega
cp target/release/omega-server /opt/omega/
chmod +x /opt/omega/omega-server
```

## 3. Настройка службы (Systemd)

Скопируйте файл службы systemd.

```bash
cp deploy/omega-server.service /etc/systemd/system/
systemctl daemon-reload
```

Включите и запустите службу.

```bash
systemctl enable omega-server
systemctl start omega-server
systemctl status omega-server
```

## 4. Настройка клиента

По умолчанию сервер слушает на `0.0.0.0:51820`.
Убедитесь, что на клиенте установлена правильная переменная окружения `OMEGA_SERVER`, указывающая на IP вашего VPS.

Пример запуска клиента:
```bash
OMEGA_SERVER=203.0.113.1:51820 cargo run --release -p omega-client
```

## 5. Обновление сервера
 
 При выходе новых версий или исправлений безопасности (как сейчас), выполните следующие шаги:
 
 1. **Получите свежий код**:
    ```bash
    cd ~/omega-vpn
    git pull
    ```
 
 2. **Пересооберите сервер**:
    ```bash
    cargo build --release -p omega-server
    ```
 
 3. **Обновите бинарный файл**:
    ```bash
    systemctl stop omega-server
    cp target/release/omega-server /opt/omega/
    chmod +x /opt/omega/omega-server
    ```
 
 4. **Перезапустите службу**:
    ```bash
    systemctl start omega-server
    systemctl status omega-server
    ```
 
 ## Устранение неполадок

Просмотр логов:
```bash
journalctl -u omega-server -f
```

Если пакеты теряются, проверьте настройки MTU или правила фаервола.
## Подготовка нескольких пользователей и устройств после деплоя

После запуска сервера создайте пользователей и устройства через админ CLI:

```bash
# Создать пользователя
/opt/omega/omega-server admin create_user --max-devices 5 --max-sessions 3

# Зарегистрировать устройство (сохраните device_id и token из вывода)
/opt/omega/omega-server admin register_device \
  --user-id <user_uuid> \
  --device-name "laptop" \
  --platform linux
```

Клиент должен передавать учетные данные устройства:

```bash
OMEGA_SERVER=<server_ip>:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<token_hex> \
OMEGA_DEVICE_NAME="laptop" \
./omega-client
```

Дополнительные переменные окружения для путей состояния сервера:

- `OMEGA_IDENTITY_DB` (по умолчанию `omega-server/state/identity.json`)
- `OMEGA_SESSION_SNAPSHOT` (по умолчанию `omega-server/state/sessions.json`)
- `OMEGA_ADMIN_COMMANDS` (по умолчанию `omega-server/state/admin_commands.ndjson`)
## Встроенная веб-админка

Сервер может поднимать встроенную web admin панель для управления пользователями/устройствами.

Переменные окружения:
- `OMEGA_ADMIN_WEB_BIND` (по умолчанию `127.0.0.1:8081`)
- `OMEGA_ADMIN_WEB_PUBLIC=1` и `OMEGA_ADMIN_WEB_PORT=8081`, если админку нужно открыть наружу
- `OMEGA_CLIENT_SERVER=<SERVER_IP_OR_DOMAIN>:443`, чтобы UI генерировал правильные `omega://connect/...` коды
- `OMEGA_ADMIN_WEB_DISABLE=1` для полного отключения

Пример запуска:

```bash
OMEGA_ADMIN_WEB_BIND=127.0.0.1:8081 /opt/omega/omega-server
```

Встроенная админка сейчас работает по plain HTTP, не HTTPS. Если она опубликована
наружу, открывайте ее явно как:

```text
http://<SERVER_IP>:8081/
```

Если открыть `https://<SERVER_IP>:8081/`, сервер получит TLS ClientHello вместо
HTTP-запроса и запишет `malformed HTTP request`.

Для production override-ов используйте `/etc/default/omega-server`, а не правку
unit-файла:

```env
# Сгенерируйте один раз и не меняйте после регистрации устройств.
OMEGA_TOKEN_PEPPER=<long-random-secret>
OMEGA_CLIENT_SERVER=<SERVER_IP_OR_DOMAIN>:443

# Public plain-HTTP admin.
OMEGA_ADMIN_WEB_PUBLIC=1
OMEGA_ADMIN_WEB_PORT=8081

# Если у VPS нет IPv6 egress, не включайте nat66.
OMEGA_IPV6_MODE=disabled

# Если TCP 443 уже занят nginx/xray/другим сервисом, отключите Omega TCP fallback.
OMEGA_TCP_ENABLE=0
```

Сетевой bootstrap для такого IPv4-only варианта:

```bash
sudo OMEGA_VPN_PORT=443 \
  OMEGA_TCP_ENABLE=0 \
  OMEGA_VPN_IPV6_MODE=disabled \
  OMEGA_ADMIN_WEB_PUBLIC=1 \
  OMEGA_ADMIN_WEB_PORT=8081 \
  bash deploy/setup_nat.sh

sudo OMEGA_VPN_PORT=443 \
  OMEGA_TCP_ENABLE=0 \
  OMEGA_VPN_IPV6_MODE=disabled \
  OMEGA_ADMIN_WEB_PUBLIC=1 \
  OMEGA_ADMIN_WEB_PORT=8081 \
  bash deploy/diagnose_server.sh
```

`OMEGA_IPV6_MODE=nat66` включайте только после проверки, что на VPS есть
исходящий IPv6 route:

```bash
ip -6 route get 2606:4700:4700::1111
```

`OMEGA_TCP_ENABLE=1` имеет смысл только если TCP endpoint из `OMEGA_SERVER`
свободен под Omega. Клиентский TCP fallback использует тот же host:port, поэтому
если TCP `443` уже занимает, например, `xray`, включать Omega TCP fallback на
`[::]:443` нельзя.

Если админка содержит реальные пользовательские токены, безопаснее держать bind
только на localhost и публиковать доступ через защищенный reverse proxy
(mTLS/VPN/SSH tunnel) или хотя бы ограничить `8081` по IP в firewall/security group.
## Автодеплой при push (GitHub Actions)

В репозитории добавлен workflow: `.github/workflows/deploy-server.yml`.
Он автоматически срабатывает при push в ветку `main` (по изменениям server/core) и делает:
1. Сборку `omega-server` в release режиме.
2. Копирование бинарника на VPS по SSH.
3. Безопасное обновление через `deploy/update_server.sh`.
4. Рестарт `omega-server` и проверку `systemctl is-active`.
5. Авто-rollback на предыдущий бинарник при неуспешном старте.

### Что настроить в GitHub Secrets

Обязательные:
- `DEPLOY_HOST` — IP или домен VPS.
- `DEPLOY_USER` — пользователь для SSH (например `deploy`).
- `DEPLOY_SSH_KEY` — приватный SSH ключ (ed25519/rsa) для доступа к VPS.
- `DEPLOY_KNOWN_HOSTS` — результат `ssh-keyscan -H <host>`.

Опциональные:
- `DEPLOY_PORT` — SSH порт (по умолчанию `22`).
- `DEPLOY_PATH` — временная директория на сервере (по умолчанию `/tmp/omega-deploy`).
- `DEPLOY_SERVICE_NAME` — systemd unit (по умолчанию `omega-server`).
- `DEPLOY_INSTALL_DIR` — директория установки бинарников (по умолчанию `/opt/omega`).
- `DEPLOY_KEEP_RELEASES` — сколько релизов хранить (по умолчанию `5`).

### Подготовка VPS

1. Убедитесь, что systemd unit уже настроен (`omega-server.service`).
2. У пользователя `DEPLOY_USER` должны быть права на перезапуск сервиса через `sudo` без пароля.
   Пример правила в `/etc/sudoers.d/omega-deploy`:

```bash
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart omega-server, /usr/bin/systemctl is-active omega-server, /usr/bin/systemctl --no-pager --full status omega-server
```

3. Убедитесь, что существует директория `/opt/omega` и сервис стартует командой `ExecStart=/opt/omega/omega-server`.

После этого достаточно делать `git push` в `main` — сервер будет обновляться автоматически.

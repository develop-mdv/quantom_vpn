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
ufw allow OpenSSH
ufw allow 51820/udp
ufw enable
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

## Устранение неполадок

Просмотр логов:
```bash
journalctl -u omega-server -f
```

Если пакеты теряются, проверьте настройки MTU или правила фаервола.

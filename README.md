# Omega VPN

**Omega VPN** — это высокопроизводительный, устойчивый к цензуре VPN-протокол следующего поколения, написанный на Rust.

## Ключевые возможности

### 🔒 Безопасность (Post-Quantum)
*   **ML-KEM-768**: Использует постквантовую криптографию (Kyber) для обмена ключами, защищая от будущих угроз со стороны квантовых компьютеров.
*   **ChaCha20-Poly1305**: Быстрое и надежное симметричное шифрование трафика.
*   **Perfect Forward Secrecy**: Ключи сессий регулярно обновляются.

### 🎭 Маскировка трафика (Traffic Morphing)
*   **Bimodal Chaos Padding**: Трафик VPN маскируется под WebRTC (аудио/видео потоки). Размеры пакетов динамически меняются по хаотическому алгоритму, имитируя "голос" и "видео", что затрудняет DPI-анализ.
*   RTP-заголовки добавляются к каждому пакету для полной мимикрии.

### 📶 Надежность в плохих сетях
*   **ARQ (Automatic Repeat reQuest)**: Автоматический перезапрос потерянных пакетов.
*   **Adaptive RaptorQ FEC**: Адаптивная коррекция ошибок (Forward Error Correction). При обнаружении потерь автоматически включается избыточное кодирование, позволяя восстанавливать данные без перезапросов.

### 🚀 Высокая производительность
*   Написан на **Rust** с использованием асинхронного рантайма **Tokio**.
*   Многопоточная архитектура.
*   Пропускная способность шифрования **>10 Гбит/с** на одно ядро.
 
 ## 🏆 Почему Omega VPN уникален? (Сравнение)
 
 | Функция | **Omega VPN** | WireGuard | OpenVPN / Shadowsocks |
 | :--- | :--- | :--- | :--- |
 | **Защита от квантовых компьютеров** | ✅ **ML-KEM-768 (Kyber)** | ❌ Нет (Curve25519) | ❌ Нет |
 | **Маскировка от DPI** | ✅ **WebRTC/RTP Mimicry** (выглядит как Zoom) | ❌ Нет (легко блокируется) | ⚠️ Shadowsocks (активная война с цензорами) |
 | **Работа при потерях пакетов** | ✅ **RaptorQ FEC + ARQ** (работает при 20% потерь) | ❌ Нет (теряет скорость) | ❌ TCP-over-TCP тормозит |
 | **Гейминг (UDP)** | ✅ **Спец. оптимизация MTU** (Dota 2, CS:GO) | ⚠️ Требует тонкой настройки | ❌ Высокий джиттер |
 | **Простота** | ✅ Один бинарник / Auto-Setup | ✅ Просто | ❌ Сложно (сертификаты) |

## Структура проекта

*   `omega-core`: Основная библиотека (криптография, протокол, ARQ, FEC, Chaos PRNG).
*   `omega-server`: Серверная часть (TUN-устройство, управление сессиями).
*   `omega-client`: Клиентская часть.

## Как пользоваться

### Требования
*   Linux (для сервера) / Windows, Linux, macOS (для клиента).
*   Rust toolchain (для сборки).

### Быстрый старт (Локально)

1.  **Запуск сервера**:
    ```bash
    # Сервер слушает на 0.0.0.0:51820
    cargo run --release -p omega-server
    ```

2.  **Запуск клиента**:
    ```bash
    # Подключение к локальному серверу
    # OMEGA_SERVER указывает адрес сервера
    OMEGA_SERVER=127.0.0.1:51820 cargo run --release -p omega-client
    ```

3.  **Проверка**:
    После запуска должны появиться сетевые интерфейсы `tun0` (или аналогичные). Вы можете пинговать внутренние IP адреса туннеля (по умолчанию 10.0.0.x).

### Windows (Клиент)

1.  Установите [Rust](https://rustup.rs/).
2.  Скачайте [Wintun драйвер](https://www.wintun.net/). Вам нужен файл `wintun.dll` (из папки `bin/amd64` для 64-битных систем).
3.  Положите `wintun.dll` в корень проекта (рядом с `Cargo.toml`).
4.  Запустите скрипт `start_client.bat` (он сам скачает драйвер, если его нет).
    *   **Важно**: теперь `start_client.bat` читает параметры из `.env` (см. `.env.example`), редактировать bat-файл не нужно.

## Deployment (Quick Start)
 
 1. **Deploy Server**:
    Follow [DEPLOY.md](DEPLOY.md) or use this one-liner on Ubuntu:
    ```bash
    curl -sSL https://raw.githubusercontent.com/your-repo/omega-vpn/main/deploy/setup_nat.sh | sudo bash
    ```
    *(Note: You still need to build/run the binary first)*

## Статус разработки

Проект находится в стадии **Alpha**.
*   ✅ Реализовано: Handshake, Шифрование, ARQ, FEC, Маскировка.
*   🚧 В планах: eBPF оптимизация (пока не требуется), поддержка Android/iOS.
## Поддержка нескольких пользователей и устройств (MVP)

Сервер поддерживает аутентификацию устройств и динамическую выдачу tunnel IP из пула `10.7.0.0/16`.

### Подготовка через админ CLI

Создать пользователя:

```bash
cargo run -p omega-server -- admin create_user --max-devices 5 --max-sessions 3
```

Зарегистрировать устройство для пользователя (сохраните `device_id` и `token`):

```bash
cargo run -p omega-server -- admin register_device \
  --user-id <user_uuid> \
  --device-name "laptop" \
  --platform windows
```

Запустить сервер:

```bash
cargo run -p omega-server
```

Запустить клиент с учетными данными устройства:

```bash
OMEGA_SERVER=203.0.113.1:51820 \
OMEGA_DEVICE_ID=<device_uuid> \
OMEGA_DEVICE_TOKEN=<device_token_hex> \
OMEGA_DEVICE_NAME="laptop" \
cargo run -p omega-client
```

### Полезные команды администратора

```bash
cargo run -p omega-server -- admin list_users
cargo run -p omega-server -- admin list_user_devices --user-id <user_uuid>
cargo run -p omega-server -- admin revoke_device --device-id <device_uuid>
cargo run -p omega-server -- admin list_active_sessions
cargo run -p omega-server -- admin terminate_session --flow-id <flow_id_hex>
```

### Файлы состояния

- БД идентификации: `omega-server/state/identity.json` (переопределяется через `OMEGA_IDENTITY_DB`)
- Снимок активных сессий: `omega-server/state/sessions.json` (переопределяется через `OMEGA_SESSION_SNAPSHOT`)
- Очередь админ-команд: `omega-server/state/admin_commands.ndjson` (переопределяется через `OMEGA_ADMIN_COMMANDS`)
### Веб-админка

В `omega-server` встроена простая web admin панель.

По умолчанию она слушает только localhost:

```bash
OMEGA_ADMIN_WEB_BIND=127.0.0.1:8081 cargo run -p omega-server
```

Откройте в браузере: `http://127.0.0.1:8081/`.

Через UI доступны операции:
- создание пользователя;
- регистрация устройства (с выдачей device token);
- блокировка/разблокировка/удаление пользователя;
- отзыв устройства;
- завершение активной сессии.

Отключение web admin:

```bash
OMEGA_ADMIN_WEB_DISABLE=1 cargo run -p omega-server
```
### Windows: запуск через `.env` и `start_client.bat`

1. Скопируйте `.env.example` в `.env`.
2. Заполните значения:
   - `OMEGA_SERVER`
   - `OMEGA_DEVICE_ID`
   - `OMEGA_DEVICE_TOKEN`
   - `OMEGA_DEVICE_NAME` (опционально)
3. Запустите `start_client.bat` от имени администратора (скрипт сам запросит права).

`start_client.bat` автоматически читает `.env` и передает переменные в `omega-client`.

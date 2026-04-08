# Omega VPN Deploy Guide

Этот документ описывает первичное развертывание на Linux/VPS. Для day-2 операций, диагностики и текущего CI/CD смотри `docs/OPERATIONS.md`.

## Что предполагается

- Ubuntu 22.04+ или другой Linux с TUN и systemd.
- Публичный IP или домен.
- SSH-доступ с sudo.
- Понимание, какой интерфейс является публичным.

## Быстрый путь: GitHub Actions + systemd

Текущий рекомендуемый production flow не требует ручного `git pull` на сервере.

### Один раз на сервере

1. Создай директории:

```bash
sudo mkdir -p /opt/omega/state
sudo chown -R $USER:$USER /opt/omega
```

2. Поставь systemd unit:

```bash
sudo cp deploy/omega-server.service /etc/systemd/system/omega-server.service
sudo systemctl daemon-reload
```

3. Один раз примени сетевой bootstrap:

```bash
sudo bash deploy/setup_nat.sh
```

4. Убедись, что у deploy-пользователя есть `sudo` без пароля хотя бы на нужные `systemctl` и deploy scripts.

### Дальше обычный релиз

После этого основной путь - просто push в `main`.

`deploy-server.yml` сам:

1. собирает `omega-server --release`;
2. загружает deploy bundle на сервер;
3. вызывает `deploy/update_server.sh`;
4. повторно применяет `deploy/setup_nat.sh`;
5. запускает `deploy/diagnose_server.sh`.

## Какие secrets нужны в GitHub

### Хватает для старта

- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `DEPLOY_PATH`

С таким набором deploy уже может работать.

### Очень рекомендуется

- `DEPLOY_KNOWN_HOSTS`

Без него workflow пытается сделать `ssh-keyscan` на лету. Это удобный fallback, но pinned host key в secrets надежнее.

### Полезные optional secrets

- `DEPLOY_PORT`
- `DEPLOY_SERVICE_NAME`
- `DEPLOY_INSTALL_DIR`
- `DEPLOY_KEEP_RELEASES`
- `DEPLOY_CLIENT_CIDR`
- `DEPLOY_VPN_PORT`
- `DEPLOY_VPN_PROTOCOL`
- `DEPLOY_METRICS_PORT`

### Optional secrets для alert rules

- `DEPLOY_ALERTS_DEST`
- `DEPLOY_PROMETHEUS_SERVICE_NAME`

Если `DEPLOY_PROMETHEUS_SERVICE_NAME` задан, deploy после обновления `omega-alerts.yml` попытается перечитать Prometheus автоматически.

## Что именно деплоится сейчас

В server bundle входят:

- `omega-server`
- `setup_nat.sh`
- `update_server.sh`
- `diagnose_server.sh`
- `omega-server.service`
- `omega-alerts.yml`

Это значит, что при обычном push обновляется не только бинарник, но и deploy scripts, unit file и alert rules.

## Когда использовать `bootstrap-network.yml`

Отдельно запускай этот workflow только когда нужно восстановить или проверить сетевой bootstrap:

- новый VPS;
- переезд на другой сервер;
- сломались firewall/NAT/sysctl;
- поменялся interface, SSH port или публичный VPN port.

Если изменился только код приложения, `deploy-server.yml` обычно достаточно.

## Ручной rollback / recovery

Если automation не помогла:

1. Посмотри `systemctl status omega-server`.
2. Запусти `sudo bash deploy/diagnose_server.sh`.
3. Проверь `state/observability.json` и `state/trace.ndjson`.
4. При необходимости откати релиз через предыдущий symlink/binary в `/opt/omega/releases/`.

В обычном happy path этим занимается сам `update_server.sh`.
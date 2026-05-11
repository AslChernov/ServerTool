# 🚀 Server Setup Tool

Комплексный инструмент для настройки и управления серверами на **Ubuntu 24.04**.

## ⚡ Быстрый запуск

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AslChernov/ServerTool/main/server_tool.sh)
```

## 📦 Возможности

| # | Функция | Описание |
|---|---------|----------|
| 1 | **Подготовка Ubuntu** | Обновление системы, установка базового ПО, Docker |
| 2 | **Настройка сети и BBR** | BBR1/BBR2/BBR3, управление IPv6, бэкапы сетевых настроек |
| 3 | **UFW Manager** | Полнофункциональный менеджер файрвола |
| 4 | **TrafficGuard** | Защита от нежелательного трафика |
| 5 | **AdGuard Home** | DNS-блокировщик рекламы и трекеров |
| 6 | **SSH Hardening** | Смена порта, настройка ключей, отключение паролей |
| 7 | **Swap** | Создание и управление файлом подкачки |
| 8 | **Бенчмарк (YABS)** | Тестирование производительности сервера |
| 9 | **Очистка системы** | Удаление кэша, старых логов, неиспользуемых Docker-ресурсов |
| 10 | **Установка в систему** | Команда `sudo server-tool` из любого места |
| 11 | **Self-Update** | Автообновление скрипта с GitHub |

## 🔧 Требования

- Ubuntu 24.04 LTS
- Права root (`sudo`)
- Доступ в интернет

## 📜 На основе

- [Balbuto/Setup-and-Test-Server-Ubuntu-24](https://github.com/Balbuto/Setup-and-Test-Server-Ubuntu-24)
- [SawGoD/bbr-control](https://github.com/SawGoD/bbr-control)
- [Balbuto/ufw-manager](https://github.com/Balbuto/ufw-manager)
- [DonMatteoVPN/TrafficGuard-auto](https://github.com/DonMatteoVPN/TrafficGuard-auto)

## 📄 Лицензия

MIT

# ServerTool

Интерактивная пост-настройка и защита Ubuntu/Debian-ноды Remnawave. Скрипт рассчитан на запуск **после установки ноды**.

## Что умеет

- обновляет систему;
- устанавливает единый входящий firewall на nftables без UFW;
- открывает `443/tcp`, `443/udp` или оба протокола на выбор;
- разрешает API-порт ноды (по умолчанию `2222/tcp`) только с IPv4/CIDR панели;
- фильтрует как локальный трафик, так и опубликованные Docker-порты;
- закрывает неизвестные Docker DNAT-публикации;
- объединяет и схлопывает Anti-Scanner/government/Geo-IP списки;
- хранит проверенный кэш списков для загрузки firewall без интернета;
- опционально устанавливает CrowdSec с nftables-bouncer и защитой SSH/Nginx;
- ограничивает память CrowdSec в зависимости от ОЗУ сервера;
- добавляет публичный SSH-ключ или генерирует Ed25519-пару;
- переводит SSH на случайный или указанный порт с синхронным обновлением firewall и откатом;
- устанавливает XanMod LTS/Main и включает BBR + `fq`;
- делает резервные копии firewall и SSH-конфигурации.

TrafficGuard, CTGuard и BanOnce не устанавливаются. Из TrafficGuard используются только публичные IP-списки. Скрипт не выполняет глобальный `nft flush ruleset` и не изменяет таблицы Docker/CrowdSec.

## Запуск

```bash
sudo apt-get update && sudo apt-get install -y curl
curl -fsSL https://raw.githubusercontent.com/AslChernov/ServerTool/main/server_tool.sh -o server_tool.sh
chmod +x server_tool.sh
sudo ./server_tool.sh
```

Просмотр состояния без меню:

```bash
sudo ./server_tool.sh --status
```

## Рекомендуемый порядок

1. Сделайте snapshot и оставьте открытой резервную консоль хостинга.
2. Добавьте или создайте SSH-ключ.
3. Измените SSH-порт и проверьте новый вход, не закрывая текущую сессию.
4. Настройте nftables: выберите `443`, порт ноды и IP панели.
5. При необходимости установите CrowdSec.
6. Установите XanMod LTS, перезагрузитесь и включите BBR.

## Архитектура firewall

ServerTool управляет только таблицей `inet server_tool_guard`:

- `input` имеет политику `drop`;
- разрешены loopback, установленные соединения, ICMP, SSH, выбранные протоколы `443` и порт ноды от панели;
- контейнерам разрешено инициировать исходящие соединения к хосту и другим сетям;
- `forward` проверяет исходный порт до Docker DNAT;
- неизвестные опубликованные Docker-порты блокируются;
- основной firewall загружается из локального кэша до запуска Docker;
- списки обновляются отдельным systemd-таймером раз в сутки.

IPv6-службы наружу не открываются. ICMPv6 разрешён для корректной работы сетевого стека.

## CrowdSec

CrowdSec устанавливается только по выбору пользователя:

- используется официальный репозиторий CrowdSec;
- включаются коллекции Linux, SSH и Nginx;
- скрипт пытается автоматически найти Nginx-контейнер Remnawave;
- nftables-bouncer создаёт отдельную таблицу `ip crowdsec`;
- дополнительная forward-цепочка применяет решения CrowdSec к Docker-трафику;
- systemd ограничивает память и снижает вероятность убийства CrowdSec через OOM.

CrowdSec не является защитой от объёмного DDoS — она должна предоставляться хостингом.

## Важные замечания

- По умолчанию API ноды доступен только с `45.148.62.18`; значение меняется в меню.
- Geo-block по умолчанию выключен.
- Слишком широкие, приватные и локальные сети из внешних списков отбрасываются.
- Подозрительно пустое обновление не заменяет рабочий кэш.
- Приватный ключ, созданный на сервере, нужно скачать, проверить и удалить с сервера.
- Скрипт не перезагружает сервер автоматически.

## Файлы на сервере

| Назначение | Путь |
|---|---|
| Настройки firewall | `/etc/server-tool/guard.conf` |
| Проверенный кэш IP | `/var/lib/server-tool/blocklist-v4.txt` |
| Применение firewall | `/usr/local/sbin/server-tool-guard-update` |
| SSH-настройки | `/etc/ssh/sshd_config.d/00-server-tool.conf` |
| Резервные копии | `/var/backups/server-tool/` |
| Лог | `/var/log/server-tool.log` |

## Поддержка

- Ubuntu 24.04 LTS и Debian 13 рекомендуются;
- другие актуальные Ubuntu/Debian также проверяются скриптом;
- amd64 обязательна только для XanMod;
- запуск от `root`/через `sudo`.

Источники: [XanMod](https://xanmod.org/), [CrowdSec](https://docs.crowdsec.net/u/getting_started/installation/linux/), [Docker firewall](https://docs.docker.com/engine/network/packet-filtering-firewalls/) и [Ubuntu OpenSSH](https://documentation.ubuntu.com/server/how-to/security/openssh-server/).

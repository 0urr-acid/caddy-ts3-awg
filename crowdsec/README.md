# CrowdSec для Caddy TS3/AWG

Цепочка: `Caddy JSON → custom parser → scenario → CrowdSec decision → firewall-bouncer`.
Плагин только пишет события; сам он IP не блокирует.

## Установка

В Caddy направь logger `ts3_awg` в отдельный JSON-файл:

```caddyfile
log ts3_awg_security {
    include ts3_awg
    output file /var/log/caddy/ts3-awg.json
    format json
    level INFO
}
```

Каталог должен быть доступен на запись пользователю Caddy и на чтение CrowdSec.

Из корня репозитория плагина:

```bash
sudo install -d /etc/crowdsec/parsers/s01-parse /etc/crowdsec/scenarios /etc/crowdsec/acquis.d
sudo install -m 0644 crowdsec/parsers/s01-parse/0urr-acid/caddy-ts3-awg.yaml \
  /etc/crowdsec/parsers/s01-parse/0urr-acid-caddy-ts3-awg.yaml
sudo install -m 0644 crowdsec/scenarios/0urr-acid/ts3-awg-connection-flood.yaml \
  /etc/crowdsec/scenarios/0urr-acid-ts3-awg-connection-flood.yaml
sudo install -m 0644 crowdsec/acquis.yaml /etc/crowdsec/acquis.d/caddy-ts3-awg.yaml
```

Используется стандартный enricher времени `crowdsecurity/dateparse-enrich`.
Он обычно уже установлен с базовыми коллекциями; при необходимости:

```bash
sudo cscli parsers install crowdsecurity/dateparse-enrich
sudo crowdsec -t
sudo systemctl reload crowdsec
```

Parser и scenario локальные и не требуют публикации в CrowdSec Hub.
Acquisition использует тип **`caddy-ts3-awg`**, не `caddy`.
Parser принимает только `logger=ts3_awg`, `event=suspicious_connection`,
`reason=session_start_rate`; обычные логи маршрутизации и ошибки backend
не совпадают с ним. Адрес берётся из `remote_ip`, не из адреса backend.

## Что считается подозрительным

В Caddy по умолчанию превышение 60 стартов с одного IP за 10 секунд вызывает
один WARN event за это окно. Считаются новые исходные UDP tuple и повторные
`I1` до переключения на AWG. Обычные пакеты активного TS3/AWG потока не считаются.

Сценарий — leaky bucket с `capacity: 2`, `leakspeed: 30s`, `blackhole: 2m`.
Повторяющиеся превышения заполняют его и создают alert с `remediation: true`.
Продолжительность бана задаёт твой CrowdSec profile. Учитывай клиентов за NAT
и подделку source IP в UDP: пороги и whitelist должны соответствовать нагрузке.

Для реальной блокировки нужен **firewall-bouncer** на машине, принимающей UDP.
Существующий HTTP-bouncer Caddy защищает HTTP, а не этот UDP-сервис.
Убедись, что bouncer подключён к тому же LAPI и применяет решения на входном
сетевом пути релея, включая IPv6, если listener его принимает.

## Проверка

```bash
sudo cscli explain --file crowdsec/tests/events.jsonl --type caddy-ts3-awg
sudo cscli explain --file crowdsec/tests/benign.jsonl --type caddy-ts3-awg
sudo cscli scenarios list
sudo cscli alerts list
sudo cscli decisions list
sudo cscli bouncers list
```

Первая команда должна показывать parser `0urr-acid/caddy-ts3-awg`, метаданные
`source_ip`, `service=ts3-awg`, `log_type=ts3_awg_suspicious` и вход в сценарий.
Вторая не должна сопоставлять benign-события с нашим parser. `explain` проверяет
путь парсинга, но не устанавливает firewall ban. Для реальных блокировок проверь
события в рабочем файле Caddy, alert/decision в LAPI и работу firewall-bouncer.

Официальные справочники:
[custom scenarios](https://docs.crowdsec.net/docs/log_processor/scenarios/create/),
[проверка parser](https://docs.crowdsec.net/u/user_guides/cscli_explain/),
[firewall-bouncer](https://docs.crowdsec.net/docs/bouncers/firewall/).

## Изолированный тест без установленного сервиса

Проверено с CrowdSec **v1.8.2**. Нужны бинарники `cscli`, `crowdsec` и локальная
копия официального [crowdsecurity/hub](https://github.com/crowdsecurity/hub)
с шаблонами `.tests` и `dateparse-enrich`:

```bash
python3 scripts/test-crowdsec.py \
  --hub /path/to/crowdsecurity/hub \
  --cscli /path/to/cscli \
  --crowdsec /path/to/crowdsec
```

Скрипт создаёт временную конфигурацию и локальный LAPI для `cscli hubtest`,
проверяет положительный и отрицательный сценарии и удаляет тестовую среду.
Он не читает `/etc/crowdsec`, не меняет службу или firewall, не создаёт
эксплуатационные баны и не загружает файлы из сети.

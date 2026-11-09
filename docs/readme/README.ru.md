<h1><picture><source media="(prefers-color-scheme: dark)" srcset="../brand/banner-ru.webp"><img alt="Kanareika: аудит безопасности серверов по SSH" src="../brand/banner-ru-light.webp"></picture></h1>

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mikekosulin/kanareika/badges/coverage.json)](https://github.com/mikekosulin/kanareika/actions/workflows/coverage.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE) [![Stars](https://img.shields.io/github/stars/mikekosulin/kanareika?style=social)](https://github.com/mikekosulin/kanareika)

[English](../../README.md) · [Español](README.es.md) · [Français](README.fr.md) · [Português](README.pt.md) · **Русский** · [中文](README.zh.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

Kanareika проверяет безопасность Linux-серверов по SSH. Ставить агент не нужно, на серверах ничего не меняется. Она покажет, что закрывать первым: CVE с учётом KEV и EPSS, доступ по SSH, открытые порты, состояние хостов. Для каждой проблемы есть готовые шаги исправления с откатом.

Работает одинаково в терминале, в браузере и через MCP-сервер для ИИ-агентов. Один бинарник на Go, настройки организации — в одном YAML-файле, никакой телеметрии; данные хранятся только у вас.

- **Домашние серверы**: выберите хосты из `~/.ssh/config` или вставьте `user@host`.
- **Фрилансер**: по организации на каждого клиента, серверы можно добавить позже.
- **Компания**: вставьте список хостов, CSV или инвентарь Ansible; неудачные входы сгруппированы по причине, с подсказкой, как исправить.

### Терминальный интерфейс

Запустите `kanareika` — откроется список задач, самое срочное сверху.

<picture><source media="(prefers-color-scheme: dark)" srcset="../screenshots/tui-ru.webp"><img alt="Терминальный интерфейс на вымышленных данных" src="../screenshots/tui-ru-light.webp"></picture>

### Веб-интерфейс

`kanareika web` показывает те же данные в браузере, плюс динамику за последние 30 сканирований.

<picture><source media="(prefers-color-scheme: dark)" srcset="../screenshots/web-ru.webp"><img alt="Веб-интерфейс на вымышленных данных" src="../screenshots/web-ru-light.webp"></picture>

<sub>На скриншотах вымышленные данные.</sub>

### Установка

Homebrew (macOS и Linux) — формула фиксирует версию и её контрольную сумму:

```bash
brew install mikekosulin/tap/kanareika
```

Или скриптом установки — сначала прочитайте его, потом запустите:

```bash
curl -fsSLO https://raw.githubusercontent.com/mikekosulin/kanareika/main/install.sh
less install.sh
sh install.sh
```

Скрипт выберет сборку под эту машину, сверит контрольную сумму (и аттестацию сборки, если установлен GitHub CLI) и спросит, прежде чем ставить в `/usr/local/bin` или `~/.local/bin`; с `KANAREIKA_YES=1` вопроса не будет.

Или вручную (Linux, macOS):

```bash
cd "$(mktemp -d)"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')                 # linux, darwin
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')  # amd64, arm64
FILE=kanareika-$OS-$ARCH.tar.xz
URL=https://github.com/mikekosulin/kanareika/releases/latest/download

curl -fsSLO "$URL/$FILE"
curl -fsSLO "$URL/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS  # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
gh attestation verify "$FILE" --repo mikekosulin/kanareika  # необязательно, нужен GitHub CLI
tar -xJf "$FILE" kanareika
sudo install kanareika /usr/local/bin/  # или без sudo: install kanareika ~/.local/bin/
```

Windows (PowerShell):

```powershell
Invoke-WebRequest https://github.com/mikekosulin/kanareika/releases/latest/download/kanareika-windows-amd64.zip -OutFile kanareika.zip; Expand-Archive kanareika.zip -DestinationPath kanareika
```

Затем запустите `kanareika.exe` из папки `kanareika`. Для ARM есть отдельный `kanareika-windows-arm64.zip`.

### Запуск

В терминале:

```bash
kanareika
```

или в браузере, на http://127.0.0.1:8088 (веб-интерфейс слушает только localhost):

```bash
kanareika web
```

При первом запуске Kanareika поможет добавить серверы (SSH-пользователь и ключ, хосты, согласие на сканирование) и запустит первое сканирование. Перед скачиванием списка уязвимостей (около 210 МБ) спросит.

### Для скриптов и cron

Создать организацию — настройки окажутся в `orgs/<ORG_ID>.yml`:

```bash
kanareika org new <ORG_ID>
```

Просканировать её; перед этим проверяются настройки и скачиваются базы:

```bash
kanareika scan <ORG_ID>
```

Веб-интерфейс на другом порту (`--port 0` — любой свободный):

```bash
kanareika web --port <PORT>
```

Подключить терминальный интерфейс к удалённому веб-интерфейсу:

```bash
kanareika tui --url http://<SERVER>:8088 --token <YOUR_SECRET_TOKEN>
```

Без интернета: выгрузите базы на машине, где интернет есть,

```bash
kanareika db export <BUNDLE.tar.gz>
```

затем загрузите их на изолированной машине и сканируйте офлайн:

```bash
kanareika db import <BUNDLE.tar.gz>
kanareika scan <ORG_ID> --offline
```

Всё остальное — `kanareika --help`.

### Как пользоваться

- **Терминал** — `kanareika`. `?` — горячие клавиши, `o` — настройка панелей, `L` — язык. Можно подключиться к удалённому серверу.
- **Браузер** — `kanareika web`: сводка, графики, карточки хостов, сканирование запускается прямо со страницы.
- **Командная строка** — для скриптов и cron.
- **MCP** — `kanareika mcp`: инструменты только на чтение, чтобы с результатами могли работать ИИ-агенты (Claude Code и другие).

Данные и правила везде одни и те же.

### Что проверяется

- **Уязвимости** в пакетах ОС, Docker-образах, jar- и lock-файлах. Внутри работает trivy, он уже встроен в бинарник. Бэкпорты и наличие исправлений проверяются на самом хосте. Приоритет от P1 до P4 учитывает KEV, EPSS, доступность сервиса снаружи и pre-auth RCE.
- **Доступ** — вход по паролю, SSH-ключи, кто и откуда заходил, подбор паролей, открытые порты, файрвол, внешнее сканирование.
- **Состояние хостов** — ошибки ядра, место на дисках, память, синхронизация времени, ожидающие перезагрузки.
- **Исправления** — отметьте нужные пункты, и Kanareika соберёт готовую задачу для инженера или ИИ-агента: что применить, как проверить и как откатить.

### Безопасность

Kanareika только читает данные с серверов. Организации изолированы друг от друга, при смене ключа хоста подключение отклоняется, без явного согласия сканирование не запускается. Веб-интерфейс по умолчанию слушает только localhost, снаружи — только с токеном.

Kanareika не собирает телеметрию и никуда не отправляет данные о вас и ваших серверах, отчёты остаются у вас. Скачиваются только публичные данные: базы уязвимостей (ghcr.io, запасные — mirror.gcr.io и public.ecr.aws), CISA KEV (cisa.gov), EPSS (FIRST, empiricalsecurity.com) и IP-базы DB-IP Lite (db-ip.com), по которым IP-адреса определяются офлайн. Телеметрия встроенного trivy тоже отключена.

**Отказ от ответственности.** Kanareika показывает то, что нашла, но не гарантирует, что нашла всё. Приоритеты и шаги исправления — это рекомендации: проверьте их, прежде чем что-то запускать на серверах. Сканируйте только те серверы, на которые у вас есть права. Программа распространяется «как есть», без каких-либо гарантий ([MIT](../../LICENSE)).

Понравилось — [поставьте звезду](https://github.com/mikekosulin/kanareika). Нашли ошибку — [создайте issue](https://github.com/mikekosulin/kanareika/issues/new/choose) (только без реальных хостов и адресов). Нашли уязвимость — [сообщите приватно](../../SECURITY.md).

[Формат файла организации](../org-file.md) · [История изменений](../../CHANGELOG.md) · [Как помочь проекту](../../CONTRIBUTING.md) · [Лицензия MIT](../../LICENSE)

<h1><img src="../brand/banner-es.png" alt="Kanareika: auditoría de seguridad de sus servidores por SSH"></h1>

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mikekosulin/kanareika/badges/coverage.json)](https://github.com/mikekosulin/kanareika/actions/workflows/coverage.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE) [![Stars](https://img.shields.io/github/stars/mikekosulin/kanareika?style=social)](https://github.com/mikekosulin/kanareika)

[English](../../README.md) · **Español** · [Français](README.fr.md) · [Português](README.pt.md) · [Русский](README.ru.md) · [中文](README.zh.md) · [日本語](README.ja.md) · [한국어](README.ko.md)

Auditoría de seguridad de sus servidores por SSH, sin agentes y de solo lectura: qué parchear primero, quién puede entrar, qué está expuesto y si los hosts están sanos, con pasos de corrección que se pueden revertir. Un solo binario, un YAML por organización; los datos no salen de su máquina.

### Interfaz de terminal

Ejecute `kanareika`. Se abre en «Por hacer»: lo que hay que corregir primero, lo más urgente arriba.

![Datos de demostración, inventados.](../screenshots/tui-es.png)

### Interfaz web

Ejecute `kanareika web` para ver los mismos datos en el navegador, con la tendencia de las últimas 30 ejecuciones.

![Datos de demostración, inventados.](../screenshots/web-es.png)

<sub>Datos de demostración, inventados.</sub>

### Instalación

Homebrew (macOS, Linux); la fórmula fija la versión y su suma de comprobación:

```bash
brew install mikekosulin/tap/kanareika
```

O con el script de instalación: léalo y luego ejecútelo:

```bash
curl -fsSLO https://raw.githubusercontent.com/mikekosulin/kanareika/main/install.sh
less install.sh
sh install.sh
```

Elige la versión para esta máquina, verifica su suma de comprobación (y la atestación de la compilación, si GitHub CLI está instalado) y pregunta antes de instalar en `/usr/local/bin` o `~/.local/bin`; `KANAREIKA_YES=1` omite la pregunta.

O a mano (Linux, macOS): descargue `kanareika-<OS>-<ARCH>.tar.xz` y `SHA256SUMS` de la [última release](https://github.com/mikekosulin/kanareika/releases/latest) y luego:

```bash
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify kanareika-<OS>-<ARCH>.tar.xz --repo mikekosulin/kanareika
tar -xJf kanareika-<OS>-<ARCH>.tar.xz kanareika
```

`<OS>` es `linux` o `darwin`; `<ARCH>`, `amd64` o `arm64`. En macOS, use `shasum -a 256 -c` en lugar de `sha256sum -c`. La comprobación de la atestación requiere GitHub CLI y es opcional; `tar` deja `kanareika` en el directorio actual.

Windows (PowerShell):

```powershell
Invoke-WebRequest https://github.com/mikekosulin/kanareika/releases/latest/download/kanareika-windows-amd64.zip -OutFile kanareika.zip; Expand-Archive kanareika.zip -DestinationPath kanareika
```

Luego ejecute `kanareika.exe` desde la carpeta `kanareika`. En ARM, use `kanareika-windows-arm64.zip` en su lugar.

### Inicio

En la terminal:

```bash
kanareika
```

o en el navegador, en http://127.0.0.1:8088 (solo escucha en localhost):

```bash
kanareika web
```

En el primer inicio le guía para añadir sus servidores (usuario y clave SSH, hosts, consentimiento para el escaneo) y ejecuta el primer escaneo; las bases de vulnerabilidades se descargan solas.

### Para scripts y cron

Cree una organización; su configuración queda en `orgs/<ORG_ID>.yml`:

```bash
kanareika org new <ORG_ID>
```

Escanéela; antes se comprueba el archivo y se descargan las bases:

```bash
kanareika scan <ORG_ID>
```

La interfaz web en otro puerto (`--port 0` toma cualquiera libre):

```bash
kanareika web --port <PORT>
```

La interfaz de terminal conectada a una web remota:

```bash
kanareika tui --url http://<SERVER>:8088 --token <YOUR_SECRET_TOKEN>
```

Red aislada: exporte las bases en una máquina con acceso a internet,

```bash
kanareika db export <BUNDLE.tar.gz>
```

luego impórtelas en la máquina aislada y escanee sin conexión:

```bash
kanareika db import <BUNDLE.tar.gz>
kanareika scan <ORG_ID> --offline
```

Todo lo demás: `kanareika --help`.

**Cuatro formas de acceso, mismos datos y reglas:**

- **TUI**, la principal: `kanareika`: `?` para las teclas, `o` para los paneles, `L` para el idioma. También se conecta a una web remota.
- **Web**: `kanareika web`; paneles, tendencias, fichas de host; los escaneos se lanzan desde la página.
- **Comandos**: para scripts y cron.
- **MCP**: `kanareika mcp`; herramientas de solo lectura para agentes de IA (Claude Code y otros).

**Qué comprueba:**

- **Vulnerabilidades**: paquetes del SO, imágenes, jars y lockfiles mediante trivy, integrado en el binario; backports y disponibilidad de la corrección verificados en el host; prioridades **P1–P4** según KEV, EPSS, exposición y pre-auth RCE.
- **Acceso y exposición**: inicio de sesión SSH con contraseña, claves, accesos y atacantes, puertos abiertos, firewalls, escaneo externo.
- **Salud**: errores del kernel, discos, memoria, sincronización horaria, reinicios pendientes.
- **Corrección**: las acciones seleccionadas se convierten en una tarea lista para un ingeniero o un agente de IA: aplicar, verificar, revertir.
- **Seguro por diseño**: solo lectura, organizaciones aisladas, se rechazan las claves de host cambiadas, ningún escaneo sin consentimiento, la interfaz web solo en localhost (o con token).
- **Privado**: sin telemetría; no envía nada sobre usted ni sobre sus servidores a ningún sitio, y los informes se quedan en su máquina. Solo descarga datos públicos: las bases de vulnerabilidades (ghcr.io, con mirror.gcr.io y public.ecr.aws como alternativas), CISA KEV (cisa.gov), EPSS (FIRST, empiricalsecurity.com) y las bases de IP DB-IP Lite (db-ip.com), con las que las consultas de IP se hacen sin conexión. Incluso la telemetría del trivy integrado está desactivada.

**Aviso legal.** Kanareika informa de lo que encuentra; no promete encontrarlo todo. Las prioridades y los pasos de corrección son recomendaciones: revíselos antes de ejecutar nada en sus hosts. Audite solo los servidores para los que tenga autorización. Se ofrece tal cual, sin garantía ([MIT](../../LICENSE)).

¿Le gusta? [Dele una estrella](https://github.com/mikekosulin/kanareika) · ¿Algo falla? [Abra una incidencia](https://github.com/mikekosulin/kanareika/issues/new/choose) (sin hosts ni direcciones reales, por favor) · ¿Una vulnerabilidad? [Infórmela en privado](../../SECURITY.md)

[Referencia del archivo de organización](../org-file.md) · [Registro de cambios](../../CHANGELOG.md) · [Cómo contribuir](../../CONTRIBUTING.md) · [MIT](../../LICENSE)

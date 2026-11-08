<h1><img src="../brand/banner-ko.png" alt="Kanareika: SSH를 통한 서버 보안 감사"></h1>

[![CI](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml/badge.svg)](https://github.com/mikekosulin/kanareika/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/mikekosulin/kanareika/badges/coverage.json)](https://github.com/mikekosulin/kanareika/actions/workflows/coverage.yml) [![Release](https://img.shields.io/github/v/release/mikekosulin/kanareika)](https://github.com/mikekosulin/kanareika/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE) [![Stars](https://img.shields.io/github/stars/mikekosulin/kanareika?style=social)](https://github.com/mikekosulin/kanareika)

[English](../../README.md) · [Español](README.es.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Русский](README.ru.md) · [中文](README.zh.md) · [日本語](README.ja.md) · **한국어**

에이전트 없이 SSH로 서버를 점검하는 읽기 전용 보안 감사 도구입니다. 무엇부터 패치할지, 누가 접근할 수 있는지, 무엇이 외부에 노출됐는지, 호스트 상태는 괜찮은지 알려 주고, 롤백 가능한 수정 단계까지 제시합니다. 바이너리 하나, 조직마다 YAML 하나, 데이터는 내 컴퓨터에만 남습니다.

### 터미널 인터페이스

`kanareika`를 실행하면 **할 일** 화면이 열립니다. 먼저 고칠 항목이 나오고, 가장 긴급한 항목이 맨 위에 있습니다.

![데모 데이터(가상).](../screenshots/tui-ko.png)

### 웹 인터페이스

`kanareika web`을 실행하면 같은 데이터를 브라우저에서 최근 30회 실행 추이와 함께 볼 수 있습니다.

![데모 데이터(가상).](../screenshots/web-ko.png)

<sub>데모 데이터(가상).</sub>

```bash
brew install mikekosulin/tap/kanareika   # macOS, Linux; 또는 릴리스의 바이너리 (Windows 포함)
kanareika init                   # 여기에 orgs/, secrets/, reports/ 생성 (또는 --home DIR)
kanareika org new myorg          # 호스트, 점프 호스트, 동의: orgs/myorg.yml
kanareika validate myorg
kanareika db update              # 취약점 DB (폐쇄망: db export / db import)
kanareika scan myorg
kanareika                        # 터미널 인터페이스
kanareika web                    # 웹 인터페이스, http://127.0.0.1:8088
```

**네 가지 사용 방식, 같은 데이터와 규칙:**

- **TUI**, 기본 인터페이스 — `kanareika`: `?` 키 목록, `o` 패널, `L` 언어. 원격 웹 서버에도 연결할 수 있습니다: `kanareika tui --url http://host:8088 --token …`.
- **웹** — `kanareika web`: 대시보드, 추이, 호스트 상세; 스캔은 페이지에서 시작합니다.
- **CLI 명령** — 스크립트와 cron용: `kanareika --help`.
- **MCP** — `kanareika mcp`: AI 에이전트(Claude Code 등)를 위한 읽기 전용 도구.

**점검 항목:**

- **취약점** — 바이너리에 내장된 trivy로 OS 패키지, 이미지, jar, lockfile을 검사; 백포트와 수정 버전 제공 여부는 호스트에서 확인; KEV, EPSS, 외부 노출, pre-auth RCE를 기준으로 **P1–P4** 우선순위 지정.
- **접근과 노출** — SSH 비밀번호 로그인, 키, 로그인 기록과 공격자, 열린 포트, 방화벽, 외부 스캔.
- **상태** — 커널 오류, 디스크, 메모리, 시간 동기화, 대기 중인 재부팅.
- **수정** — 선택한 조치가 엔지니어나 AI 에이전트를 위한 작업으로 바로 만들어집니다: 적용, 확인, 롤백.
- **안전한 설계** — 읽기 전용, 조직 간 격리, 변경된 호스트 키 거부, 동의 없이는 스캔하지 않음, 웹 인터페이스는 localhost 전용 (또는 토큰 사용).

**면책 조항.** Kanareika는 찾은 것을 보고할 뿐, 모든 것을 찾아낸다고 보장하지 않습니다. 우선순위와 수정 단계는 권고 사항이므로 호스트에서 무엇이든 실행하기 전에 검토하세요. 감사 권한이 있는 서버만 점검하세요. 어떠한 보증도 없이 "있는 그대로" 제공됩니다 ([MIT](../../LICENSE)).

마음에 드세요? [별 누르기](https://github.com/mikekosulin/kanareika) · 문제가 있나요? [이슈 등록](https://github.com/mikekosulin/kanareika/issues/new/choose) (실제 호스트나 주소는 넣지 마세요) · 취약점인가요? [비공개로 제보](../../SECURITY.md)

[조직 파일 레퍼런스](../org-file.md) · [변경 이력](../../CHANGELOG.md) · [기여 방법](../../CONTRIBUTING.md) · [MIT](../../LICENSE)

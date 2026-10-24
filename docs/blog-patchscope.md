# PatchScope: 보안패치, 이제 "올려보고 확인"이 아니라 "보고 올린다"

> eBPF로 서비스가 실제로 쓰는 OS 패키지를 관측해, 패치 전에는 영향 범위를, 패치 후에는 반영 여부를 근거와 함께 보여주는 PoC

<!--
작성 메모 (게시 전 삭제)
- 🎨 블록: GPT 이미지 생성 프롬프트. 생성한 이미지를 블록 자리에 넣고 블록은 지우세요.
- 📸 블록: 직접 캡처할 화면. 캡처를 블록 자리에 넣고 블록은 지우세요.
- 모든 🎨 프롬프트 뒤에 아래 공통 스타일을 붙이면 톤이 맞습니다.
  Clean flat vector illustration, modern tech blog style, navy (#0f172a) and blue (#1d4ed8) palette with red (#d92d20), orange (#f79009), purple (#7c3aed), green (#16a34a) accents, white background, no text except the labels specified, 16:9.
- 캡처 공통: 브라우저 폭 약 1440px, 확대 90~100%, 시간대 KST. 주소창의 CloudFront 도메인, AWS 계정 ID, 공인 IP, 비밀번호가 보이지 않게.
-->

> 🎨 **이미지 1 · 대표 이미지**
> ```
> A stylized Linux server rack in the center, viewed slightly from above. From the server, glowing thin lines flow upward into floating hexagon-shaped package icons labeled "openssl", "glibc", "libxml2". A magnifying glass with a small bee-like eBPF probe icon inspects the connections. On the right, a shield with a checkmark and a small patch/bandage icon. Leave empty space at the top for a title overlay. Calm, trustworthy, observability theme.
> ```

---

## 1. 왜 만들었나

AI로 취약점이 더 빨리 발견되고 악용되면서 OS 보안패치를 자주 해야 합니다. 하지만 개발자 없이 SM 인력만 남은 레거시 운영 서버는 어떤 서비스가 어떤 패키지를 쓰는지 몰라, 커널만 올리고 마무리하는 경우가 많습니다.

관리가 잘되는 서버도 사정은 크게 다르지 않습니다. 패치 후 어떤 프로세스에 새 라이브러리가 반영됐는지, 패치 전 라이브러리를 계속 쓰는 프로세스는 없는지 확인하기 어렵습니다. 그래서 서비스 영향도를 미리 파악하지 못한 채 **"패치 → 서비스 점검 → 문제 시 롤백"을 DEV, STG, PRD 순서로 반복**합니다.

> 🎨 **이미지 2 · 지금의 패치 방식 (Before / After)**
> ```
> Split-screen illustration. Left side labeled "Before": a stressed operator in front of a dark terminal, question marks floating over three servers labeled DEV, STG, PRD, and a circular arrow labeled "patch → check → rollback". Right side labeled "After": the same operator calmly looking at a dashboard where one service node connects to package nodes with red and orange dots, and a green check labeled "verified". Strong contrast between confusion and clarity.
> ```

PatchScope는 **"서비스를 모니터링하듯 패키지 사용도 관측해서 영향도를 파악해 보자"** 는 생각에서 출발했습니다.

### "설치되어 있다"와 "실제로 쓰고 있다"는 다르다

서버에 패키지가 500개 깔려 있어도, nginx가 실제로 메모리에 올리는 건 그중 일부입니다. 기존 방식(RPM 의존성)은 "설치에 필요하다"까지만 알려주고, PatchScope는 "이 서비스가 이 라이브러리를 실제로 썼다"를 근거로 남깁니다.

> 🎨 **이미지 3 · 설치된 것 vs 실제로 쓰는 것**
> ```
> Concept illustration: a large faded box filled with hundreds of tiny gray package icons labeled "Installed (500 packages)". Inside it, a small highlighted cluster of bright red package icons is connected by lines to a service icon labeled "nginx.service", with the label "Actually used (observed)". A magnifying glass with a bee-like eBPF probe focuses on the bright cluster. Minimal and clear.
> ```

| 질문 | 기존 방식 | PatchScope |
|---|---|---|
| 이 패치가 어떤 서비스에 영향을 주나? | RPM 의존성으로 추정 → 너무 넓거나 놓침 | eBPF로 **실제로 실행·메모리 매핑한** 패키지를 서비스별로 관측 |
| 테스트 환경이 없는데? | 운영에서 바로 패치하고 점검 | 운영 서버에서 **설치 없이 거래만 계산**해 영향 후보를 미리 확인 |
| 패치가 실제로 반영됐나? | 서비스 점검으로 간접 확인 | 패치 명령 전후로 **서비스가 쓰는 버전**을 비교하고 재시작이 필요한 프로세스 표시 |
| 누가, 언제, 무엇을 했나? | 작업 기록을 따로 관리 | dnf 이력(명령·사용자·메모)을 패키지 타임라인으로 정리 |

---

## 2. 한눈에 보기

PatchScope가 하는 일은 다섯 단계입니다.

1. **관측**: 에이전트가 eBPF로 프로세스 실행, 파일 열기, 라이브러리 매핑을 수집합니다.
2. **매핑**: 파일 → RPM 패키지 → 프로세스 → systemd 서비스로 연결합니다.
3. **계획**: 화면에서 패치할 패키지를 고르면, 대상 서버가 dnf 거래를 **계산만** 해서 올립니다.
4. **영향 분석**: 변경 예정 패키지를 실제로 쓴 서비스를 근거와 함께 보여줍니다.
5. **패치 후 확인**: 명령 전후로 서비스별 사용 버전을 비교하고, 재시작이 필요한 프로세스를 표시합니다.

> 🎨 **이미지 4 · 5단계 흐름**
> ```
> Horizontal 5-step infographic with numbered circular icons connected by one arrow: 1 "Observe" (eye with a bee-like eBPF probe), 2 "Map" (file → package → service chain), 3 "Plan" (clipboard with calculator, small label "resolve only"), 4 "Analyze impact" (target with highlighted services), 5 "Verify after patch" (version arrow old → new with a small restart icon). Evenly spaced, icon-centric, minimal.
> ```

---

## 3. 전체 아키텍처

> 🎨 **이미지 5 · 전체 아키텍처**
> ```
> Cloud architecture diagram in AWS style. Left: an operator laptop with a browser, arrow to a "CloudFront" icon with small tags "HTTPS", "cache off", "IP allow". A large rounded rectangle labeled "VPC" contains: an "Analysis Server" box with three stacked layers "nginx", "FastAPI", "PostgreSQL"; two "Target Server" boxes labeled "RHEL 8.10" and "Amazon Linux 2023", each containing a bee icon "eBPF agent" and a small box "plan-export". CloudFront connects to the Analysis Server with a dashed line labeled "VPC origin (private)". Solid arrows from each Target Server to the Analysis Server labeled "HTTPS (private CA) · every 10s", and a thin dotted arrow back labeled "task pull". Small side icons "SSM Session Manager" and "Terraform". Clean lines, readable labels.
> ```

```
                    ┌──────────────────────── AWS VPC ───────────────────────────────────────┐
 운영자 브라우저     │   ┌──────────────┐  HTTPS(사설 CA)   ┌──────────────────────────────┐   │
   │  HTTPS          │   │ 대상 서버      │  ── 10초 batch ─▶ │ 분석 서버                      │   │
   ▼                 │   │ (RHEL 8.10 /  │  ◀─ 계산 요청 pull │  nginx → FastAPI → PostgreSQL │   │
 CloudFront ─────────┼─▶ │  AL2023)      │                   │  - 수집 API (443, 사설 CA)    │   │
 (기본 인증서,       │   │  eBPF 에이전트 │                   │  - 웹 화면 (80, CloudFront 전용)│   │
  캐시 OFF,          │   │  plan-export  │                   └──────────────────────────────┘   │
  IP 허용 함수)      │   └──────────────┘          ▲ VPC origin (인터넷 경유 없음)               │
                    └──────────────────────────────────────────────────────────────────────────┘
 관리 접속: SSM Session Manager (SSH 미개방) · 인프라: Terraform
```

| 구성 | 역할 | 기술 |
|---|---|---|
| **에이전트** (대상 서버) | 실행·종료, 파일 열기(성공/실패), 파일 기반 mmap 수집. `/proc` 스냅샷으로 이미 실행 중인 프로세스 보완. RPM 인벤토리·dnf 이력 전송 | eBPF (C, CO-RE, tracepoint) + Go 정적 바이너리 |
| **plan-export** (대상 서버) | dnf 거래를 **계산만** 함 (설치·재시작 안 함). 업데이트 가능 목록, 거래 이력 조회 | Python dnf API |
| **분석 서버** | 수신·중복 제거·저장, 영향 분석, 웹 화면, JSON/CSV 보고서 | FastAPI, PostgreSQL, 서버 렌더링 HTML, SVG |
| **CloudFront** | 도메인 구입 없이 기본 인증서로 HTTPS. 캐시 끔. 접속 IP 허용 목록 | VPC origin + CloudFront Function |
| **인프라** | VPC, EC2 3대, IAM, S3(빌드 산출물), CloudFront | Terraform, SSM |

### 통신 원칙

- **에이전트는 서버로 나가는 HTTPS만 씁니다.** 서버가 대상 서버에 접속하거나 명령을 보내는 경로는 없습니다.
- 패치 계획 계산도 "서버에 요청 저장 → 에이전트가 가져가서(pull) 계산 → 결과 업로드" 방식입니다. 에이전트가 실행할 수 있는 동작은 **거래 계산 2가지로 고정**되어 있습니다.
- 에이전트 토큰은 대상 서버에서 만들고 서버에는 **해시만** 등록합니다. 토큰, CA 개인키, 관리자 비밀번호는 Terraform, Git, user-data 어디에도 남지 않습니다.
- 분석 서버의 공인 포트는 닫혀 있고, 웹은 CloudFront VPC origin으로만 들어옵니다.

> 📸 **캡처 A (선택) · CloudFront VPC origin**
> - 위치: AWS 콘솔 → CloudFront → 왼쪽 메뉴 **VPC origins**
> - 찍을 것: `patchscope-analysis` VPC origin이 EC2 인스턴스 ARN을 가리키고 상태가 `Deployed`인 화면
> - 가릴 것: 계정 ID(ARN 안의 12자리 숫자)

---

## 4. 무엇을 어떻게 관측하나

### 4.1 "실제로 쓴다"의 근거

| 근거 | 수집 방법 | 의미 |
|---|---|---|
| 실행 파일 | `sched_process_exec` tracepoint, `/proc/PID/exe` | 이 바이너리를 실행했다 |
| 메모리 매핑 | `mmap` tracepoint, `/proc/PID/maps` | 이 라이브러리를 메모리에 올렸다 → **직접 사용** |
| 파일 열기 | `openat`/`open` tracepoint, `/proc/PID/fd` | 파일을 열었다 (로딩·실행은 모름) → **파일 접근** |
| 서비스 귀속 | 이벤트 시점의 cgroup (커널에서 직접 읽음) | 이 프로세스는 `php-fpm.service` 소속이다 |

eBPF를 먼저 붙이고 `/proc` 스냅샷을 읽습니다. 에이전트보다 먼저 떠 있던 프로세스(예: nginx)는 스냅샷으로, 이후 생기는 짧은 배치·CLI 프로세스는 eBPF 이벤트로 잡습니다.

> 🎨 **이미지 6 · 에이전트가 보는 것**
> ```
> Diagram of a Linux host split into two layers: "User space" on top with process icons (nginx, php-fpm, a short-lived "cron job" icon fading out) and "Kernel" at the bottom. Small bee-like eBPF probes sit on kernel hooks labeled "exec", "open", "mmap", "exit". Thin arrows from the probes go up to an "Agent" box, which also reads a folder icon labeled "/proc snapshot". The Agent sends a stack of envelopes labeled "batches" to the right. Technical but friendly.
> ```

### 4.2 파일 → 패키지 → 서비스

```
/usr/lib64/libcrypto.so.3.0.8 ─(RPM 소유)─▶ openssl-libs-1:3.0.8-1 ─▶ php-fpm(pid 1234) ─▶ php-fpm.service
```

- 경로는 **커널이 본 파일(device/inode)과 지금 디스크의 파일이 같을 때만** 확정합니다. 확정 못 하면 `unresolved`로 남기고 추측하지 않습니다.
- RPM이 소유하지 않는 파일은 `unmanaged`로 표시하고, "영향 없음"으로 처리하지 않습니다.
- 프로세스는 PID만이 아니라 `호스트 + 부팅 + PID + 시작 시각`으로 구분합니다 (PID 재사용 대비).

### 4.3 이 도구가 "말하지 않는 것"

| 원칙 | 이유 |
|---|---|
| **미관측 ≠ 안전** | 관측 기간에 실행되지 않은 기능은 알 수 없습니다. "관측 없음"으로만 표시합니다 |
| **파일 열기 ≠ 함수 사용** | 열기만 한 파일은 "파일 접근", 매핑·실행은 "직접 사용"으로 구분합니다 |
| **커널은 별도 검증** | 모든 프로세스가 커널을 쓰므로 시스템 호출 관측으로 커널 호환성을 판정하지 않습니다 |
| **손실은 숨기지 않음** | 이벤트 손실이 있는 구간은 "불완전"으로 표시합니다 |

---

## 5. 화면 투어: 어디에 들어가면 무엇을 확인하나

### 5.1 서버 목록 (첫 화면)

로그인하면 관측 중인 서버가 카드로 보입니다. 서버별 수집 상태(정상/끊김/일부 제한), OS·커널, 최근 24시간 관측 서비스 수, 업데이트 가능 패키지 수를 한눈에 봅니다.

> 📸 **캡처 1 · 서버 목록**
> - 위치: 로그인 후 첫 화면 `/`
> - 찍을 것: 서버 카드 2개(`patchscope-al2023`, `patchscope-rhel8`) 전체. 각 카드의 초록 상태 점, OS, 커널, 관측 서비스 수, 업데이트 가능 수가 보이게
> - 포인트: 카드 아래 "패치 계획 만들기" 버튼까지 포함

### 5.2 패치 계획 만들기

카드의 **패치 계획 만들기**를 누르면 두 단계로 진행합니다.

1. **업데이트 목록 확인**: 에이전트가 저장소를 조회해 업데이트 가능한 패키지를 올립니다 (시험 환경 기준 RHEL 214개, AL2023 308개).
2. **범위 선택**: 선택한 패키지 / 전체 / 커널만. 패키지마다 **최근 24시간 동안 이 패키지를 쓴 서비스 수**가 표시되어 고르기 쉽습니다.

**계획 계산 요청**을 누르면 대상 서버가 종속 패키지까지 계산합니다 (30~80초). 설치는 하지 않습니다.

> 📸 **캡처 2 · 패치 계획 만들기**
> - 위치: 서버 카드 → **패치 계획 만들기** (`/hosts/{서버}/plans/new`)
> - 찍을 것: 1단계 "N개 패키지를 업데이트할 수 있습니다" 문구 + 2단계 범위 선택 3칸 + 검색창에 `openssl` 입력한 뒤의 목록
> - 포인트: 목록 오른쪽 "최근 사용 서비스" 빨간 배지(예: `12개 서비스`)가 보이게

### 5.3 영향 분석

계획 계산이 끝나면 영향 분석이 만들어집니다. 맨 위에서 결론부터 보여줍니다.

- **요약 숫자 4개**: 영향 후보 서비스, 직접 사용 패키지, 파일 접근·정적 의존, 관측 없음
- **근거 범위**: 몇 시간을 관측했는지, 손실은 없는지, 계획이 완전한지

> 📸 **캡처 3 · 영향 분석 상단**
> - 위치: **패치 계획·영향 분석** 탭 → 계획 하나 클릭 (`/plans/{번호}`)
> - 찍을 것: 요약 숫자 4개 + "근거 범위" 초록/노란 안내 박스 + 분류 설명 4칸(직접 사용 / 파일 접근 / 정적 의존 / 관측 없음)

| 분류 | 뜻 |
|---|---|
| 🔴 직접 사용 | 변경 패키지의 실행 파일·라이브러리를 실행하거나 메모리에 매핑 |
| 🟠 파일 접근 | 파일을 열었지만 로딩·실행은 미확인 |
| 🟠 정적 의존 | RPM 의존 관계로만 연결 |
| ⚪ 관측 없음 | 관측 기간에 사용이 보이지 않음 (안전 판정 아님) |

그 아래 **서비스별 영향** 표에서 "이 패치가 nginx에 영향이 있나?"를 검색으로 바로 확인하고, **패키지별 근거**에서 어떤 프로세스가 어떤 파일을 언제 썼는지 펼쳐 봅니다. 커널 계획이면 실행·설치·목표 커널, 로드된 모듈, 재부팅 후 확인 항목이 따로 나옵니다.

> 📸 **캡처 4 · 서비스별 영향 표**
> - 위치: 같은 페이지 아래 "서비스별 영향"
> - 찍을 것: 검색창에 `nginx` 또는 `php` 입력 후 남은 행. 서비스 이름과 빨간 패키지 배지(`openssl-libs` 등)가 보이게

### 5.4 서비스 의존성 맵

**서비스 의존성** 탭에서 서비스를 고르면, 그 서비스가 실제로 쓴 패키지를 방사형 맵으로 보여줍니다.

- 가운데 서비스 → 안쪽 프로세스 → 바깥 **실제로 사용한 RPM 패키지** (시험 환경 php-fpm은 약 59개)
- 🔴 실행·매핑 / 🟠 파일 열기만 / 🟣 테두리 = **업데이트 대기 중**
- 가장 바깥 점선 링: 사용은 관측되지 않았지만 RPM 의존으로 끌려오는 패키지

> 📸 **캡처 5 · 의존성 맵**
> - 위치: **서비스 의존성** 탭 → `php-fpm.service` 클릭
> - 찍을 것: 상단 요약 숫자 + "의존성 맵" 원 전체 (가운데 php-fpm.service, 빨간 점, 보라 테두리, 바깥 점선 링)
> - 팁: 원이 한 화면에 다 들어오게 브라우저를 축소(80% 정도)

맵 아래 표에서 패키지 옆 **`+`** 를 누르면, 그 패키지가 다시 의존하는 패키지가 트리로 펼쳐집니다. 각 항목에 "이 서비스에서 사용 관측"과 "정적 의존만"이 구분되어 표시됩니다.

> 📸 **캡처 6 · 의존 트리 펼치기**
> - 위치: 같은 페이지 아래 패키지 표
> - 찍을 것: `php8.1-common`(RHEL은 `php-common`) 또는 `libxml2`의 `+ 의존 N`을 2단계까지 펼친 상태. 빨간 "사용 관측" 배지와 회색 "정적 의존만" 배지가 같이 보이게

### 5.5 패키지 변경 이력 (타임라인)

맵의 노드나 표의 패키지 이름을 누르면, 그 패키지 하나가 **언제, 누가, 어떻게** 바뀌었는지 시간순으로 나옵니다. 관측 기간을 고를 필요가 없습니다.

| 표시 | 내용 |
|---|---|
| 🔵 계획 | 이 패키지가 들어간 패치 계획과 영향 분석 |
| 🟣 설치 | dnf 거래: 언제, 누가, 실행한 명령, 메모 |
| 🩵 감지 | 에이전트가 설치 버전 변화를 발견 |
| 🟢 반영 | **서비스가 새 버전을 실제로 쓰기 시작** (관측) |
| 🟠 부팅 | 재부팅, 커널 변화 |

설치 버전과 서비스가 쓰는 버전이 다르면 맨 위에 **"재시작 필요 가능성"** 안내가 뜹니다.

> 📸 **캡처 7 · 패키지 타임라인**
> - 위치: 서비스 상세 표에서 `openssl-libs`의 **변경 이력 →** 클릭 (`/hosts/{서버}/packages/openssl-libs?unit=...`)
> - 찍을 것: 상단 요약 3칸(현재 설치 버전 / 서비스가 마지막으로 쓴 버전 / 업데이트 가능) + "버전별 사용 기간" + 타임라인 위쪽 4~5개(계획 → 설치 → 감지 → 반영 → 부팅)
> - 포인트: 설치 이벤트의 "메모: PatchScope PoC 보안패치 / 계획 #N"이 보이게

### 5.6 변경 작업 (명령 기준)

운영자가 실제로 입력한 패치 명령을 기준점으로 전후를 비교하는 화면입니다. 목록에는 서버에서 실행된 dnf 명령이 시간순으로 나옵니다.

> 📸 **캡처 8 · 변경 작업 목록**
> - 위치: **변경 작업 (명령 기준)** 탭 (`/hosts/{서버}/changes`)
> - 찍을 것: 명령 목록 표. `dnf ... --comment "PatchScope PoC ..." upgrade ...` 행과 파란 "메모" 배지, "로그인 세션 없음" 표시, 성공 배지

명령을 누르면 그 시점 전후로 서비스가 어떻게 바뀌었는지 바로 보여줍니다.

- 실행한 명령, 시각, 누가(dnf loginuid), 메모(`dnf --comment`)
- 이 변경 전에 **영향 분석을 했는지** (사전 계획 링크)
- 서비스별 **이전 버전 → 새 버전**과 상태: 반영됨 / 이전 버전 계속 사용 / 재시작 필요
- 교체 전(삭제된) 라이브러리를 아직 매핑 중인 프로세스와 권장 조치 (`systemctl restart ...`)

> 📸 **캡처 9 · 변경 작업 상세**
> - 위치: 위 목록에서 보안패치(또는 전체 업데이트) 명령 클릭 (`/hosts/{서버}/changes/{번호}`)
> - 찍을 것: 검은 박스의 명령줄 + 시각/누가/메모/사전 영향 분석 + 요약 숫자 4개 + "서비스별 전후" 카드 2~3개
> - 포인트: 빨간 "재시작 필요" 카드와 초록 "새 버전 반영" 카드가 같이 보이면 가장 좋습니다. 재부팅 전에 찍어야 "재시작 필요"가 남아 있습니다

> 🎨 **이미지 7 · 패치 후 재시작 필요 개념**
> ```
> Illustration of a process box labeled "redis" still holding an old, faded library tile labeled "libssl (old, deleted)", while the disk next to it now holds a fresh library tile labeled "libssl (new)". A red tag "restart needed" hangs on the process. Next to it, another process box "nginx" holding the fresh tile with a green check "new version in use". Simple, explanatory.
> ```

### 5.7 관측 기간 비교와 관측 기간

- **관측 기간 비교**: 두 관측 기간을 서비스 단위 카드로 비교합니다. 🔵 버전 변경 / 🟢 새로 사용 / 🔴 사용 사라짐. 기본값은 설치 패키지나 부팅이 바뀐 시점 전후를 자동으로 고릅니다.
- **관측 기간**: 에이전트가 쉬지 않고 관측한 구간 목록입니다. 손실 여부, 재부팅(boot ID), 기간 중 패키지 변경 여부를 보여줍니다.

> 📸 **캡처 10 · 관측 기간 비교**
> - 위치: **관측 기간 비교** 탭 (`/hosts/{서버}/compare`)
> - 찍을 것: 상단 요약 숫자(버전 변경 / +새로 사용 / −사용 사라짐) + 색 범례 + 서비스 카드 1~2개를 펼친 상태
> - 포인트: 파란 "버전 변경" 줄에서 이전 버전 취소선 → 굵은 새 버전이 보이게

---

## 6. 실제로 돌려본 시나리오

**환경**: AWS 서울 리전, Terraform으로 3대 구성 (분석 서버 1대 + 일부러 오래된 AMI로 만든 대상 서버 2대)

| | RHEL 8.10 | Amazon Linux 2023 |
|---|---|---|
| 시작 커널 | 4.18.0-553 (2024-05 AMI) | 6.1.15 (2023-03 AMI) |
| 작업 부하 | nginx, PHP-FPM(확장 8종), PostgreSQL, Redis, Python 배치(psycopg2·lxml·ssl), curl/openssl 주기 작업 | 동일 |

PHP-FPM 워커 하나가 libpng, libxml2, ICU, libpq, libcurl, openssl-libs 등 RPM 약 55개를 동시에 씁니다. "프로세스 하나가 여러 패키지를 쓰는" 실제 환경에 가깝게 만들었습니다. 일부 기능(`intl.php`, 압축 내보내기 작업)은 일부러 실행하지 않아, "실행하지 않은 기능은 관측 없음으로 남는다"도 같이 확인했습니다.

**진행 순서**
1. 패치 전 같은 작업을 수행하며 관측
2. 화면에서 패치 계획 생성 → 영향 분석 확인
3. `dnf upgrade --comment "PatchScope PoC 보안패치 / 계획 #N / 작업: ..."` 실행
4. nginx·php-fpm·postgresql만 재시작 (redis·sshd는 일부러 그대로)
5. 패치 후 같은 작업 수행 → 변경 작업 화면에서 전후 확인
6. 커널 업데이트 → 재부팅 → 에이전트 재연결·사전 점검 확인

> 🎨 **이미지 8 · 시나리오 타임라인**
> ```
> Horizontal timeline with colored milestone markers in order: blue "Plan & impact analysis", purple "dnf upgrade --comment", teal "Agent detects version change", green "Service uses new library", red warning "Restart needed: redis", orange "Kernel update & reboot". Below the line, two small server icons labeled "RHEL 8.10" and "AL2023" with version arrows "openssl 1.1.1k-12 → 1.1.1k-18" and "openssl 3.0.8 → 3.5.8". Infographic style.
> ```

**결과**

| | RHEL 8.10 | AL2023 |
|---|---|---|
| 패키지 패치 | openssl 1.1.1k-12 → 1.1.1k-18<br>glibc 2.28-251 → 2.28-251.el8_10.48 | openssl 3.0.8 → 3.5.8 (종속으로 openssh 포함 6개) |
| 영향 분석 (openssl-libs 계획) | 영향 후보 서비스 47개 | 영향 후보 서비스 43개 |
| 기능 시험 (전 → 후) | 27/27 → 27/27 | 27/27 → 27/27 |
| 커널 | 4.18.0-553 → 553.177.1 | 6.1.15 → 6.1.188 |
| 재부팅 후 | 새 boot ID, 실패 유닛 없음, 에이전트 재연결·`supported` | 동일 |

> 영향 후보 수에는 sshd, journald 같은 시스템 서비스도 들어 있습니다. openssl·glibc처럼 거의 모든 프로세스가 쓰는 패키지는 범위가 넓게 나오는 게 정상이라, 화면에서는 개수보다 **"어떤 서비스가 어떤 근거로"** 를 먼저 보여줍니다.

> 📸 **캡처 11 (선택) · 재부팅 후 사전 점검**
> - 위치: 대상 서버 SSM 세션에서 `sudo /opt/patchscope/bin/patchscope-agent precheck`
> - 찍을 것: 첫 줄 `status=supported ... kernel=<새 커널>` 과 마지막 `attached:` 목록

---

## 7. 기술적으로 신경 쓴 부분 (큰 그림)

### 오래된 커널과 최신 커널을 같은 바이너리로

- **CO-RE (Compile Once, Run Everywhere)**: 분석 서버에서 한 번 빌드한 eBPF 오브젝트가 RHEL 8(4.18 백포트 커널)과 AL2023(6.1)에서 그대로 로드됩니다. 커널마다 다른 구조체 필드(예: 프로세스 시작 시각)는 CO-RE로 처리합니다.
- **perf buffer**: RHEL 8에서도 확실히 되는 perf buffer로 이벤트를 전달합니다.
- **사전 점검**: OS 이름만 보고 지원한다고 판단하지 않고, BTF 파싱, tracepoint 존재, 실제 로드·연결까지 시험한 뒤 `supported / degraded / unsupported`로 판정합니다.
- 대상 서버에는 컴파일러가 필요 없습니다 (정적 Go 바이너리 1개 + 계산 도구).

> 🎨 **이미지 9 · CO-RE 개념**
> ```
> One glowing eBPF program capsule labeled "built once" in the center, with three arrows going to three different kernel blocks labeled "RHEL 8 · 4.18", "AL2023 · 6.1", "Newer kernel". Each kernel block shows slightly different internal gear shapes, and a small adapter piece labeled "BTF" fits the capsule into each. Clean, conceptual.
> ```

### 정확한 경로와 서비스 귀속

- 상대 경로로 연 파일은 사용자 공간에서 확인할 때 디렉터리 fd가 이미 닫혀 있을 수 있습니다. 그래서 **커널에서 dentry 경로를 직접 만들고**, 사용자 공간에서 device/inode가 같은지 다시 확인합니다.
- 금방 끝나는 프로세스도 **이벤트 시점의 cgroup을 커널에서 읽어** 정확한 서비스에 귀속합니다.

### 패치 후 "반영됐나?"

- 패키지가 바뀌면 에이전트가 60분 동안 1분마다 모든 프로세스의 매핑에서 **교체 전(삭제된) 라이브러리**를 찾습니다 (`needs-restarting`과 같은 근거).
- 교체 전 파일의 소유 패키지는 **변경 전 인벤토리**로 해석해서, 지금 경로의 새 파일과 섞지 않습니다.

### 믿을 수 있는 수집

- 전송 실패 시 디스크 spool(기본 1 GiB)에 쌓았다가 재전송하고, batch ID로 중복을 막습니다.
- 커널 손실, 사용자 공간 큐 손실, spool 삭제를 따로 집계해 "불완전" 구간으로 표시합니다.
- 시험: 분석 서버 경로를 90초 막았더니 batch 9개가 spool에 쌓였고, 복구 후 5~10초 안에 공백 없이 전송됐습니다.

> 📸 **캡처 12 (선택) · 관측 기간 목록**
> - 위치: **관측 기간** 탭 (`/hosts/{서버}/periods`)
> - 찍을 것: 초록 "손실 없음" 배지가 이어진 행들과, 재부팅으로 커널·boot ID가 바뀐 행이 함께 보이게

---

## 8. 검증 결과 요약

| 항목 | 결과 |
|---|---|
| 정답을 아는 스모크 시험 (두 OS) | 17/17 통과 (실행 파일·libc·openssl → RPM 연결, 실패한 open 분리, 상대 경로, PID 재사용, unmanaged 표시, 손실 0 등) |
| 전송 장애 | 90초 차단 후 손실 없이 재전송 |
| 중복 전송 | 첫 요청 200, 재전송 409 |
| 잘못된 CA / 토큰 | TLS 검증 실패 / 401로 거부, 데이터는 spool에 보존 |
| 화면 보안 | 미로그인 리다이렉트, CSRF 403, 잘못된 패키지 이름 400 |

**성능 (솔직하게)**: 2 vCPU 서버에 요청마다 새 연결로 초당 약 2,500건, 짧은 프로세스 반복 실행을 섞은 최악 조건입니다.

| | AL2023 | RHEL 8.10 | 제안 목표 |
|---|---|---|---|
| p95 지연 | +22.6% | +7.6% | +5% 이하 |
| 에이전트 CPU | 1코어의 21% | 1코어의 17% | 5% 이하 |
| 에이전트 메모리 | 97 MiB | 89 MiB | 200 MiB 이하 |
| 이벤트 손실 | 0 | 0 | — |

메모리는 목표 안이지만 CPU와 지연은 목표를 넘었습니다. 파일 열기마다 큰 이벤트를 만들고 경로를 끝까지 따라가기 때문입니다. 같은 파일을 반복해서 여는 이벤트를 커널 안에서 걸러내는 개선이 다음 과제입니다. 실제 운영 부하는 이 시험보다 훨씬 낮은 경우가 많지만, 적용 전에는 실제 부하로 다시 재봐야 합니다.

---

## 9. 한계와 다음 단계

**한계**
- 관측 기간에 실행되지 않은 기능은 알 수 없습니다. 그래서 "관측 없음"을 안전으로 표시하지 않습니다.
- Java·Python 내부 라이브러리(JAR, pip 패키지) 단위 분석은 범위 밖입니다. OS 파일 접근으로만 보입니다.
- 컨테이너·다른 mount namespace는 호스트 파일과 동일성이 확인될 때만 RPM으로 연결합니다.
- dnf의 "누가"는 로그인 세션 기준이라 자동화·원격 명령은 비어 있습니다. `dnf --comment`로 작업자를 남기는 것을 권장합니다.
- 정적 의존은 capability 이름 기준이며 버전 조건까지 판정하지는 않습니다.

**다음 단계**
- 커널 안에서 반복 이벤트를 집계해 성능 개선
- 서비스 중요도(사용자 입력)를 반영한 우선순위
- 변경 작업 화면 기반 패치 체크리스트·보고서 자동 생성
- RHEL 9, AL2 5.10 등 추가 커널 검증

---

## 10. 마치며

보안패치는 이제 "가끔 하는 큰 작업"이 아니라 "자주 하는 운영 업무"가 되어가고 있습니다. 그런데 패치에서 가장 큰 비용은 패치 자체보다 **"이걸 올려도 되나?"를 판단하는 시간**과 **"제대로 반영됐나?"를 확인하는 시간**입니다.

PatchScope는 그 두 질문에 대해, 서비스를 모니터링하듯 패키지 사용을 관측해서 **근거**를 보여주려는 시도입니다. 개발자가 떠난 레거시 서버에서도, DEV-STG-PRD를 거치는 잘 관리된 서버에서도, "올려보고 확인"보다 한 걸음 앞서 "보고 올리는" 데 도움이 되길 바랍니다.

> 🎨 **이미지 10 · 마무리 이미지 (선택)**
> ```
> A calm operator at a desk looking at a dashboard with a service map and a green "verified" badge, while behind them three server racks labeled DEV, STG, PRD glow steadily with small shield icons. Warm, confident, minimal.
> ```

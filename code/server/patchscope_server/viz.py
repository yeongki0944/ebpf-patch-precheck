"""서버 렌더링 SVG 시각화 (외부 JS/라이브러리 없음, CSP 'self' 유지).

service_map: 가운데 서비스 → 안쪽 원 프로세스 → 바깥 원 RPM 패키지 (방사형 트리)
"""
import math
import re
from html import escape

COL_EXEC = "#d92d20"    # 실행·매핑
COL_FILE = "#f79009"    # 파일 열기만
COL_PROC = "#1d4ed8"
COL_SVC = "#0f172a"
COL_UPD = "#7c3aed"     # 업데이트 대기
MAX_PKG = 160


def evr(nevra: str, name: str | None = None) -> str:
    """name-epoch:version-release.arch → version-release (epoch 0 생략, arch 생략)."""
    s = nevra
    if name and s.startswith(name + "-"):
        s = s[len(name) + 1:]
    ep, _, rest = s.partition(":")
    if not rest:
        rest, ep = ep, "0"
    rest = rest.rsplit(".", 1)[0] if "." in rest else rest
    return rest if ep == "0" else f"{ep}:{rest}"


def _vercmp_key(s: str):
    """rpmvercmp 와 같은 순서: 숫자/문자 구간 비교, 숫자 > 문자, '~' 는 가장 낮음."""
    parts = []
    for m in re.finditer(r"~|\d+|[A-Za-z]+", s):
        t = m.group()
        parts.append((-1, 0, "") if t == "~" else (2, int(t), "") if t.isdigit() else (1, 0, t))
    return tuple(parts) + ((0, 0, ""),)


def evr_key(nevra: str):
    """NEVRA 의 (epoch, version, release) 정렬 키."""
    m = re.match(r"^.*-(\d+):([^-]+)-([^-]+)$", nevra)
    if not m:
        return ((0,), _vercmp_key(nevra), ())
    ep, ver, rel = m.groups()
    rel = rel.rsplit(".", 1)[0]
    return ((int(ep),), _vercmp_key(ver), _vercmp_key(rel))


def service_map(unit: str, pk: list[dict], procs: list[dict], updates: dict[str, str]) -> dict:
    """pk: name, nevra, executed, comms / procs: comm, n / updates: name -> 목표 nevra."""
    comms = [p["comm"] for p in procs if p["comm"]][:12] or ["(process)"]
    ci = {c: i for i, c in enumerate(comms)}
    pkgs = sorted(pk, key=lambda p: (min((ci.get(c, 99) for c in p["comms"] or []), default=99),
                                     not p["executed"], p["name"]))[:MAX_PKG]
    n = max(len(pkgs), 1)
    r2 = max(230.0, n * 15 / (2 * math.pi))
    r1 = r2 * 0.42 if len(comms) > 1 else 0.0
    pad = 175
    size = 2 * (r2 + pad)
    cx = cy = size / 2
    out = []

    # 프로세스 위치
    ppos = {}
    for i, c in enumerate(comms):
        a = -math.pi / 2 + 2 * math.pi * i / len(comms)
        ppos[c] = (cx + r1 * math.cos(a), cy + r1 * math.sin(a))

    # 패키지 위치 + 간선
    nodes, edges = [], []
    for i, p in enumerate(pkgs):
        a = -math.pi / 2 + 2 * math.pi * i / n
        x, y = cx + r2 * math.cos(a), cy + r2 * math.sin(a)
        for c in (p["comms"] or [])[:4]:
            if c in ppos:
                px, py = ppos[c]
                # 중심 쪽으로 휘는 곡선
                mx, my = (px + x) / 2 * 0.85 + cx * 0.15, (py + y) / 2 * 0.85 + cy * 0.15
                edges.append(f'<path d="M{px:.1f},{py:.1f} Q{mx:.1f},{my:.1f} {x:.1f},{y:.1f}" '
                             f'stroke="{COL_EXEC if p["executed"] else COL_FILE}" stroke-opacity=".28" fill="none" stroke-width="1"/>')
        nodes.append((p, a, x, y))

    out.append(f'<g aria-hidden="true">{"".join(edges)}</g>')
    for c, (px, py) in ppos.items():
        if r1:
            out.append(f'<line x1="{cx:.1f}" y1="{cy:.1f}" x2="{px:.1f}" y2="{py:.1f}" stroke="{COL_PROC}" stroke-opacity=".5" stroke-width="2"/>')

    for p, a, x, y in nodes:
        col = COL_EXEC if p["executed"] else COL_FILE
        upd = updates.get(p["name"])
        deg = math.degrees(a)
        left = 90 < (deg % 360) < 270
        lx, ly = cx + (r2 + 12) * math.cos(a), cy + (r2 + 12) * math.sin(a)
        rot = deg + 180 if left else deg
        anchor = "end" if left else "start"
        label = escape(p["name"] if len(p["name"]) <= 24 else p["name"][:23] + "…")
        tip = escape(f'{p["name"]} {evr(p["nevra"], p["name"])}\n근거: {"실행·매핑" if p["executed"] else "파일 열기만"}'
                     f'\n프로세스: {", ".join(p["comms"] or [])}' + (f'\n업데이트 가능 → {evr(upd, p["name"])}' if upd else ""))
        ring = (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9.5" fill="none" stroke="{COL_UPD}" stroke-width="2.5"/>' if upd else "")
        weight = ' font-weight="700"' if upd else ""
        out.append(
            f'<a href="#pkg-{escape(p["name"])}"><title>{tip}</title>{ring}'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5.5" fill="{col}"/>'
            f'<text x="{lx:.1f}" y="{ly:.1f}" font-size="11" dominant-baseline="middle" text-anchor="{anchor}"'
            f' transform="rotate({rot:.1f} {lx:.1f} {ly:.1f})" fill="{"#4c1d95" if upd else "#1f2933"}"{weight}>{label}</text></a>')

    for c, (px, py) in ppos.items():
        if r1:
            w = 14 + 7 * len(c)
            out.append(f'<g><title>{escape(c)} 프로세스</title><rect x="{px - w / 2:.1f}" y="{py - 12:.1f}" width="{w}" height="24" rx="12" fill="{COL_PROC}"/>'
                       f'<text x="{px:.1f}" y="{py:.1f}" font-size="12" fill="#fff" text-anchor="middle" dominant-baseline="middle">{escape(c)}</text></g>')

    title = unit if len(unit) <= 30 else unit[:29] + "…"
    sub = comms[0] if not r1 else f"프로세스 {len(comms)}종"
    w = max(150, 8 * len(title) + 30)
    out.append(f'<g><rect x="{cx - w / 2:.1f}" y="{cy - 26:.1f}" width="{w}" height="52" rx="12" fill="{COL_SVC}"/>'
               f'<text x="{cx:.1f}" y="{cy - 6:.1f}" font-size="14" font-weight="700" fill="#fff" text-anchor="middle">{escape(title)}</text>'
               f'<text x="{cx:.1f}" y="{cy + 13:.1f}" font-size="11" fill="#cbd5e1" text-anchor="middle">{escape(sub)} · 패키지 {len(pkgs)}</text></g>')

    desc = (f"{unit} 서비스가 사용한 RPM 패키지 {len(pkgs)}개. 실행·매핑 {sum(p['executed'] for p in pkgs)}개, "
            f"파일 열기만 {sum(not p['executed'] for p in pkgs)}개, 업데이트 대기 {sum(p['name'] in updates for p in pkgs)}개. 아래 표에 같은 내용이 있습니다.")
    svg = (f'<svg viewBox="0 0 {size:.0f} {size:.0f}" role="img" aria-labelledby="mapT mapD" class="svcmap" '
           f'font-family="system-ui, Malgun Gothic, sans-serif">'
           f'<title id="mapT">{escape(unit)} 의존성 맵</title><desc id="mapD">{escape(desc)}</desc>{"".join(out)}</svg>')
    return {"svg": svg, "shown": len(pkgs), "total": len(pk)}

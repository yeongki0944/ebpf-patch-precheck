"""웹 화면 (서버 렌더링). 브라우저 로그인 필요.

대상 서버에는 접속하지 않는다. 패치 계획은 "계산 요청"을 저장하면 에이전트가 가져가 계산만 수행한다.
"""
import csv
import io
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from urllib.parse import urlencode

from . import analysis, auth, db, deps, tasks, timeline, viz

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
KST = timezone(timedelta(hours=9))


def _dt(v):
    if v is None:
        return None
    if isinstance(v, str):
        v = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


def fmt_ts(v, tz="KST"):
    v = _dt(v)
    if v is None:
        return ""
    return v.astimezone(KST if tz == "KST" else timezone.utc).strftime("%Y-%m-%d %H:%M:%S ") + tz


def ago(v):
    v = _dt(v)
    if v is None:
        return "없음"
    s = int((datetime.now(timezone.utc) - v).total_seconds())
    if s < 60:
        return f"{s}초 전"
    if s < 3600:
        return f"{s // 60}분 전"
    if s < 86400:
        return f"{s // 3600}시간 전"
    return f"{s // 86400}일 전"


def duration(a, b):
    a, b = _dt(a), _dt(b)
    if not a or not b:
        return ""
    s = int((b - a).total_seconds())
    return f"{s // 3600}시간 {s % 3600 // 60}분" if s >= 3600 else f"{s // 60}분 {s % 60}초"


templates.env.filters.update(ts=fmt_ts, ago=ago)
templates.env.globals.update(duration=duration)

CLASS_INFO = {
    "direct": ("직접 사용", "b-red", "변경 패키지의 실행 파일·라이브러리를 프로세스가 실행하거나 메모리에 매핑했습니다."),
    "file_access": ("파일 접근", "b-amber", "변경 패키지의 파일을 열었지만 실행·로딩 여부는 확인되지 않았습니다."),
    "static_dependency": ("정적 의존", "b-amber", "RPM 의존 관계로만 연결됩니다. 실행은 관측되지 않았습니다."),
    "no_observation": ("관측 없음", "b-gray", "관측 기간 동안 사용이 보이지 않았습니다. 안전·미사용 판정이 아닙니다."),
}
templates.env.globals.update(CLASS_INFO=CLASS_INFO)


def render(request: Request, name: str, **ctx):
    tz = request.cookies.get("ps_tz", "KST")
    csrf = request.cookies.get("ps_csrf") or secrets.token_urlsafe(16)
    resp = templates.TemplateResponse(request, name, {"tz": tz, "csrf": csrf, "user": auth.cookie_user(request), **ctx})
    resp.set_cookie("ps_csrf", csrf, httponly=True, secure=True, samesite="strict")
    return resp


def check_csrf(request: Request, token: str):
    if not token or not secrets.compare_digest(token, request.cookies.get("ps_csrf") or ""):
        raise HTTPException(403, "csrf")


# ---------------------------------------------------------------- login

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", error=None)


@router.post("/login")
def login(request: Request, password: str = Form(...), csrf: str = Form("")):
    check_csrf(request, csrf)
    if not auth.verify_password(password, auth.admin_hash()):
        return render(request, "login.html", error="비밀번호가 올바르지 않습니다.")
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(auth.COOKIE, auth.make_cookie("admin"), httponly=True, secure=True, samesite="strict", max_age=8 * 3600)
    return r


@router.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(auth.COOKIE)
    return r


@router.get("/tz/{tz}")
def set_tz(tz: str, request: Request, user=Depends(auth.require_user)):
    ref = request.headers.get("referer") or "/"
    r = RedirectResponse(ref if ref.startswith("https://") or ref.startswith("/") else "/", status_code=303)
    r.set_cookie("ps_tz", "UTC" if tz == "UTC" else "KST", secure=True, samesite="strict")
    return r


# ---------------------------------------------------------------- data helpers

def host_or_404(conn, host_id):
    h = conn.execute("SELECT * FROM hosts WHERE host_id = %s", (host_id,)).fetchone()
    if not h:
        raise HTTPException(404)
    return h


def periods(conn, host_id, limit=50):
    return conn.execute(
        """SELECT s.*, (SELECT count(DISTINCT unit) FROM records r WHERE r.session_id = s.session_id AND unit LIKE '%%.service') AS services
           FROM sessions s WHERE host_id = %s ORDER BY first_window_start DESC LIMIT %s""", (host_id, limit)).fetchall()


def health(h):
    """호스트 카드 상태: (점 색, 문구)."""
    if h["capability_status"] == "unsupported":
        return "red", "수집 불가"
    last = _dt(h["last_seen"])
    if last and (datetime.now(timezone.utc) - last).total_seconds() > 300:
        return "red", "수신 끊김"
    if h["capability_status"] == "degraded":
        return "amber", "일부 기능 제한"
    return "green", "정상 수집 중"


# ---------------------------------------------------------------- dashboard

@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        hosts = conn.execute(
            """SELECT h.*,
                 (SELECT count(*) FROM sessions s WHERE s.host_id = h.host_id) AS periods,
                 (SELECT jsonb_array_length(updates) FROM available_updates u WHERE u.host_id = h.host_id) AS updates,
                 (SELECT received_at FROM available_updates u WHERE u.host_id = h.host_id) AS updates_at,
                 (SELECT count(*) FROM patch_plans p WHERE p.host_id = h.host_id) AS plans,
                 (SELECT count(DISTINCT unit) FROM records r WHERE r.host_id = h.host_id AND unit LIKE '%%.service'
                    AND r.ts_utc > now() - interval '1 day') AS services,
                 (SELECT bool_or(s.incomplete_batches > 0 OR cardinality(s.dropped_batch_ids) > 0)
                    FROM sessions s WHERE s.host_id = h.host_id AND s.last_created_at > now() - interval '1 day') AS lossy
               FROM hosts h ORDER BY h.hostname""").fetchall()
        recent = conn.execute(
            """SELECT p.id, p.label, p.plan_type, p.uploaded_at, h.hostname, h.host_id,
                      jsonb_array_length(p.plan->'items') AS items
               FROM patch_plans p JOIN hosts h USING (host_id) ORDER BY p.uploaded_at DESC LIMIT 8""").fetchall()
    for h in hosts:
        h["health"] = health(h)
    return render(request, "dashboard.html", hosts=hosts, recent=recent, nav="dash")


# ---------------------------------------------------------------- host

@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_overview(host_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        h["health"] = health(h)
        caps = conn.execute("SELECT status, kernel, boot_id, agent_version, received_at, report FROM capability_reports WHERE host_id = %s ORDER BY received_at DESC LIMIT 5", (host_id,)).fetchall()
        inv = conn.execute("SELECT * FROM inventories WHERE host_id = %s ORDER BY received_at DESC LIMIT 1", (host_id,)).fetchone()
        ps = periods(conn, host_id, 5)
        upd = conn.execute("SELECT * FROM available_updates WHERE host_id = %s", (host_id,)).fetchone()
        plans = conn.execute("SELECT id, label, plan_type, uploaded_at, jsonb_array_length(plan->'items') AS items FROM patch_plans WHERE host_id = %s ORDER BY uploaded_at DESC LIMIT 5", (host_id,)).fetchall()
    return render(request, "host_overview.html", h=h, caps=caps, inv=inv, periods=ps, upd=upd, plans=plans, tab="overview")


@router.get("/hosts/{host_id}/periods", response_class=HTMLResponse)
def host_periods(host_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        ps = periods(conn, host_id)
    return render(request, "host_periods.html", h=h, periods=ps, tab="periods")


@router.get("/hosts/{host_id}/services", response_class=HTMLResponse)
def host_services(host_id: str, request: Request, session: str | None = None, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        ps = periods(conn, host_id)
        sid = session or (ps[0]["session_id"] if ps else None)
        rows = []
        if sid:
            rows = conn.execute(
                """SELECT coalesce(unit,'(서비스 미확인)') AS unit, count(DISTINCT proc_key) AS procs,
                          count(DISTINCT comm) AS comms, array_agg(DISTINCT comm) AS comm_list,
                          count(DISTINCT p) AS packages, max(coalesce(last_ts_utc, ts_utc)) AS last
                   FROM records LEFT JOIN LATERAL unnest(packages) p ON true
                   WHERE session_id = %s AND proc_key IS NOT NULL GROUP BY 1 ORDER BY packages DESC, 1""", (sid,)).fetchall()
    return render(request, "host_services.html", h=h, periods=ps, sid=sid, rows=rows, tab="services")


@router.get("/hosts/{host_id}/services/detail", response_class=HTMLResponse)
def service_detail(host_id: str, unit: str, session: str, request: Request, user=Depends(auth.require_user)):
    """서비스 → 프로세스 → 패키지 → 파일."""
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        u = None if unit == "(서비스 미확인)" else unit
        pk = conn.execute(
            """SELECT p AS nevra, count(DISTINCT proc_key) AS procs, array_agg(DISTINCT comm) AS comms,
                      array_agg(DISTINCT kind) AS kinds, array_agg(DISTINCT path) AS files,
                      min(ts_utc) AS first, max(coalesce(last_ts_utc, ts_utc)) AS last
               FROM records, unnest(packages) p
               WHERE session_id = %s AND unit IS NOT DISTINCT FROM %s AND ownership IN ('rpm','deleted')
               GROUP BY 1 ORDER BY 1""", (session, u)).fetchall()
        other = conn.execute(
            """SELECT ownership, path_status, count(*) AS n, array_agg(DISTINCT coalesce(path, requested_path)) AS paths
               FROM records WHERE session_id = %s AND unit IS NOT DISTINCT FROM %s AND ownership IN ('unmanaged','unknown')
                 AND NOT (kind = 'file_open' AND ok IS FALSE)
               GROUP BY 1,2 ORDER BY n DESC""", (session, u)).fetchall()
        procs = conn.execute(
            """SELECT comm, count(DISTINCT proc_key) AS n, min(ts_utc) AS first FROM records
               WHERE session_id = %s AND unit IS NOT DISTINCT FROM %s AND proc_key IS NOT NULL GROUP BY 1 ORDER BY 2 DESC""",
            (session, u)).fetchall()
        upd_row = conn.execute("SELECT updates FROM available_updates WHERE host_id = %s", (host_id,)).fetchone()
    for p in pk:
        p["name"] = analysis.nevra_name(p["nevra"])
        p["executed"] = bool(set(p["kinds"]) & {"exec", "process", "mapped_file", "file_mmap"})
        p["comms"] = [c for c in (p["comms"] or []) if c]
    updates = {u["name"]: u["to_nevra"] for u in (upd_row["updates"] if upd_row else [])}
    for p in pk:
        p["update_to"] = viz.evr(updates[p["name"]], p["name"]) if p["name"] in updates else None
    # 업데이트 대기 → 실행·매핑 → 이름 순
    pk.sort(key=lambda p: (p["update_to"] is None, not p["executed"], p["name"]))

    # 정적 의존 (관측 패키지가 RPM Requires 로 더 끌어오는 패키지)
    with db.connect() as conn:
        inv_id = session_inventory(conn, session)
        g = deps.graph(conn, host_id, inv_id) if inv_id else None
    static_only = []
    if g:
        observed = {p["name"] for p in pk}
        for p in pk:
            p["ndeps"] = len(deps.children(g, p["name"]))
        for name, chain in sorted(deps.closure(g, observed).items()):
            if name in observed:
                continue
            node = g["pkgs"][name]
            static_only.append({"name": name, "via": chain, "evr": viz.evr(node["nevras"][0], name),
                                "update_to": viz.evr(updates[name], name) if name in updates else None})
        static_only.sort(key=lambda s: (s["update_to"] is None, s["name"]))
    vmap = viz.service_map(unit, pk, procs, updates, static_only,
                           link_base=f"/hosts/{host_id}/packages/", link_qs="?" + urlencode({"unit": unit, "session": session}))
    return render(request, "service_detail.html", h=h, unit=unit, sid=session, pk=pk, other=other, procs=procs,
                  vmap=vmap, has_updates=bool(upd_row), static_only=static_only, inv_id=inv_id, tab="services")


@router.get("/hosts/{host_id}/packages/{name}", response_class=HTMLResponse)
def package_timeline(host_id: str, name: str, request: Request, unit: str | None = None, session: str | None = None,
                     user=Depends(auth.require_user)):
    """패키지 하나의 변경 타임라인: 계획 → dnf 설치(누가·명령) → 버전 변경 감지 → 서비스 반영(관측) → 재부팅."""
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", name):
        raise HTTPException(400)
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        t = timeline.build(conn, host_id, name, unit)
    return render(request, "package_timeline.html", h=h, t=t, sid=session, tab="services")


def session_inventory(conn, session_id: str) -> str | None:
    """관측 기간의 마지막 인벤토리 (패키지 변경이 있었으면 최신 기준)."""
    r = conn.execute("SELECT inventory_ids FROM sessions WHERE session_id = %s", (session_id,)).fetchone()
    return (r["inventory_ids"] or [None])[-1] if r else None


@router.get("/hosts/{host_id}/deps", response_class=HTMLResponse)
def deps_fragment(host_id: str, name: str, session: str, unit: str, request: Request, path: str = "",
                  user=Depends(auth.require_user)):
    """의존 트리 한 단계 (펼칠 때 불러오는 HTML 조각)."""
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", name):
        raise HTTPException(400)
    with db.connect() as conn:
        host_or_404(conn, host_id)
        inv_id = session_inventory(conn, session)
        if not inv_id:
            raise HTTPException(404)
        g = deps.graph(conn, host_id, inv_id)
        u = None if unit == "(서비스 미확인)" else unit
        observed = {analysis.nevra_name(r["p"]) for r in conn.execute(
            """SELECT DISTINCT p FROM records, unnest(packages) p
               WHERE session_id = %s AND unit IS NOT DISTINCT FROM %s AND ownership IN ('rpm','deleted')""", (session, u))}
        upd_row = conn.execute("SELECT updates FROM available_updates WHERE host_id = %s", (host_id,)).fetchone()
    updates = {x["name"]: x["to_nevra"] for x in (upd_row["updates"] if upd_row else [])}
    node = g["pkgs"].get(name)
    ancestors = set(filter(None, path.split(",")))
    kids = []
    for k in deps.children(g, name):
        kn = g["pkgs"][k]
        kids.append({"name": k, "evr": viz.evr(kn["nevras"][0], k), "observed": k in observed,
                     "update_to": viz.evr(updates[k], k) if k in updates else None,
                     "ndeps": len(kn["deps"]), "cycle": k in ancestors,
                     "reqs": sorted(node["deps"][k])[:5]})
    kids.sort(key=lambda k: (not k["observed"], k["update_to"] is None, k["name"]))
    base = f"/hosts/{host_id}/deps?" + urlencode({"session": session, "unit": unit})
    return templates.TemplateResponse(request, "_deps.html", {
        "node": node, "kids": kids, "base": base, "path": path or name, "depth": len(ancestors)})


# ---------------------------------------------------------------- plans

@router.get("/hosts/{host_id}/plans", response_class=HTMLResponse)
def host_plans(host_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        tasks.expire(conn)
        plans = conn.execute(
            """SELECT p.id, p.label, p.plan_type, p.uploaded_at, p.uploaded_by, p.inventory_id,
                      jsonb_array_length(p.plan->'items') AS items, p.validation->'warnings' AS warnings,
                      (SELECT result->'packages' FROM analysis_results a WHERE a.plan_id = p.id ORDER BY created_at DESC LIMIT 1) AS last_pk
               FROM patch_plans p WHERE host_id = %s ORDER BY uploaded_at DESC""", (host_id,)).fetchall()
        tl = conn.execute("SELECT * FROM plan_tasks WHERE host_id = %s ORDER BY requested_at DESC LIMIT 10", (host_id,)).fetchall()
    for p in plans:
        cnt = {}
        for k in (p["last_pk"] or []):
            cnt[k["classification"]] = cnt.get(k["classification"], 0) + 1
        p["counts"] = cnt
    busy = any(t["status"] in ("pending", "running") for t in tl)
    return render(request, "host_plans.html", h=h, plans=plans, tasks=tl, busy=busy, tab="plans")


@router.get("/hosts/{host_id}/plans/new", response_class=HTMLResponse)
def plan_new(host_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        tasks.expire(conn)
        upd = conn.execute("SELECT * FROM available_updates WHERE host_id = %s", (host_id,)).fetchone()
        inv = conn.execute("SELECT inventory_id FROM inventories WHERE host_id = %s ORDER BY received_at DESC LIMIT 1", (host_id,)).fetchone()
        pending = conn.execute("SELECT * FROM plan_tasks WHERE host_id = %s AND kind = 'list_updates' AND status IN ('pending','running') ORDER BY id DESC LIMIT 1", (host_id,)).fetchone()
        last_fail = conn.execute("SELECT * FROM plan_tasks WHERE host_id = %s AND kind = 'list_updates' ORDER BY id DESC LIMIT 1", (host_id,)).fetchone()
        # 각 업데이트 후보 패키지를 최근 관측에서 사용한 서비스 수 (선택 도움말)
        usage = {}
        if upd:
            names = [u["name"] for u in upd["updates"]]
            for r in conn.execute(
                    """SELECT ip.name, count(DISTINCT r.unit) AS units, array_agg(DISTINCT r.unit) AS unit_list
                       FROM records r
                       CROSS JOIN LATERAL unnest(r.packages) AS p(nevra)
                       JOIN inventory_packages ip ON ip.host_id = r.host_id AND ip.nevra = p.nevra
                       WHERE r.host_id = %s AND r.ts_utc > now() - interval '1 day' AND ip.name = ANY(%s)
                         AND r.unit LIKE '%%.service' AND r.unit <> ALL(%s)
                         AND r.kind IN ('exec','process','mapped_file','file_mmap')
                       GROUP BY 1""", (host_id, names, list(analysis.OPERATOR_UNITS))):
                usage[r["name"]] = r
    stale = bool(upd and inv and upd["inventory_id"] != inv["inventory_id"])
    is_al = h["os_id"] == "amzn"
    return render(request, "plan_new.html", h=h, upd=upd, usage=usage, pending=pending, last=last_fail,
                  stale=stale, is_al=is_al, tab="plans")


@router.post("/hosts/{host_id}/updates/refresh")
def updates_refresh(host_id: str, request: Request, csrf: str = Form(""), releasever: str = Form(""),
                    user=Depends(auth.require_user)):
    check_csrf(request, csrf)
    with db.connect() as conn:
        host_or_404(conn, host_id)
        tasks.create(conn, host_id, "list_updates", [], False, releasever.strip() or None, None, user)
    return RedirectResponse(f"/hosts/{host_id}/plans/new", status_code=303)


@router.post("/hosts/{host_id}/plans/request")
async def plan_request(host_id: str, request: Request, user=Depends(auth.require_user)):
    form = await request.form()
    check_csrf(request, form.get("csrf", ""))
    mode = form.get("mode", "selected")
    pkgs = sorted(set(form.getlist("packages"))) if mode == "selected" else []
    if mode == "selected" and not pkgs:
        raise HTTPException(400, "패키지를 하나 이상 선택하세요")
    kernel = mode == "kernel"
    rel = (form.get("releasever") or "").strip() or None
    label = (form.get("label") or "").strip()[:120] or {
        "selected": f"{len(pkgs)}개 패키지: " + ", ".join(pkgs[:3]) + (" …" if len(pkgs) > 3 else ""),
        "all": "전체 업데이트", "kernel": "커널 업데이트"}[mode]
    with db.connect() as conn:
        host_or_404(conn, host_id)
        tasks.create(conn, host_id, "resolve_plan", pkgs, kernel, rel, label, user)
    return RedirectResponse(f"/hosts/{host_id}/plans", status_code=303)


@router.post("/hosts/{host_id}/plans/upload")
async def upload_plan(host_id: str, request: Request, file: UploadFile, label: str = Form(""), csrf: str = Form(""),
                      user=Depends(auth.require_user)):
    check_csrf(request, csrf)
    raw = await file.read()
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(413)
    try:
        plan = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "invalid json")
    if plan.get("host_id") != host_id:
        raise HTTPException(400, "계획의 host_id 가 이 서버와 다릅니다")
    with db.connect() as conn:
        v = analysis.validate_plan(conn, plan)
        row = conn.execute(
            """INSERT INTO patch_plans (host_id, inventory_id, plan_type, label, plan, validation, uploaded_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (plan["host_id"], plan["inventory_id"], plan["plan_type"], label or None, json.dumps(plan),
             analysis.to_json(v), user)).fetchone()
    return RedirectResponse(f"/plans/{row['id']}", status_code=303)


def load_plan(conn, plan_id: int):
    p = conn.execute("SELECT * FROM patch_plans WHERE id = %s", (plan_id,)).fetchone()
    if not p:
        raise HTTPException(404)
    return p


@router.get("/plans/{plan_id}", response_class=HTMLResponse)
def plan_view(plan_id: int, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        p = load_plan(conn, plan_id)
        h = host_or_404(conn, p["host_id"])
        res = analysis.analyze(conn, p)
        conn.execute("INSERT INTO analysis_results (plan_id, result) VALUES (%s, %s)", (plan_id, analysis.to_json(res)))
    counts = {}
    for k in res["packages"]:
        counts[k["classification"]] = counts.get(k["classification"], 0) + 1
    svc_count = len([s for s in res["services"] if s["unit"] != "(unattributed)"])
    return render(request, "analysis.html", p=p, h=h, r=res, counts=counts, svc_count=svc_count, tab="plans")


@router.get("/plans/{plan_id}/report.json")
def report_json(plan_id: int, user=Depends(auth.require_user)):
    with db.connect() as conn:
        res = analysis.analyze(conn, load_plan(conn, plan_id))
    return Response(analysis.to_json(res), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=patchscope-plan-{plan_id}.json"})


@router.get("/plans/{plan_id}/report.csv")
def report_csv(plan_id: int, user=Depends(auth.require_user)):
    with db.connect() as conn:
        res = analysis.analyze(conn, load_plan(conn, plan_id))
    buf = io.StringIO()
    buf.write("\ufeff")  # Excel 한글
    w = csv.writer(buf)
    w.writerow(["package", "from", "to", "classification", "evidence", "unit", "unit_source", "comm", "pid",
                "proc_key", "evidence_kinds", "files", "first_utc", "last_utc", "events"])
    for p in res["packages"]:
        rows = [("direct", d) for d in p["direct"]] + [("file_access", d) for d in p["file_access"]]
        if not rows:
            w.writerow([p["name"], p["from"], p["to"], p["classification"], "", "", "", "", "", "", "",
                        ";".join(p["static_dependents"][:10]), "", "", ""])
        for kind, d in rows:
            w.writerow([p["name"], p["from"], p["to"], p["classification"], kind, d["unit"], d["unit_source"],
                        d["comm"], d["pid"], d["proc_key"], ";".join(d["evidence_kinds"]), ";".join(d["files"]),
                        d["first"], d["last"], d["events"]])
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename=patchscope-plan-{plan_id}.csv"})


# ---------------------------------------------------------------- compare

def auto_compare_pair(conn, host_id):
    """인벤토리가 바뀐 시점 기준: 최신 관측 기간(후)과 그 이전 다른 인벤토리의 마지막 관측 기간(전)."""
    ps = conn.execute("SELECT session_id, inventory_ids, kernel, boot_id FROM sessions WHERE host_id = %s AND batch_count > 3 ORDER BY first_window_start DESC", (host_id,)).fetchall()
    if len(ps) < 2:
        return None, None
    after = ps[0]
    for s in ps[1:]:
        if set(s["inventory_ids"] or []) != set(after["inventory_ids"] or []) or s["boot_id"] != after["boot_id"]:
            return s["session_id"], after["session_id"]
    return ps[1]["session_id"], after["session_id"]


@router.get("/hosts/{host_id}/compare", response_class=HTMLResponse)
def compare(host_id: str, request: Request, before: str | None = None, after: str | None = None,
            user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = host_or_404(conn, host_id)
        ps = periods(conn, host_id)
        if not before or not after:
            before, after = auto_compare_pair(conn, host_id)
        if not before:
            return render(request, "compare.html", h=h, periods=ps, b=None, a=None, tab="compare")

        def snap(sid):
            s = conn.execute("SELECT * FROM sessions WHERE session_id = %s AND host_id = %s", (sid, host_id)).fetchone()
            if not s:
                raise HTTPException(404, sid)
            deps = conn.execute(
                """SELECT coalesce(unit,'(서비스 미확인)') AS unit, p AS nevra
                   FROM records, unnest(packages) p
                   WHERE session_id = %s AND ownership = 'rpm' AND kind IN ('process','exec','mapped_file','file_mmap')
                     AND (unit IS NULL OR unit <> ALL(%s))
                   GROUP BY 1,2""", (sid, list(analysis.OPERATOR_UNITS))).fetchall()
            fails = conn.execute(
                """SELECT coalesce(unit,'(서비스 미확인)') AS unit, comm, requested_path, errno, sum(count) AS n
                   FROM records WHERE session_id = %s AND kind = 'file_open' AND ok IS FALSE AND errno NOT IN (2, 6, 20)
                     AND (unit IS NULL OR unit <> ALL(%s))
                   GROUP BY 1,2,3,4 ORDER BY n DESC LIMIT 100""", (sid, list(analysis.OPERATOR_UNITS))).fetchall()
            exits = conn.execute(
                """SELECT coalesce(unit,'(서비스 미확인)') AS unit, comm, exit_code, signal, count(*) AS n
                   FROM records WHERE session_id = %s AND kind = 'exit' AND (exit_code <> 0 OR signal IS NOT NULL)
                     AND (unit IS NULL OR unit <> ALL(%s))
                   GROUP BY 1,2,3,4 ORDER BY n DESC LIMIT 100""", (sid, list(analysis.OPERATOR_UNITS))).fetchall()
            return s, deps, fails, exits

        b, bdeps, bfails, bexits = snap(before)
        a, adeps, afails, aexits = snap(after)

    groups = build_compare_groups(bdeps, adeps)
    return render(request, "compare.html", h=h, periods=ps, b=b, a=a, groups=groups,
                  bfails=bfails, afails=afails, bexits=bexits, aexits=aexits, tab="compare")


# 실행할 때마다 이름이 바뀌는 임시 unit: 같은 서비스로 비교할 수 없으므로 따로 묶는다
TRANSIENT = re.compile(r"^(session-c?\d+\.scope|run-r[0-9a-f]+\.(service|scope)|patchscope-plan-\d+\.scope|"
                       r"user(-runtime-dir)?@\d+\.service)$")


def build_compare_groups(bdeps, adeps) -> dict:
    """서비스별 전후 비교. 반환: {'changed': [...], 'same': [...], 'only_before': [...], 'only_after': [...], 'transient': n}"""
    def index(rows):
        out = {}
        for r in rows:
            out.setdefault(r["unit"], {}).setdefault(analysis.nevra_name(r["nevra"]), set()).add(r["nevra"])
        return out
    bi, ai = index(bdeps), index(adeps)
    res = {"changed": [], "same": [], "only_before": [], "only_after": [], "transient": 0}
    for unit in sorted(set(bi) | set(ai)):
        if TRANSIENT.match(unit):
            res["transient"] += 1
            continue
        b, a = bi.get(unit, {}), ai.get(unit, {})
        if not b or not a:
            res["only_before" if b else "only_after"].append(
                {"unit": unit, "packages": len(b or a), "names": sorted(b or a)[:12]})
            continue
        upgraded, downgraded, added, removed, same = [], [], [], [], 0
        for name in sorted(set(b) | set(a)):
            bv, av = b.get(name, set()), a.get(name, set())
            if bv == av:
                same += 1
            elif not bv:
                added.append({"name": name, "after": [viz.evr(x, name) for x in sorted(av)]})
            elif not av:
                removed.append({"name": name, "before": [viz.evr(x, name) for x in sorted(bv)]})
            else:
                item = {"name": name, "before": [viz.evr(x, name) for x in sorted(bv)],
                        "after": [viz.evr(x, name) for x in sorted(av)]}
                hi_a = max(av, key=viz.evr_key)
                hi_b = max(bv, key=viz.evr_key)
                item["direction"] = "up" if viz.evr_key(hi_a) >= viz.evr_key(hi_b) else "down"
                (upgraded if item["direction"] == "up" else downgraded).append(item)
        g = {"unit": unit, "upgraded": upgraded + downgraded, "added": added, "removed": removed, "same": same,
             "total": len(set(b) | set(a))}
        (res["changed"] if upgraded or downgraded or added or removed else res["same"]).append(g)
    # 버전이 바뀐 서비스를 먼저, 그 다음 추가/사라짐이 많은 순
    res["changed"].sort(key=lambda g: (-len(g["upgraded"]), -(len(g["added"]) + len(g["removed"])), g["unit"]))
    return res

"""웹 화면 (서버 렌더링). 브라우저 로그인 필요. 대상 서버로 명령을 보내는 기능은 없다."""
import csv
import io
import json
import secrets
from datetime import timedelta, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pathlib import Path

from . import analysis, auth, db

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
KST = timezone(timedelta(hours=9))


def fmt_ts(v, tz="KST"):
    if v is None:
        return ""
    if isinstance(v, str):
        from datetime import datetime
        v = datetime.fromisoformat(v)
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.astimezone(KST if tz == "KST" else timezone.utc).strftime("%Y-%m-%d %H:%M:%S ") + tz


templates.env.filters["ts"] = fmt_ts


def render(request: Request, name: str, **ctx):
    tz = request.cookies.get("ps_tz", "KST")
    csrf = request.cookies.get("ps_csrf") or secrets.token_urlsafe(16)
    resp = templates.TemplateResponse(request, name, {"tz": tz, "csrf": csrf, "user": auth.cookie_user(request), **ctx})
    resp.set_cookie("ps_csrf", csrf, httponly=True, secure=True, samesite="strict")
    return resp


def check_csrf(request: Request, token: str):
    if not token or token != request.cookies.get("ps_csrf"):
        raise HTTPException(403, "csrf")


# ---------------------------------------------------------------- login

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", error=None)


@router.post("/login")
def login(request: Request, password: str = Form(...), csrf: str = Form("")):
    check_csrf(request, csrf)
    if not auth.verify_password(password, auth.admin_hash()):
        return render(request, "login.html", error="invalid password")
    r = RedirectResponse("/", status_code=303)
    r.set_cookie(auth.COOKIE, auth.make_cookie("admin"), httponly=True, secure=True, samesite="strict",
                 max_age=8 * 3600)
    return r


@router.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(auth.COOKIE)
    return r


@router.get("/tz/{tz}")
def set_tz(tz: str, request: Request, user=Depends(auth.require_user)):
    r = RedirectResponse(request.headers.get("referer") or "/", status_code=303)
    r.set_cookie("ps_tz", "UTC" if tz == "UTC" else "KST", secure=True, samesite="strict")
    return r


# ---------------------------------------------------------------- hosts / sessions

@router.get("/", response_class=HTMLResponse)
def hosts(request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        rows = conn.execute(
            """SELECT h.*, a.last_seen AS agent_last_seen, a.revoked_at,
                      (SELECT inventory_id FROM inventories i WHERE i.host_id = h.host_id ORDER BY received_at DESC LIMIT 1) AS inventory_id,
                      (SELECT report->'reasons' FROM capability_reports c WHERE c.host_id = h.host_id ORDER BY received_at DESC LIMIT 1) AS reasons
               FROM hosts h JOIN agents a USING (agent_id) ORDER BY h.hostname""").fetchall()
    return render(request, "hosts.html", hosts=rows)


@router.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(host_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        h = conn.execute("SELECT * FROM hosts WHERE host_id = %s", (host_id,)).fetchone()
        if not h:
            raise HTTPException(404)
        sessions = conn.execute("SELECT * FROM sessions WHERE host_id = %s ORDER BY first_window_start DESC LIMIT 50", (host_id,)).fetchall()
        caps = conn.execute("SELECT id, status, kernel, boot_id, agent_version, received_at, report FROM capability_reports WHERE host_id = %s ORDER BY received_at DESC LIMIT 10", (host_id,)).fetchall()
        invs = conn.execute("SELECT * FROM inventories WHERE host_id = %s ORDER BY received_at DESC", (host_id,)).fetchall()
        plans = conn.execute("SELECT id, plan_type, label, inventory_id, uploaded_at, validation->'warnings' AS warnings FROM patch_plans WHERE host_id = %s ORDER BY uploaded_at DESC", (host_id,)).fetchall()
    return render(request, "host.html", h=h, sessions=sessions, caps=caps, invs=invs, plans=plans)


@router.get("/sessions/{session_id}", response_class=HTMLResponse)
def session_detail(session_id: str, request: Request, user=Depends(auth.require_user)):
    with db.connect() as conn:
        s = conn.execute("SELECT * FROM sessions WHERE session_id = %s", (session_id,)).fetchone()
        if not s:
            raise HTTPException(404)
        bad = conn.execute("SELECT batch_id, seq, created_at, reason, delta FROM batches WHERE session_id = %s AND NOT complete ORDER BY seq", (session_id,)).fetchall()
        seqs = [r["seq"] for r in conn.execute("SELECT seq FROM batches WHERE session_id = %s ORDER BY seq", (session_id,))]
        missing = sorted(set(range(1, (max(seqs) if seqs else 0) + 1)) - set(seqs))
        services = conn.execute(
            """SELECT coalesce(unit,'(unattributed)') AS unit, count(DISTINCT proc_key) AS procs,
                      count(DISTINCT path) FILTER (WHERE ownership='rpm') AS rpm_files,
                      count(DISTINCT p) AS packages
               FROM records LEFT JOIN LATERAL unnest(packages) p ON true
               WHERE session_id = %s AND proc_key IS NOT NULL GROUP BY 1 ORDER BY 1""", (session_id,)).fetchall()
    return render(request, "session.html", s=s, bad=bad, missing=missing, services=services)


@router.get("/sessions/{session_id}/service", response_class=HTMLResponse)
def service_deps(session_id: str, unit: str, request: Request, user=Depends(auth.require_user)):
    """서비스의 프로세스 → 실행 파일·공유 라이브러리·RPM."""
    with db.connect() as conn:
        u = None if unit == "(unattributed)" else unit
        rows = conn.execute(
            """SELECT comm, proc_key, kind, path, path_status, ownership, packages, ok,
                      min(ts_utc) AS first, max(coalesce(last_ts_utc, ts_utc)) AS last, sum(count) AS events,
                      array_agg(DISTINCT source) AS sources
               FROM records WHERE session_id = %s AND unit IS NOT DISTINCT FROM %s
                 AND kind IN ('process','exec','mapped_file','file_mmap','file_open','open_fd')
               GROUP BY 1,2,3,4,5,6,7,8 ORDER BY comm, proc_key, kind, path LIMIT 5000""", (session_id, u)).fetchall()
    return render(request, "service.html", session_id=session_id, unit=unit, rows=rows)


# ---------------------------------------------------------------- plans / analysis

@router.post("/plans")
async def upload_plan(request: Request, file: UploadFile, label: str = Form(""), csrf: str = Form(""),
                      user=Depends(auth.require_user)):
    check_csrf(request, csrf)
    raw = await file.read()
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(413)
    try:
        plan = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "invalid json")
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
        res = analysis.analyze(conn, p)
        conn.execute("INSERT INTO analysis_results (plan_id, result) VALUES (%s, %s)", (plan_id, analysis.to_json(res)))
    return render(request, "analysis.html", p=p, r=res)


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
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=patchscope-plan-{plan_id}.csv"})


@router.get("/compare", response_class=HTMLResponse)
def compare(request: Request, before: str, after: str, user=Depends(auth.require_user)):
    """패치 전후 세션 비교: 서비스별 프로세스·RPM 의존 관계·실패 접근 차이."""
    with db.connect() as conn:
        def snap(sid):
            s = conn.execute("SELECT * FROM sessions WHERE session_id = %s", (sid,)).fetchone()
            if not s:
                raise HTTPException(404, sid)
            deps = conn.execute(
                """SELECT coalesce(unit,'(unattributed)') AS unit, comm, p AS nevra
                   FROM records, unnest(packages) p
                   WHERE session_id = %s AND ownership = 'rpm' AND kind IN ('process','exec','mapped_file','file_mmap')
                   GROUP BY 1,2,3""", (sid,)).fetchall()
            fails = conn.execute(
                """SELECT coalesce(unit,'(unattributed)') AS unit, comm, requested_path, errno, sum(count) AS n
                   FROM records WHERE session_id = %s AND kind = 'file_open' AND ok IS FALSE AND errno <> 2
                   GROUP BY 1,2,3,4""", (sid,)).fetchall()
            exits = conn.execute(
                """SELECT coalesce(unit,'(unattributed)') AS unit, comm, exit_code, signal, count(*) AS n
                   FROM records WHERE session_id = %s AND kind = 'exit' AND (exit_code <> 0 OR signal IS NOT NULL)
                   GROUP BY 1,2,3,4""", (sid,)).fetchall()
            return s, deps, fails, exits

        b, bdeps, bfails, bexits = snap(before)
        a, adeps, afails, aexits = snap(after)

    def by_name(rows):
        out = {}
        for r in rows:
            out.setdefault((r["unit"], r["comm"], analysis.nevra_name(r["nevra"])), set()).add(r["nevra"])
        return out
    bm, am = by_name(bdeps), by_name(adeps)
    changes = []
    for k in sorted(set(bm) | set(am)):
        bv, av = bm.get(k, set()), am.get(k, set())
        if bv != av:
            changes.append({"unit": k[0], "comm": k[1], "package": k[2],
                            "before": sorted(bv), "after": sorted(av),
                            "change": "added" if not bv else "removed" if not av else "version"})
    return render(request, "compare.html", b=b, a=a, changes=changes,
                  bfails=bfails, afails=afails, bexits=bexits, aexits=aexits)

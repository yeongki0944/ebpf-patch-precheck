"""에이전트 수신 API (/api/v1). 인증된 에이전트만, 스키마 버전 불일치는 거부.

중복 제거: batch_id 가 PK. 이미 있으면 409 (에이전트는 409 를 성공으로 보고 spool 에서 삭제).
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from . import SCHEMA_VERSION, db
from .auth import require_agent

router = APIRouter(prefix="/api/v1")

MAX_BODY = 64 * 1024 * 1024


async def read_json(request: Request) -> dict:
    if request.headers.get("x-patchscope-schema", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise HTTPException(426, f"schema version mismatch: server={SCHEMA_VERSION}")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(413, "body too large")
    try:
        d = json.loads(body)
    except ValueError:
        raise HTTPException(400, "invalid json")
    if not isinstance(d, dict) or d.get("schema_version") != SCHEMA_VERSION:
        raise HTTPException(426, f"schema version mismatch: server={SCHEMA_VERSION}")
    return d


def check_agent(d: dict, agent_id: str) -> dict:
    if d.get("agent_id") != agent_id:
        raise HTTPException(403, "agent_id does not match token")
    host = d.get("host") or {}
    if not host.get("host_id") or not host.get("boot_id"):
        raise HTTPException(400, "host.host_id and host.boot_id required")
    return host


def upsert_host(conn, agent_id: str, host: dict, status: str | None = None) -> None:
    owner = conn.execute("SELECT agent_id FROM hosts WHERE host_id = %s", (host["host_id"],)).fetchone()
    if owner and owner["agent_id"] != agent_id:
        # 다른 에이전트 토큰이 같은 호스트를 사칭하지 못하게 함
        raise HTTPException(403, "host is registered to another agent")
    conn.execute(
        """INSERT INTO hosts (host_id, agent_id, hostname, os_id, os_version, kernel, boot_id, capability_status)
           VALUES (%(host_id)s, %(agent)s, %(hostname)s, %(os_id)s, %(os_version)s, %(kernel)s, %(boot_id)s, %(status)s)
           ON CONFLICT (host_id) DO UPDATE SET hostname = EXCLUDED.hostname, os_id = EXCLUDED.os_id,
             os_version = EXCLUDED.os_version, kernel = EXCLUDED.kernel, boot_id = EXCLUDED.boot_id,
             capability_status = COALESCE(EXCLUDED.capability_status, hosts.capability_status), last_seen = now()""",
        {**host, "agent": agent_id, "status": status,
         "hostname": host.get("hostname"), "os_id": host.get("os_id"),
         "os_version": host.get("os_version"), "kernel": host.get("kernel")},
    )


@router.post("/capability")
async def capability(request: Request, agent_id: str = Depends(require_agent)):
    d = await read_json(request)
    host = check_agent(d, agent_id)
    rep = d.get("report") or {}
    status = rep.get("status")
    if status not in ("supported", "degraded", "unsupported"):
        raise HTTPException(400, "invalid report.status")
    with db.connect() as conn:
        upsert_host(conn, agent_id, host, status)
        conn.execute(
            """INSERT INTO capability_reports (agent_id, host_id, boot_id, kernel, session_id, status, agent_version, report)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (agent_id, host["host_id"], host["boot_id"], host.get("kernel"), d.get("session_id") or None,
             status, d.get("agent_version"), json.dumps(rep)),
        )
    return {"ok": True}


@router.post("/inventory")
async def inventory(request: Request, agent_id: str = Depends(require_agent)):
    d = await read_json(request)
    host = check_agent(d, agent_id)
    inv = d.get("inventory") or {}
    inv_id = inv.get("inventory_id")
    pkgs = inv.get("packages") or []
    if not inv_id or not pkgs:
        raise HTTPException(400, "inventory_id and packages required")
    with db.connect() as conn:
        upsert_host(conn, agent_id, host)
        cur = conn.execute(
            """INSERT INTO inventories (host_id, inventory_id, captured_at, package_count)
               VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (host["host_id"], inv_id, inv.get("captured_at"), len(pkgs)),
        )
        if cur.rowcount == 0:
            return JSONResponse({"ok": True, "duplicate": True}, status_code=409)
        with conn.cursor() as c:
            with c.copy("COPY inventory_packages (host_id, inventory_id, nevra, name, epoch, version, release, arch, requires, provides, install_time) FROM STDIN") as cp:
                for p in pkgs:
                    it = p.get("install_time")
                    cp.write_row((host["host_id"], inv_id, p["nevra"], p["name"], p.get("epoch"), p.get("version"),
                                  p.get("release"), p.get("arch"), p.get("requires") or [], p.get("provides") or [],
                                  datetime.fromtimestamp(it, tz=timezone.utc) if it else None))
    return {"ok": True, "packages": len(pkgs)}


REC_COLS = ("batch_id session_id host_id inventory_id kind source ts_mono_ns ts_utc last_ts_utc count "
            "proc_key pid start_ticks tid ppid parent_key comm uid unit unit_source path requested_path "
            "path_status dev ino deleted ownership packages file_note ok errno flags prot perms exit_code "
            "signal note").split()


def _ts(v):
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


def record_row(b: dict, r: dict) -> tuple:
    f = r.get("file") or {}
    p = r.get("proc") or {}
    return (
        b["batch_id"], b["session_id"], b["host"]["host_id"], b.get("inventory_id"),
        r["kind"], r["source"], r.get("ts_mono_ns"), _ts(r["ts_utc"]), _ts(r.get("last_ts_utc")),
        r.get("count") or 1,
        p.get("key") or None, p.get("pid") or None, p.get("start_ticks") or None,
        r.get("tid"), r.get("ppid"), r.get("parent_key"), r.get("comm"), r.get("uid"),
        r.get("unit") or None, r.get("unit_source"),
        f.get("path") or None, f.get("requested_path") or None, f.get("path_status"),
        f.get("dev"), f.get("ino"), f.get("deleted"), f.get("ownership"), f.get("packages"), f.get("note"),
        r.get("ok"), r.get("errno"), r.get("flags"), r.get("prot"), r.get("perms"),
        r.get("exit_code"), r.get("signal"), r.get("note"),
    )


@router.post("/batches")
async def batches(request: Request, agent_id: str = Depends(require_agent)):
    b = await read_json(request)
    host = check_agent(b, agent_id)
    for k in ("batch_id", "session_id", "seq", "records"):
        if k not in b:
            raise HTTPException(400, f"{k} required")
    if not b["batch_id"].startswith(b["session_id"] + "-"):
        raise HTTPException(400, "batch_id must belong to session")
    recs = b["records"] or []
    with db.connect() as conn:
        upsert_host(conn, agent_id, host)
        sess = conn.execute("SELECT agent_id FROM sessions WHERE session_id = %s", (b["session_id"],)).fetchone()
        if sess and sess["agent_id"] != agent_id:
            raise HTTPException(403, "session belongs to another agent")
        conn.execute(
            """INSERT INTO sessions (session_id, agent_id, host_id, boot_id, kernel, agent_version, first_window_start, policy)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (session_id) DO NOTHING""",
            (b["session_id"], agent_id, host["host_id"], host["boot_id"], host.get("kernel"),
             b.get("agent_version"), _ts(b.get("window_start")), json.dumps(b.get("policy"))),
        )
        cur = conn.execute(
            """INSERT INTO batches (batch_id, session_id, seq, agent_id, host_id, inventory_id, window_start, created_at,
                 reason, complete, record_count, delta, dropped_batch_ids)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (batch_id) DO NOTHING""",
            (b["batch_id"], b["session_id"], b["seq"], agent_id, host["host_id"], b.get("inventory_id"),
             _ts(b.get("window_start")), _ts(b.get("created_at")), b.get("reason"), bool(b.get("complete")),
             len(recs), json.dumps(b.get("delta")), b.get("dropped_batch_ids") or []),
        )
        if cur.rowcount == 0:
            return JSONResponse({"ok": True, "duplicate": True}, status_code=409)
        with conn.cursor() as c:
            with c.copy(f"COPY records ({', '.join(REC_COLS)}) FROM STDIN") as cp:
                for r in recs:
                    cp.write_row(record_row(b, r))
        ended = b.get("reason") in ("shutdown", "reader_closed")
        conn.execute(
            """UPDATE sessions SET
                 last_created_at = GREATEST(COALESCE(last_created_at, %(c)s), %(c)s),
                 first_window_start = LEAST(COALESCE(first_window_start, %(w)s), %(w)s),
                 max_seq = GREATEST(max_seq, %(seq)s),
                 batch_count = batch_count + 1,
                 incomplete_batches = incomplete_batches + %(inc)s,
                 dropped_batch_ids = dropped_batch_ids || %(dropped)s,
                 inventory_ids = CASE WHEN %(inv)s = ANY(inventory_ids) OR %(inv)s IS NULL THEN inventory_ids
                                      ELSE inventory_ids || %(inv)s END,
                 total = CASE WHEN %(seq)s >= max_seq THEN %(total)s::jsonb ELSE total END,
                 ended = ended OR %(ended)s,
                 end_reason = CASE WHEN %(ended)s THEN %(reason)s ELSE end_reason END
               WHERE session_id = %(sid)s""",
            {"c": _ts(b.get("created_at")), "w": _ts(b.get("window_start")), "seq": b["seq"],
             "inc": 0 if b.get("complete") else 1, "dropped": b.get("dropped_batch_ids") or [],
             "inv": b.get("inventory_id"), "total": json.dumps(b.get("total")), "ended": ended,
             "reason": b.get("reason"), "sid": b["session_id"]},
        )
    return {"ok": True, "records": len(recs)}


@router.post("/history")
async def history(request: Request, agent_id: str = Depends(require_agent)):
    d = await read_json(request)
    host = check_agent(d, agent_id)
    hist = d.get("history") or {}
    if hist.get("host_id") != host["host_id"]:
        raise HTTPException(400, "history host_id mismatch")
    txs = hist.get("transactions") or []
    n = 0
    with db.connect() as conn:
        upsert_host(conn, agent_id, host)
        for t in txs[:500]:
            if not isinstance(t.get("tid"), int):
                continue
            ts = lambda v: datetime.fromtimestamp(v, tz=timezone.utc) if isinstance(v, (int, float)) and v > 0 else None
            cur = conn.execute(
                """INSERT INTO pkg_transactions (host_id, tid, begin_at, end_at, loginuid, username, cmdline, comment,
                     return_code, releasever, items)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (host_id, tid) DO NOTHING""",
                (host["host_id"], t["tid"], ts(t.get("begin")), ts(t.get("end")), t.get("loginuid"),
                 (t.get("user") or None), (t.get("cmdline") or "")[:2000] or None, (t.get("comment") or "")[:2000] or None,
                 t.get("return_code"), t.get("releasever"), json.dumps(t.get("items") or [])))
            n += cur.rowcount
    return {"ok": True, "new": n}


@router.get("/health")
def health():
    return {"ok": True, "schema_version": SCHEMA_VERSION}

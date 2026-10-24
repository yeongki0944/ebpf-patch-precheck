"""패치 계획 계산 요청 (UI → 서버 저장 → 에이전트 pull → 결과 업로드).

에이전트는 요청을 가져가 "계산(resolve)"만 수행한다. 서버는 에이전트로 접속하지 않는다.
"""
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from . import analysis, db
from .auth import require_agent

router = APIRouter(prefix="/api/v1/tasks")

PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
REL_RE = re.compile(r"^(latest|[0-9][0-9.]{0,31})$")
CLAIM_TIMEOUT = "15 minutes"
PENDING_TIMEOUT = "30 minutes"


def validate_request(packages: list[str], releasever: str | None):
    if len(packages) > 200:
        raise HTTPException(400, "too many packages (max 200)")
    for p in packages:
        if not PKG_RE.match(p):
            raise HTTPException(400, f"invalid package name: {p!r}")
    if releasever and not REL_RE.match(releasever):
        raise HTTPException(400, f"invalid releasever: {releasever!r}")


def create(conn, host_id: str, kind: str, packages: list[str], kernel: bool, releasever: str | None,
           label: str | None, user: str) -> int:
    validate_request(packages, releasever)
    # 아직 가져가지 않은(pending) 같은 요청만 재사용 (중복 클릭). running 은 에이전트 재시작 등으로 멈췄을 수 있음
    expire(conn)
    ex = conn.execute("""SELECT id FROM plan_tasks WHERE host_id = %s AND kind = %s AND status = 'pending'
                         AND packages = %s AND kernel = %s AND releasever IS NOT DISTINCT FROM %s""",
                      (host_id, kind, packages, kernel, releasever or None)).fetchone()
    if ex:
        return ex["id"]
    row = conn.execute(
        """INSERT INTO plan_tasks (host_id, kind, packages, kernel, releasever, label, requested_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (host_id, kind, packages, kernel, releasever or None, label or None, user)).fetchone()
    return row["id"]


def expire(conn):
    conn.execute(f"""UPDATE plan_tasks SET status = 'expired', finished_at = now(),
                       error = 'agent did not complete in time'
                     WHERE (status = 'running' AND claimed_at < now() - interval '{CLAIM_TIMEOUT}')
                        OR (status = 'pending' AND requested_at < now() - interval '{PENDING_TIMEOUT}')""")


@router.post("/claim")
def claim(request: Request, agent_id: str = Depends(require_agent)):
    """에이전트 소유 호스트의 가장 오래된 대기 요청 하나를 running 으로 바꿔 돌려준다."""
    with db.connect() as conn:
        expire(conn)
        # 에이전트는 한 번에 하나만 처리한다. 새로 가져가려는 시점에 남은 running 은 중단된 것(재시작·OOM 등)
        conn.execute(
            """UPDATE plan_tasks t SET status = 'failed', finished_at = now(),
                 error = 'interrupted: agent restarted before reporting result'
               FROM hosts h WHERE h.host_id = t.host_id AND h.agent_id = %s AND t.status = 'running'""", (agent_id,))
        row = conn.execute(
            """UPDATE plan_tasks SET status = 'running', claimed_at = now()
               WHERE id = (SELECT t.id FROM plan_tasks t JOIN hosts h USING (host_id)
                           WHERE h.agent_id = %s AND t.status = 'pending'
                           ORDER BY t.requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
               RETURNING id, kind, packages, kernel, releasever""", (agent_id,)).fetchone()
    if not row:
        return Response(status_code=204)
    return {"id": row["id"], "kind": row["kind"], "packages": row["packages"], "kernel": row["kernel"],
            "releasever": row["releasever"] or ""}


@router.post("/{task_id}/result")
async def result(task_id: int, request: Request, agent_id: str = Depends(require_agent)):
    body = await request.body()
    if len(body) > 16 * 1024 * 1024:
        raise HTTPException(413)
    try:
        d = json.loads(body)
    except ValueError:
        raise HTTPException(400, "invalid json")
    with db.connect() as conn:
        t = conn.execute(
            """SELECT t.*, h.agent_id FROM plan_tasks t JOIN hosts h USING (host_id) WHERE t.id = %s FOR UPDATE OF t""",
            (task_id,)).fetchone()
        if not t or t["agent_id"] != agent_id:
            raise HTTPException(404)
        if t["status"] != "running":
            raise HTTPException(409, f"task status is {t['status']}")
        if not d.get("ok"):
            conn.execute("UPDATE plan_tasks SET status = 'failed', finished_at = now(), error = %s WHERE id = %s",
                         ((d.get("error") or "unknown error")[:4000], task_id))
            return {"ok": True}
        res = d.get("result") or {}
        if res.get("host_id") != t["host_id"]:
            conn.execute("UPDATE plan_tasks SET status = 'failed', finished_at = now(), error = 'host_id mismatch' WHERE id = %s", (task_id,))
            raise HTTPException(400, "host_id mismatch")
        if t["kind"] == "list_updates":
            conn.execute(
                """INSERT INTO available_updates (host_id, inventory_id, releasever, generated_at, updates)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT (host_id) DO UPDATE SET inventory_id = EXCLUDED.inventory_id, releasever = EXCLUDED.releasever,
                     generated_at = EXCLUDED.generated_at, updates = EXCLUDED.updates, received_at = now()""",
                (t["host_id"], res.get("inventory_id"), res.get("releasever"), res.get("generated_at"),
                 json.dumps(res.get("updates") or [])))
            conn.execute("UPDATE plan_tasks SET status = 'done', finished_at = now() WHERE id = %s", (task_id,))
            return {"ok": True}
        # resolve_plan: 업로드와 같은 검증 경로로 등록
        try:
            v = analysis.validate_plan(conn, res)
        except HTTPException as e:
            conn.execute("UPDATE plan_tasks SET status = 'failed', finished_at = now(), error = %s WHERE id = %s",
                         (f"plan validation: {e.detail}", task_id))
            return {"ok": True}
        p = conn.execute(
            """INSERT INTO patch_plans (host_id, inventory_id, plan_type, label, plan, validation, uploaded_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (res["host_id"], res["inventory_id"], res["plan_type"], t["label"], json.dumps(res),
             analysis.to_json(v), f"task:{t['requested_by']}")).fetchone()
        conn.execute("UPDATE plan_tasks SET status = 'done', finished_at = now(), plan_id = %s WHERE id = %s",
                     (p["id"], task_id))
    return {"ok": True, "plan_id": p["id"]}

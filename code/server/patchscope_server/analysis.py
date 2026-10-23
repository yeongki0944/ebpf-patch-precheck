"""패치 계획 검증과 근거 기반 영향 분석 (설계 8절).

원칙
- 미관측 = 안전 아님 ("no_observation" 으로만 표시)
- 파일 열기 = 함수 사용 아님 ("file_access" 와 "direct" 를 구분)
- 추측 경로(unresolved/requested_only)는 RPM 매핑 근거로 쓰지 않음
- 판정 근거(record id, 시각, 증거 종류)를 결과에 보존
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from fastapi import HTTPException

SUPPORTED_ACTIONS = {"upgrade", "install"}  # install 은 kernel installonly 만
UNSUPPORTED_ACTIONS = {"remove", "obsolete", "downgrade", "reinstall", "obsoleted"}
KERNEL_NAMES = re.compile(r"^kernel(-core|-modules(-core|-extra)?|-devel|-headers|-tools(-libs)?|-livepatch.*)?$")


def is_kernel_pkg(name: str) -> bool:
    return bool(KERNEL_NAMES.match(name))


def nevra_name(nevra: str) -> str:
    # name-epoch:version-release.arch  (name 에 '-' 포함 가능)
    m = re.match(r"^(.*)-[^-:]+:[^-]+-[^-]+$", nevra)
    return m.group(1) if m else nevra


# ---------------------------------------------------------------- plan

def validate_plan(conn, plan: dict) -> dict:
    """plan-export JSON 검증. 반환: 정규화된 plan + warnings + completeness."""
    for k in ("schema_version", "host_id", "inventory_id", "generated_at", "plan_type", "items"):
        if k not in plan:
            raise HTTPException(400, f"plan.{k} required")
    if plan["schema_version"] != "1":
        raise HTTPException(400, "plan schema_version must be 1")
    if plan["plan_type"] not in ("packages", "kernel"):
        raise HTTPException(400, "plan_type must be packages|kernel")
    host = conn.execute("SELECT * FROM hosts WHERE host_id = %s", (plan["host_id"],)).fetchone()
    if not host:
        raise HTTPException(400, "unknown host_id")
    inv = conn.execute("SELECT * FROM inventories WHERE host_id = %s AND inventory_id = %s",
                       (plan["host_id"], plan["inventory_id"])).fetchone()
    if not inv:
        raise HTTPException(409, "plan inventory_id not received from this host. regenerate plan or wait for agent inventory")

    warnings: list[str] = []
    latest = conn.execute("SELECT inventory_id FROM inventories WHERE host_id = %s ORDER BY received_at DESC LIMIT 1",
                          (plan["host_id"],)).fetchone()
    if latest and latest["inventory_id"] != plan["inventory_id"]:
        warnings.append(f"inventory changed since plan ({plan['inventory_id']} -> {latest['inventory_id']}): regenerate plan")

    installed = {r["nevra"] for r in conn.execute(
        "SELECT nevra FROM inventory_packages WHERE host_id = %s AND inventory_id = %s",
        (plan["host_id"], plan["inventory_id"]))}
    items, unsupported = [], []
    for it in plan["items"]:
        action, name = it.get("action"), it.get("name")
        if not action or not name:
            raise HTTPException(400, "item.action and item.name required")
        kernel = is_kernel_pkg(name)
        if action in UNSUPPORTED_ACTIONS or (action == "install" and not kernel):
            unsupported.append(it)
            continue
        if action not in SUPPORTED_ACTIONS:
            unsupported.append(it)
            continue
        if action == "upgrade" and it.get("from_nevra") not in installed:
            warnings.append(f"{name}: from_nevra {it.get('from_nevra')} not in plan inventory")
        items.append({**it, "kernel": kernel})
    if unsupported:
        warnings.append(f"{len(unsupported)} unsupported transaction item(s) (remove/obsolete/...): not analyzed")
    if plan.get("completeness") != "complete":
        warnings.append(f"plan completeness={plan.get('completeness')!r}: dependency resolution may be partial")
    if plan["plan_type"] == "packages" and any(i["kernel"] for i in items):
        warnings.append("kernel packages in packages plan: reported in kernel section")
    return {"items": items, "unsupported": unsupported, "warnings": warnings,
            "complete": not unsupported and plan.get("completeness") == "complete"}


# ---------------------------------------------------------------- analysis

def sessions_for(conn, host_id: str, inventory_id: str, session_ids: list[str] | None):
    if session_ids:
        rows = conn.execute("SELECT * FROM sessions WHERE host_id = %s AND session_id = ANY(%s)", (host_id, session_ids)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM sessions WHERE host_id = %s AND %s = ANY(inventory_ids) ORDER BY first_window_start",
                            (host_id, inventory_id)).fetchall()
    return rows


def coverage(sessions) -> dict:
    total_loss = 0
    for s in sessions:
        t = s["total"] or {}
        total_loss += max(t.get("perf_lost", 0), t.get("kernel_output_fail", 0)) + t.get("queue_drop", 0) + \
            t.get("inflight_full", 0) + t.get("spool_drop_records", 0) + t.get("followup_drop", 0)
    return {
        "sessions": [s["session_id"] for s in sessions],
        "from": min((s["first_window_start"] for s in sessions if s["first_window_start"]), default=None),
        "to": max((s["last_created_at"] for s in sessions if s["last_created_at"]), default=None),
        "incomplete_batches": sum(s["incomplete_batches"] for s in sessions),
        "dropped_batches": sum(len(s["dropped_batch_ids"]) for s in sessions),
        "lost_events_estimate": total_loss,
        "complete": bool(sessions) and all(s["incomplete_batches"] == 0 and not s["dropped_batch_ids"] for s in sessions),
    }


DIRECT_KINDS = ("exec", "process", "mapped_file", "file_mmap")
ACCESS_KINDS = ("file_open", "open_fd")


def analyze(conn, plan_row: dict) -> dict:
    plan = plan_row["plan"]
    v = plan_row["validation"]
    host_id, inv_id = plan["host_id"], plan["inventory_id"]
    sessions = sessions_for(conn, host_id, inv_id, plan.get("session_ids"))
    sids = [s["session_id"] for s in sessions]
    cov = coverage(sessions)

    pkg_items = [i for i in v["items"] if not i["kernel"]]
    from_nevras = [i["from_nevra"] for i in pkg_items if i.get("from_nevra")]

    # 변경 RPM 이 소유한 파일을 사용한 증거 (경로 확정 + rpm 소유)
    evidence = conn.execute(
        """SELECT r.id, r.kind, r.source, r.ts_utc, r.last_ts_utc, r.count, r.proc_key, r.pid, r.comm,
                  r.unit, r.unit_source, r.path, r.path_status, r.ok, r.perms, r.prot, p.nevra
           FROM records r CROSS JOIN LATERAL unnest(r.packages) AS p(nevra)
           WHERE r.session_id = ANY(%s) AND r.ownership IN ('rpm','deleted') AND p.nevra = ANY(%s)
             AND r.path_status NOT IN ('unresolved','requested_only')
             AND (r.kind <> 'file_open' OR r.ok)
           ORDER BY r.ts_utc""",
        (sids, from_nevras),
    ).fetchall()

    by_pkg: dict[str, dict] = {}
    for it in pkg_items:
        by_pkg[it["from_nevra"]] = {"item": it, "direct": defaultdict(list), "access": defaultdict(list)}
    for e in evidence:
        slot = by_pkg.get(e["nevra"])
        if not slot:
            continue
        cls = "direct" if e["kind"] in DIRECT_KINDS else "access"
        slot[cls][(e["unit"] or "", e["proc_key"] or "")].append(e)

    # 정적 의존: 변경 패키지의 Provides 를 Requires 하는 설치 패키지 (rpm 버전 비교는 rpm 규칙 그대로가 아닌 이름 수준 → 후보로만 표시)
    static = static_dependents(conn, host_id, inv_id, [i["name"] for i in pkg_items])

    packages = []
    for nevra, slot in by_pkg.items():
        it = slot["item"]
        direct = summarize(slot["direct"])
        access = summarize(slot["access"])
        # 직접 근거가 있는 프로세스는 access 목록에서 제외 (중복 제거)
        dkeys = {(d["unit"], d["proc_key"]) for d in direct}
        access = [a for a in access if (a["unit"], a["proc_key"]) not in dkeys]
        if direct:
            cls = "direct"
        elif access:
            cls = "file_access"
        elif static.get(it["name"]):
            cls = "static_dependency"
        else:
            cls = "no_observation"
        packages.append({
            "name": it["name"], "action": it["action"], "from": it.get("from_nevra"), "to": it.get("to_nevra"),
            "classification": cls,
            "direct": direct, "file_access": access,
            "services": sorted({d["unit"] or "(unattributed)" for d in direct + access}),
            "static_dependents": static.get(it["name"], [])[:50],
        })
    order = {"direct": 0, "file_access": 1, "static_dependency": 2, "no_observation": 3}
    packages.sort(key=lambda p: (order[p["classification"]], p["name"]))

    unresolved = conn.execute(
        """SELECT kind, path_status, ownership, count(*) AS n, sum(count) AS events
           FROM records WHERE session_id = ANY(%s) AND kind IN ('exec','file_open','file_mmap','mapped_file','process')
             AND (path_status IN ('unresolved') OR ownership IN ('unknown','unmanaged'))
             AND NOT (kind = 'file_open' AND ok IS FALSE)
           GROUP BY 1,2,3 ORDER BY n DESC""", (sids,)).fetchall()

    services = defaultdict(lambda: {"packages": set(), "processes": set()})
    for p in packages:
        for d in p["direct"] + p["file_access"]:
            s = services[d["unit"] or "(unattributed)"]
            s["packages"].add(p["name"])
            s["processes"].add(d["comm"])

    return {
        "plan_id": plan_row["id"],
        "host_id": host_id,
        "inventory_id": inv_id,
        "plan_type": plan["plan_type"],
        "coverage": cov,
        "plan_warnings": v["warnings"],
        "plan_complete": v["complete"],
        "unsupported_items": v["unsupported"],
        "packages": packages,
        "services": [{"unit": u, "packages": sorted(s["packages"]), "processes": sorted(s["processes"])}
                     for u, s in sorted(services.items())],
        "unresolved": unresolved,
        "kernel": kernel_section(conn, plan, v, sids),
        "disclaimer": "관측 기반 영향 후보이며 패치 후 호환성·무중단을 보장하지 않습니다. "
                      "no_observation 은 해당 기간에 관측된 연결이 없다는 뜻이며 안전·미사용 판정이 아닙니다.",
    }


def summarize(groups: dict) -> list[dict]:
    out = []
    for (unit, proc_key), evs in groups.items():
        kinds = sorted({e["kind"] for e in evs})
        out.append({
            "unit": unit or None,
            "unit_source": evs[0]["unit_source"],
            "proc_key": proc_key,
            "pid": evs[0]["pid"],
            "comm": evs[0]["comm"],
            "evidence_kinds": kinds,
            "files": sorted({e["path"] for e in evs})[:20],
            "first": min(e["ts_utc"] for e in evs),
            "last": max((e["last_ts_utc"] or e["ts_utc"]) for e in evs),
            "events": sum(e["count"] for e in evs),
            "record_ids": [e["id"] for e in evs[:20]],
        })
    out.sort(key=lambda d: (d["unit"] or "~", d["comm"] or ""))
    return out


def static_dependents(conn, host_id, inv_id, names: list[str]) -> dict[str, list[str]]:
    """변경 패키지 이름 또는 그 Provides 이름을 Requires 하는 패키지. 버전 조건은 표시만 하고 판정하지 않음."""
    if not names:
        return {}
    rows = conn.execute(
        """WITH changed AS (
             SELECT name, split_part(prov, ' ', 1) AS cap
             FROM inventory_packages, unnest(provides) AS prov
             WHERE host_id = %(h)s AND inventory_id = %(i)s AND name = ANY(%(n)s)
           )
           SELECT DISTINCT c.name AS changed, ip.nevra AS dependent
           FROM inventory_packages ip, unnest(ip.requires) AS req, changed c
           WHERE ip.host_id = %(h)s AND ip.inventory_id = %(i)s AND split_part(req, ' ', 1) = c.cap
             AND ip.name <> c.name""",
        {"h": host_id, "i": inv_id, "n": names}).fetchall()
    out = defaultdict(list)
    for r in rows:
        out[r["changed"]].append(r["dependent"])
    return {k: sorted(v) for k, v in out.items()}


def kernel_section(conn, plan, v, sids) -> dict | None:
    kitems = [i for i in v["items"] if i["kernel"]]
    if not kitems and plan["plan_type"] != "kernel":
        return None
    cap = conn.execute(
        "SELECT report, kernel, boot_id, received_at FROM capability_reports WHERE host_id = %s ORDER BY received_at DESC LIMIT 1",
        (plan["host_id"],)).fetchone()
    installed = [r["nevra"] for r in conn.execute(
        "SELECT nevra FROM inventory_packages WHERE host_id = %s AND inventory_id = %s AND name ~ '^kernel(-core)?$' ORDER BY nevra",
        (plan["host_id"], plan["inventory_id"]))]
    ks = plan.get("kernel") or {}
    return {
        "running": cap["kernel"] if cap else None,
        "boot_id": cap["boot_id"] if cap else None,
        "installed": installed,
        "target": [i.get("to_nevra") for i in kitems],
        "items": kitems,
        "modules": ks.get("loaded_modules", []),
        "external_modules": ks.get("external_modules", []),
        "dkms": ks.get("dkms"),
        "default_boot": ks.get("default_boot"),
        "missing": [k for k in ("loaded_modules", "default_boot") if k not in ks],
        "checks": ["reboot succeeds", "SSM returns", "required services active", "HTTP/DB/batch functional tests",
                   "no new kernel errors (journalctl -k -p err)", "agent reconnects with new boot_id and precheck passes"],
        "note": "커널 변경은 실행 중인 모든 프로세스에 영향을 줍니다. 시스템 호출 관측만으로 새 커널 호환성을 판정하지 않습니다.",
    }


def to_json(v) -> str:
    return json.dumps(v, default=str, ensure_ascii=False)

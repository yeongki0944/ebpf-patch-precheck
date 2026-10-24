"""운영자가 실행한 패키지 변경 명령(dnf 거래) 기준 전후 비교.

dnf 거래 이력의 명령·시각을 기준점으로 삼아, 사용자가 관측 기간을 고르지 않아도 다음을 보여준다.
  - 패키지 변화 : 거래 항목 (업그레이드/설치/제거) + 거래 전후 인벤토리 비교
  - 서비스 영향 : 거래 직전 WINDOW 와 직후 WINDOW 동안 각 서비스가 사용한 변경 패키지 버전
  - 재시작 필요 : 거래 후 재검사에서 교체 전(삭제된) 파일을 아직 매핑 중인 프로세스
  - 사전 분석  : 같은 변경을 포함한 패치 계획이 거래 전에 있었는지

관측은 에이전트가 동작한 기간에 한정된다. 직전·직후 구간에 관측이 없으면 그렇게 표시한다.
"""
from datetime import timedelta

from . import analysis, viz

WINDOW = timedelta(hours=6)
UPDATE_ACTIONS = {"Upgrade", "Install", "Downgrade", "Reinstall", "Obsolete"}
OLD_ACTIONS = {"Upgraded", "Downgraded", "Obsoleted", "Reinstalled"}
REMOVE_ACTIONS = {"Removed", "Erase"}


def list_changes(conn, host_id: str) -> list[dict]:
    rows = conn.execute("SELECT * FROM pkg_transactions WHERE host_id = %s ORDER BY begin_at DESC NULLS LAST", (host_id,)).fetchall()
    out = []
    for t in rows:
        items = summarize_items(t["items"])
        out.append({**t, "summary": items, "kernel": any(analysis.is_kernel_pkg(i["name"]) for i in items),
                    "who": who(t)})
    return out


def who(t) -> str:
    if t["username"]:
        return t["username"]
    if t["loginuid"] in (None, 4294967295, -1):
        return "로그인 세션 없음 (자동화·원격 명령)"
    return str(t["loginuid"])


def summarize_items(items) -> list[dict]:
    """거래 항목을 패키지 단위로 묶는다: name → action, from, to."""
    by = {}
    for i in items:
        n = i["name"]
        d = by.setdefault(n, {"name": n, "action": None, "from": None, "to": None, "from_nevra": None, "to_nevra": None})
        a = i["action"]
        if a in OLD_ACTIONS:
            d["from"], d["from_nevra"] = viz.evr(i["nevra"], n), i["nevra"]
        elif a in REMOVE_ACTIONS:
            d["action"], d["from"], d["from_nevra"] = "제거", viz.evr(i["nevra"], n), i["nevra"]
        else:
            d["to"], d["to_nevra"] = viz.evr(i["nevra"], n), i["nevra"]
            d["action"] = {"Upgrade": "업그레이드", "Install": "설치", "Downgrade": "다운그레이드",
                           "Reinstall": "재설치", "Obsolete": "대체 설치"}.get(a, a)
    for d in by.values():
        if d["action"] == "설치" and analysis.is_kernel_pkg(d["name"]):
            d["action"] = "커널 설치 (기존 유지)"
    return sorted(by.values(), key=lambda d: (not analysis.is_kernel_pkg(d["name"]), d["name"]))


def detail(conn, host_id: str, tid: int) -> dict | None:
    t = conn.execute("SELECT * FROM pkg_transactions WHERE host_id = %s AND tid = %s", (host_id, tid)).fetchone()
    if not t:
        return None
    items = summarize_items(t["items"])
    at = t["begin_at"]
    end = t["end_at"] or at
    names = [i["name"] for i in items]

    # 직전·직후 관측 구간
    before_lo, after_hi = at - WINDOW, end + WINDOW
    cov = conn.execute(
        """SELECT count(*) FILTER (WHERE created_at BETWEEN %s AND %s) AS before_batches,
                  count(*) FILTER (WHERE created_at BETWEEN %s AND %s) AS after_batches,
                  count(*) FILTER (WHERE created_at BETWEEN %s AND %s AND NOT complete) AS before_bad,
                  count(*) FILTER (WHERE created_at BETWEEN %s AND %s AND NOT complete) AS after_bad
           FROM batches WHERE host_id = %s""",
        (before_lo, at, end, after_hi, before_lo, at, end, after_hi, host_id)).fetchone()

    # 서비스별 변경 패키지 사용 버전 (전/후)
    rows = conn.execute(
        """SELECT CASE WHEN r.ts_utc < %(at)s THEN 'before' ELSE 'after' END AS side,
                  coalesce(r.unit, '(서비스 미확인)') AS unit, p AS nevra,
                  count(DISTINCT r.proc_key) AS procs, max(coalesce(r.last_ts_utc, r.ts_utc)) AS last,
                  min(r.ts_utc) AS first
           FROM records r, unnest(r.packages) p
           WHERE r.host_id = %(h)s AND r.ownership IN ('rpm','deleted')
             AND r.kind IN ('exec','process','mapped_file','file_mmap','stale_mapping')
             AND ((r.ts_utc BETWEEN %(lo)s AND %(at)s) OR (r.ts_utc BETWEEN %(end)s AND %(hi)s))
             AND (r.unit IS NULL OR r.unit <> ALL(%(ex)s))
           GROUP BY 1, 2, 3""",
        {"at": at, "end": end, "lo": before_lo, "hi": after_hi, "h": host_id,
         "ex": list(analysis.OPERATOR_UNITS)}).fetchall()
    want = set(names)
    svc = {}
    for r in rows:
        n = analysis.nevra_name(r["nevra"])
        if n not in want:
            continue
        s = svc.setdefault(r["unit"], {"unit": r["unit"], "pkgs": {}})
        e = s["pkgs"].setdefault(n, {"name": n, "before": set(), "after": set(), "after_last": None})
        e[r["side"]].add(viz.evr(r["nevra"], n))
        if r["side"] == "after":
            e["after_last"] = max(filter(None, [e["after_last"], r["last"]]))

    # 재시작 필요: 거래 후 재검사에서 교체 전 파일을 매핑 중
    stale = conn.execute(
        """SELECT coalesce(unit,'(서비스 미확인)') AS unit, comm, pid, p AS nevra, max(ts_utc) AS last,
                  array_agg(DISTINCT path) AS files
           FROM records LEFT JOIN LATERAL unnest(packages) p ON true
           WHERE host_id = %s AND kind = 'stale_mapping' AND ts_utc BETWEEN %s AND %s
           GROUP BY 1,2,3,4 ORDER BY 1,2""", (host_id, end, after_hi)).fetchall()
    last_rescan = conn.execute(
        """SELECT max(ts_utc) AS at, count(*) AS n FROM records
           WHERE host_id = %s AND kind = 'rescan' AND ts_utc BETWEEN %s AND %s""", (host_id, end, after_hi)).fetchone()
    # 가장 마지막 재검사 기준 (이후 재시작하면 사라짐)
    latest = [s for s in stale if last_rescan["at"] and s["last"] >= last_rescan["at"] - timedelta(seconds=90)]
    stale_by_unit = {}
    for s in latest:
        n = analysis.nevra_name(s["nevra"]) if s["nevra"] else None
        u = stale_by_unit.setdefault(s["unit"], {"unit": s["unit"], "procs": set(), "pkgs": set(), "files": set()})
        u["procs"].add(f"{s['comm']}({s['pid']})")
        if n:
            u["pkgs"].add(n)
        u["files"].update(f for f in s["files"] if f)

    services = []
    for s in svc.values():
        status_list = []
        for e in s["pkgs"].values():
            if e["before"] and e["after"] and e["before"] != e["after"]:
                e["status"] = "반영됨" if not (e["before"] & e["after"]) else "일부 반영"
            elif e["before"] and e["after"]:
                e["status"] = "이전 버전 계속 사용"
            elif e["after"]:
                e["status"] = "변경 후 새로 사용"
            else:
                e["status"] = "변경 후 사용 관측 없음"
            e["before"], e["after"] = sorted(e["before"]), sorted(e["after"])
            status_list.append(e["status"])
        st = stale_by_unit.get(s["unit"])
        restart = bool(st) or "이전 버전 계속 사용" in status_list or "일부 반영" in status_list
        services.append({**s, "pkgs": sorted(s["pkgs"].values(), key=lambda e: e["name"]),
                         "restart": restart, "stale": st})
    for u, st in stale_by_unit.items():
        if u not in svc:
            services.append({"unit": u, "pkgs": [], "restart": True, "stale": st})
    services.sort(key=lambda s: (not s["restart"], s["unit"]))
    for s in services:
        if s["stale"]:
            s["stale"] = {k: sorted(v) if isinstance(v, set) else v for k, v in s["stale"].items()}

    # 인벤토리 전후
    inv_before = conn.execute("SELECT inventory_id, received_at FROM inventories WHERE host_id = %s AND received_at <= %s ORDER BY received_at DESC LIMIT 1", (host_id, at)).fetchone()
    inv_after = conn.execute("SELECT inventory_id, received_at FROM inventories WHERE host_id = %s AND received_at >= %s ORDER BY received_at LIMIT 1", (host_id, end)).fetchone()
    # 사전 분석: 거래 전에 만든 계획 중 같은 패키지를 포함한 것
    plans = conn.execute(
        """SELECT p.id, p.label, p.uploaded_at, p.uploaded_by,
                  count(*) FILTER (WHERE item->>'name' = ANY(%s)) AS matched, jsonb_array_length(p.plan->'items') AS total
           FROM patch_plans p, jsonb_array_elements(p.plan->'items') item
           WHERE p.host_id = %s AND p.uploaded_at <= %s
           GROUP BY p.id HAVING count(*) FILTER (WHERE item->>'name' = ANY(%s)) > 0
           ORDER BY p.uploaded_at DESC LIMIT 5""", (names, host_id, at, names)).fetchall()
    # 재부팅 (거래 후)
    boot = conn.execute(
        """SELECT boot_id, kernel, min(first_window_start) AS at FROM sessions
           WHERE host_id = %s AND first_window_start > %s GROUP BY 1,2 ORDER BY 3 LIMIT 1""", (host_id, end)).fetchone()
    prev_boot = conn.execute(
        "SELECT boot_id, kernel FROM sessions WHERE host_id = %s AND first_window_start <= %s ORDER BY first_window_start DESC LIMIT 1",
        (host_id, at)).fetchone()
    rebooted = boot if boot and prev_boot and boot["boot_id"] != prev_boot["boot_id"] else None

    kernel_items = [i for i in items if analysis.is_kernel_pkg(i["name"])]
    return {"t": t, "who": who(t), "pkg_items": items, "services": services, "coverage": cov,
            "inv_before": inv_before, "inv_after": inv_after, "plans": plans, "window": WINDOW,
            "kernel_items": kernel_items, "rebooted": rebooted, "prev_boot": prev_boot,
            "last_rescan": last_rescan, "n_restart": sum(1 for s in services if s["restart"])}

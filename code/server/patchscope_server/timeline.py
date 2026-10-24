"""패키지 하나의 변경 타임라인 (서비스 관점).

여러 근거를 시간순으로 합친다. 각 이벤트에는 출처를 표시한다.
  dnf     : dnf 거래 이력 - 언제, 누가(loginuid), 명령, 버전 변화
  rpm     : RPM DB 설치 시각 (dnf 이력이 없을 때 보조)
  inventory: 에이전트가 감지한 설치 버전 변화
  plan    : 이 패키지를 포함한 패치 계획(영향 분석) 생성
  observe : 이 서비스가 해당 버전 파일을 실제로 사용하기 시작/마지막으로 사용 (관측 기간 기준)
  boot    : 재부팅 (boot_id 변화)

"서비스 반영"은 관측으로만 판단한다. 설치만 되고 서비스가 재시작되지 않으면 구 버전 사용이 계속 관측된다.
"""
from . import analysis, viz


def build(conn, host_id: str, name: str, unit: str | None) -> dict:
    events = []

    # 1) dnf 거래 이력
    txs = conn.execute(
        """SELECT * FROM pkg_transactions WHERE host_id = %s AND items @> %s::jsonb ORDER BY begin_at""",
        (host_id, f'[{{"name": "{name}"}}]')).fetchall()
    for t in txs:
        mine = [i for i in t["items"] if i["name"] == name]
        acts = {i["action"] for i in mine}
        new = [i for i in mine if i["action"] not in ("Upgraded", "Downgraded", "Obsoleted", "Removed", "Erase")]
        old = [i for i in mine if i["action"] in ("Upgraded", "Downgraded", "Obsoleted")]
        events.append({
            "at": t["begin_at"], "kind": "dnf", "title": _act_title(acts),
            "from": viz.evr(old[0]["nevra"], name) if old else None,
            "to": viz.evr(new[0]["nevra"], name) if new else None,
            "who": t["username"] or ("(로그인 세션 없음: 자동화·원격 명령)" if t["loginuid"] in (None, 4294967295) else str(t["loginuid"])),
            "cmd": t["cmdline"], "comment": t["comment"], "tid": t["tid"], "rc": t["return_code"],
            "others": len(t["items"]) - len(mine), "releasever": t["releasever"]})

    # 2) 인벤토리 버전 변화 (에이전트 관측)
    invs = conn.execute(
        """SELECT i.inventory_id, i.received_at, p.nevra, p.install_time
           FROM inventories i LEFT JOIN inventory_packages p
             ON p.host_id = i.host_id AND p.inventory_id = i.inventory_id AND p.name = %s
           WHERE i.host_id = %s ORDER BY i.received_at""", (name, host_id)).fetchall()
    prev = None
    versions = {}
    for r in invs:
        cur = r["nevra"] or ""          # 미설치 인벤토리는 "" 로 통일 (None/"" 차이로 거짓 변경 방지)
        if cur:
            versions.setdefault(cur, r["install_time"])
        if prev is not None and cur != prev:
            events.append({"at": r["received_at"], "kind": "inventory",
                           "title": "새로 설치 감지" if not prev else "제거 감지" if not cur else "설치 버전 변경 감지",
                           "from": viz.evr(prev, name) if prev else None, "to": viz.evr(cur, name) if cur else "(제거됨)",
                           "inv": r["inventory_id"]})
        prev = cur
    # dnf 이력이 없으면 RPM 설치 시각으로 보조
    if not txs:
        for nev, it in versions.items():
            if it:
                events.append({"at": it, "kind": "rpm", "title": "RPM 설치 시각", "to": viz.evr(nev, name),
                               "who": "기록 없음 (dnf 이력 미수신)"})

    # 3) 이 패키지를 포함한 패치 계획
    for p in conn.execute(
            """SELECT id, label, plan_type, uploaded_at, uploaded_by, item
               FROM patch_plans, jsonb_array_elements(plan->'items') item
               WHERE host_id = %s AND item->>'name' = %s ORDER BY uploaded_at""", (host_id, name)):
        it = p["item"]
        by = p["uploaded_by"] or ""
        events.append({"at": p["uploaded_at"], "kind": "plan", "title": f"패치 계획 #{p['id']} 에 포함",
                       "label": p["label"], "plan_id": p["id"],
                       "from": viz.evr(it.get("from_nevra") or "", name) if it.get("from_nevra") else None,
                       "to": viz.evr(it.get("to_nevra") or "", name) if it.get("to_nevra") else None,
                       "who": by.removeprefix("task:") + (" (화면에서 요청)" if by.startswith("task:") else "")})

    # 4) 서비스의 버전별 사용 관측 (관측 기간 단위)
    usage = []
    if unit is not None:
        u = None if unit == "(서비스 미확인)" else unit
        rows = conn.execute(
            """SELECT p AS nevra, r.session_id, min(r.ts_utc) AS first, max(coalesce(r.last_ts_utc, r.ts_utc)) AS last,
                      count(DISTINCT r.proc_key) AS procs, bool_or(r.deleted) AS deleted
               FROM records r, unnest(r.packages) p
               WHERE r.host_id = %s AND r.unit IS NOT DISTINCT FROM %s AND r.ownership IN ('rpm','deleted')
                 AND p LIKE %s
               GROUP BY 1, 2 ORDER BY first""",
            (host_id, u, name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "-%:%")).fetchall()
        rows = [r for r in rows if analysis.nevra_name(r["nevra"]) == name]
        seen = {}
        for r in rows:
            v = viz.evr(r["nevra"], name)
            if v not in seen:
                seen[v] = r
                events.append({"at": r["first"], "kind": "observe", "title": "서비스가 이 버전 사용 시작 (관측)",
                               "to": v, "procs": r["procs"], "deleted": r["deleted"]})
            seen[v] = {**seen[v], "last": r["last"]}
        usage = [{"version": v, "first": r["first"], "last": r["last"]} for v, r in seen.items()]
        usage.sort(key=lambda x: x["first"])

    # 5) 재부팅
    boots = conn.execute(
        """SELECT boot_id, kernel, min(first_window_start) AS at FROM sessions WHERE host_id = %s
           GROUP BY 1, 2 ORDER BY 3""", (host_id,)).fetchall()
    for prev_b, b in zip(boots, boots[1:]):
        events.append({"at": b["at"], "kind": "boot", "title": "재부팅 감지 (boot ID 변경)",
                       "from": prev_b["kernel"], "to": b["kernel"]})

    events = [e for e in events if e["at"] is not None]
    events.sort(key=lambda e: (e["at"], ["plan", "dnf", "rpm", "inventory", "boot", "observe"].index(e["kind"])))

    # 현재 상태 요약
    cur_inst = conn.execute(
        """SELECT p.nevra FROM inventory_packages p
           WHERE p.host_id = %s AND p.name = %s
             AND p.inventory_id = (SELECT inventory_id FROM inventories WHERE host_id = %s ORDER BY received_at DESC LIMIT 1)""",
        (host_id, name, host_id)).fetchone()
    installed = viz.evr(cur_inst["nevra"], name) if cur_inst else None
    in_use = usage[-1]["version"] if usage else None
    upd = conn.execute("SELECT updates FROM available_updates WHERE host_id = %s", (host_id,)).fetchone()
    target = next((viz.evr(x["to_nevra"], name) for x in (upd["updates"] if upd else []) if x["name"] == name), None)
    stale = bool(installed and usage and any(u["version"] != installed for u in usage[-1:]))
    return {"name": name, "unit": unit, "events": events, "usage": usage, "installed": installed,
            "in_use": in_use, "update_to": target, "restart_needed": stale,
            "history_received": bool(conn.execute("SELECT 1 FROM pkg_transactions WHERE host_id = %s LIMIT 1", (host_id,)).fetchone())}


def _act_title(acts: set[str]) -> str:
    if acts & {"Upgrade", "Upgraded"}:
        return "업그레이드 설치"
    if acts & {"Downgrade", "Downgraded"}:
        return "다운그레이드"
    if acts & {"Removed", "Erase"}:
        return "제거"
    if "Reinstall" in acts or "Reinstalled" in acts:
        return "재설치"
    if "Install" in acts:
        return "설치"
    return "거래: " + ", ".join(sorted(acts))

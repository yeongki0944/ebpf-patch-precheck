"""RPM 정적 의존 그래프 (인벤토리의 Requires/Provides 기준).

- 요구(capability) 이름이 설치 패키지의 Provides(또는 패키지 이름)와 같으면 그 패키지에 의존한다고 본다.
- 버전 조건(>=, = 등)은 표시만 하고 판정하지 않는다. 설치된 패키지 집합 안에서만 해석한다.
- rpmlib(...) 은 제외. 조건부 의존 "(a if b)" 와 해석되지 않는 요구는 unresolved 로 남긴다.
- 정적 의존은 "설치에 필요한 관계"이며, 실제로 로딩·실행되었다는 뜻이 아니다.
"""
import threading
from collections import deque

_cache: dict[tuple[str, str], dict] = {}
_lock = threading.Lock()
_MAX_CACHE = 16


def graph(conn, host_id: str, inv_id: str) -> dict:
    key = (host_id, inv_id)
    with _lock:
        g = _cache.get(key)
    if g is not None:
        return g
    rows = conn.execute(
        "SELECT name, nevra, requires, provides FROM inventory_packages WHERE host_id = %s AND inventory_id = %s",
        key).fetchall()
    prov: dict[str, set[str]] = {}
    for r in rows:
        prov.setdefault(r["name"], set()).add(r["name"])
        for p in r["provides"] or []:
            prov.setdefault(p.split(" ", 1)[0], set()).add(r["name"])
    pkgs: dict[str, dict] = {}
    for r in rows:
        node = pkgs.setdefault(r["name"], {"nevras": [], "deps": {}, "unresolved": []})
        node["nevras"].append(r["nevra"])
        for req in r["requires"] or []:
            cap = req.split(" ", 1)[0]
            if cap.startswith("rpmlib(") or not cap:
                continue
            if cap.startswith("("):
                node["unresolved"].append(req)  # 조건부(rich) 의존
                continue
            providers = prov.get(cap)
            if not providers:
                node["unresolved"].append(req)
                continue
            for pn in providers:
                if pn != r["name"]:
                    node["deps"].setdefault(pn, set()).add(req)
    g = {"pkgs": pkgs, "inventory_id": inv_id}
    with _lock:
        if len(_cache) >= _MAX_CACHE:
            _cache.pop(next(iter(_cache)))
        _cache[key] = g
    return g


def children(g: dict, name: str) -> list[str]:
    n = g["pkgs"].get(name)
    return sorted(n["deps"]) if n else []


def closure(g: dict, start: set[str]) -> dict[str, list[str]]:
    """start 에서 정적 의존으로만 도달하는 패키지 → 처음 도달한 경로(부모 사슬)."""
    seen = set(start)
    parent: dict[str, str] = {}
    q = deque(start)
    while q:
        cur = q.popleft()
        for d in children(g, cur):
            if d not in seen:
                seen.add(d)
                parent[d] = cur
                q.append(d)
    out = {}
    for n in parent:
        chain, x = [], n
        while x in parent:
            x = parent[x]
            chain.append(x)
        out[n] = list(reversed(chain))
    return out

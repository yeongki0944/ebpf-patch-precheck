# -*- coding: utf-8 -*-
# 실행은 patchscope-plan-export 래퍼로 (dnf 모듈이 있는 인터프리터 선택)
"""PatchScope plan-export: DNF resolver 로 패치 거래를 해결해 JSON 으로 내보낸다.

거래 실행·RPM 설치·서비스 재시작은 하지 않는다 (resolve 만).
저장소 메타데이터는 별도 cachedir 를 사용해 시스템 dnf 캐시를 바꾸지 않는다.

  patchscope-plan-export [--releasever latest] [--kernel] [pkg ...] -o plan.json
    pkg 미지정: 전체 upgrade 계산
    --kernel  : plan_type=kernel (커널 installonly 거래 + 모듈 정보)

AL2023 / RHEL 8 의 dnf 4 Python API 사용 (platform-python).
"""
import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile

import dnf
import dnf.exceptions
import hawkey

SCHEMA_VERSION = "1"
NEVRA_FMT = "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}"


def nevra(p):
    return "%s-%d:%s-%s.%s" % (p.name, p.epoch or 0, p.version, p.release, p.arch)


def inventory_id():
    """에이전트 rpminv.CurrentID 와 동일 계산: 정렬된 NEVRA 목록 sha256 앞 8바이트(hex 16자)."""
    out = subprocess.check_output(["rpm", "-qa", "--qf", NEVRA_FMT + r"\n"]).decode()
    lines = sorted(out.split())
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]


def machine_id():
    with open("/etc/machine-id") as f:
        return f.read().strip()


def kernel_info():
    info = {"running": os.uname().release}
    mods = []
    try:
        with open("/proc/modules") as f:
            for line in f:
                name = line.split()[0]
                path = None
                try:
                    path = subprocess.check_output(["modinfo", "-n", name], stderr=subprocess.DEVNULL).decode().strip()
                except Exception:
                    pass
                pkg = None
                if path and path.startswith("/"):
                    try:
                        pkg = subprocess.check_output(["rpm", "-qf", "--qf", NEVRA_FMT, path],
                                                      stderr=subprocess.DEVNULL).decode().strip()
                    except subprocess.CalledProcessError:
                        pkg = None
                mods.append({"name": name, "path": path, "package": pkg})
    except OSError:
        pass
    info["loaded_modules"] = mods
    info["external_modules"] = [m["name"] for m in mods if m["path"] and not m["package"]]
    info["dkms"] = os.path.exists("/usr/sbin/dkms") or os.path.exists("/var/lib/dkms")
    try:
        info["default_boot"] = subprocess.check_output(["grubby", "--default-kernel"], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        pass
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packages", nargs="*")
    ap.add_argument("--releasever", help="AL2023 목표 releasever (예: latest, 2023.12.20261021)")
    ap.add_argument("--kernel", action="store_true", help="kernel plan")
    ap.add_argument("--list-updates", action="store_true", help="업데이트 가능 목록만 출력")
    ap.add_argument("-o", "--output", default="-")
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("root required (rpmdb read + repo metadata)")
    inv_before = inventory_id()

    base = dnf.Base()
    conf = base.conf
    conf.read()
    conf.substitutions.update_from_etc(conf.installroot)
    # RHUI 등은 dnf 플러그인이 $REGION 같은 변수를 채우므로 CLI 와 같이 플러그인을 로드
    base.init_plugins()
    base.pre_configure_plugins()
    if a.releasever:
        conf.releasever = a.releasever
        conf.substitutions["releasever"] = a.releasever
    # 시스템 캐시와 분리. 거래는 실행하지 않음
    work = tempfile.mkdtemp(prefix="patchscope-plan-")
    conf.cachedir = work
    conf.assumeyes = False
    base.read_all_repos()
    base.configure_plugins()
    base.fill_sack(load_system_repo=True, load_available_repos=True)

    if a.list_updates:
        # 업데이트 가능 목록 (UI 선택용). 거래 계산 없음
        q = base.sack.query()
        inst = {(p.name, p.arch): p for p in q.installed()}
        ups = []
        for p in q.upgrades().latest():
            old = inst.get((p.name, p.arch))
            ups.append({"name": p.name, "arch": p.arch, "from_nevra": nevra(old) if old else None,
                        "to_nevra": nevra(p), "repo": p.reponame,
                        "kernel": p.name in base.conf.installonlypkgs or p.name.startswith("kernel")})
        out = {"schema_version": SCHEMA_VERSION, "host_id": machine_id(), "inventory_id": inv_before,
               "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
               "releasever": conf.releasever, "updates": sorted(ups, key=lambda u: u["name"])}
        s = json.dumps(out, ensure_ascii=False)
        if a.output == "-":
            print(s)
        else:
            open(a.output, "w").write(s + "\n")
        base.close()
        subprocess.call(["rm", "-rf", work])
        return

    if a.kernel:
        targets = a.packages or ["kernel"]
        for t in targets:
            base.upgrade(t) if base.sack.query().installed().filter(name=t) else base.install(t)
    elif a.packages:
        for p in a.packages:
            try:
                base.upgrade(p)
            except dnf.exceptions.MarkingError as e:
                sys.exit("cannot upgrade %s: %s" % (p, e))
            except dnf.exceptions.PackagesNotInstalledError:
                sys.exit("%s is not installed" % p)
    else:
        base.upgrade_all()

    completeness = "complete"
    try:
        base.resolve(allow_erasing=False)
    except dnf.exceptions.DepsolveError as e:
        sys.exit("depsolve failed: %s" % e)

    items = []
    for tsi in base.transaction:
        action = {
            dnf.transaction.PKG_UPGRADE: "upgrade",
            dnf.transaction.PKG_INSTALL: "install",
            dnf.transaction.PKG_DOWNGRADE: "downgrade",
            dnf.transaction.PKG_REINSTALL: "reinstall",
            dnf.transaction.PKG_REMOVE: "remove",
            dnf.transaction.PKG_OBSOLETE: "obsolete",
        }.get(tsi.action)
        if action is None:
            continue  # UPGRADED/OBSOLETED/DOWNGRADED 등 쌍의 반대편은 아래에서 from 으로 처리
        pkg = tsi.pkg
        item = {"action": action, "name": pkg.name, "arch": pkg.arch, "to_nevra": nevra(pkg),
                "repo": pkg.reponame}
        if action in ("upgrade", "downgrade", "obsolete"):
            old = [nevra(o) for o in getattr(tsi, "replaces", []) or []]
            if not old:
                inst = base.sack.query().installed().filter(name=pkg.name, arch=pkg.arch).run()
                old = [nevra(o) for o in inst]
            item["from_nevra"] = old[0] if old else None
            if len(old) > 1:
                item["also_replaces"] = old[1:]
        if action == "remove":
            item = {"action": "remove", "name": pkg.name, "arch": pkg.arch, "from_nevra": nevra(pkg)}
        items.append(item)

    repos = []
    for r in base.repos.iter_enabled():
        md = getattr(r, "_repo", None)
        repos.append({
            "id": r.id,
            "revision": getattr(md, "getRevision", lambda: None)() if md else None,
            "timestamp": getattr(md, "getTimestamp", lambda: None)() if md else None,
        })

    if inventory_id() != inv_before:
        completeness = "inventory_changed_during_export"

    plan = {
        "schema_version": SCHEMA_VERSION,
        "tool": "patchscope-plan-export/1",
        "host_id": machine_id(),
        "inventory_id": inv_before,
        "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "plan_type": "kernel" if a.kernel else "packages",
        "releasever": conf.releasever,
        "requested": a.packages or (["kernel"] if a.kernel else ["<upgrade-all>"]),
        "repositories": repos,
        "dnf_version": dnf.const.VERSION,
        "completeness": completeness,
        "items": sorted(items, key=lambda i: (i["action"], i["name"])),
    }
    if a.kernel:
        plan["kernel"] = kernel_info()

    out = json.dumps(plan, indent=2, ensure_ascii=False)
    if a.output == "-":
        print(out)
    else:
        with open(a.output, "w") as f:
            f.write(out + "\n")
        sys.stderr.write("wrote %s: %d items, inventory %s, releasever %s\n"
                         % (a.output, len(items), inv_before, conf.releasever))
    base.close()
    subprocess.call(["rm", "-rf", work])


if __name__ == "__main__":
    main()

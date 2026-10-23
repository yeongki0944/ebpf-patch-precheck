#!/bin/bash
SP=/var/lib/patchscope/smoke-spool
tail -8 /tmp/agent-smoke.log
ls "$SP" | head
PY=$(command -v python3 || echo /usr/libexec/platform-python)
$PY - "$SP" <<'PY'
import json, glob, sys, collections
for f in sorted(glob.glob(sys.argv[1] + "/*.json"))[:3]:
    d = json.load(open(f))
    print(f.split("/")[-1], list(d.keys())[:8], type(d.get("records")))
recs = []
for f in glob.glob(sys.argv[1] + "/*batch*.json"):
    recs += json.load(open(f)).get("records") or []
print("agent-ish:", collections.Counter((r.get("comm"), r.get("unit"), r["kind"]) for r in recs if r.get("comm") in ("patchscope-agen","rpm")).most_common(5))
PY

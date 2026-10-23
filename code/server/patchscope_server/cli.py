"""서버 관리 CLI (analysis 호스트에서 root 로 실행).

  python -m patchscope_server.cli init
  python -m patchscope_server.cli register-agent <agent_id> <token_sha256>   # 토큰 원문은 서버로 오지 않음
  python -m patchscope_server.cli rotate-agent   <agent_id> <token_sha256>
  python -m patchscope_server.cli revoke-agent   <agent_id>
  python -m patchscope_server.cli list-agents
  python -m patchscope_server.cli set-admin-password        # stdin 으로 입력
"""
import re
import sys

from . import auth, db

HEX64 = re.compile(r"^[0-9a-f]{64}$")
AGENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "init":
        db.init_schema()
        print("schema ok")
    elif cmd in ("register-agent", "rotate-agent"):
        agent, th = args
        if not AGENT.match(agent) or not HEX64.match(th):
            print("invalid agent id or sha256", file=sys.stderr)
            return 2
        with db.connect() as conn:
            if cmd == "register-agent":
                conn.execute(
                    """INSERT INTO agents (agent_id, token_sha256) VALUES (%s, %s)
                       ON CONFLICT (agent_id) DO UPDATE SET token_sha256 = EXCLUDED.token_sha256,
                         rotated_at = now(), revoked_at = NULL""", (agent, th))
            else:
                n = conn.execute("UPDATE agents SET token_sha256 = %s, rotated_at = now(), revoked_at = NULL WHERE agent_id = %s",
                                 (th, agent)).rowcount
                if not n:
                    print("no such agent", file=sys.stderr)
                    return 1
        print(f"{cmd}: {agent} ok")
    elif cmd == "revoke-agent":
        with db.connect() as conn:
            n = conn.execute("UPDATE agents SET revoked_at = now() WHERE agent_id = %s", (args[0],)).rowcount
        print("revoked" if n else "no such agent")
    elif cmd == "list-agents":
        with db.connect() as conn:
            for r in conn.execute("SELECT agent_id, created_at, rotated_at, revoked_at, last_seen FROM agents ORDER BY agent_id"):
                print(r["agent_id"], "revoked" if r["revoked_at"] else "active", "last_seen=", r["last_seen"])
    elif cmd == "set-admin-password":
        pw = sys.stdin.readline().rstrip("\n")
        if len(pw) < 12:
            print("password must be >= 12 chars", file=sys.stderr)
            return 2
        print(auth.hash_password(pw))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

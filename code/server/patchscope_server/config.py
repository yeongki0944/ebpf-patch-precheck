import os

# PostgreSQL: 로컬 unix socket + peer 인증 (DB 비밀번호 없음)
DSN = os.environ.get("PATCHSCOPE_DSN", "dbname=patchscope")
SESSION_KEY_FILE = os.environ.get("PATCHSCOPE_SESSION_KEY", "/etc/patchscope-server/session.key")
ADMIN_HASH_FILE = os.environ.get("PATCHSCOPE_ADMIN_HASH", "/etc/patchscope-server/admin.hash")
RAW_RETENTION_DAYS = int(os.environ.get("PATCHSCOPE_RAW_RETENTION_DAYS", "7"))
SUMMARY_RETENTION_DAYS = int(os.environ.get("PATCHSCOPE_SUMMARY_RETENTION_DAYS", "30"))
SESSION_TTL_SECONDS = 8 * 3600

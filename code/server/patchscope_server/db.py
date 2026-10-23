from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from . import config


@contextmanager
def connect():
    """요청당 연결 (PoC 규모). with 블록이 정상 종료되면 commit, 예외면 rollback."""
    with psycopg.connect(config.DSN, row_factory=dict_row) as conn:
        yield conn


def init_schema() -> None:
    sql = (Path(__file__).parent / "schema.sql").read_text()
    with connect() as conn:
        conn.execute(sql)


def apply_retention() -> dict:
    """원시 이벤트 RAW_RETENTION_DAYS, 배치·세션·보고서 SUMMARY_RETENTION_DAYS."""
    with connect() as conn:
        r = conn.execute(
            "DELETE FROM records WHERE ts_utc < now() - make_interval(days => %s)",
            (config.RAW_RETENTION_DAYS,),
        ).rowcount
        s = conn.execute(
            "DELETE FROM sessions WHERE last_created_at < now() - make_interval(days => %s)",
            (config.SUMMARY_RETENTION_DAYS,),
        ).rowcount
        c = conn.execute(
            "DELETE FROM capability_reports WHERE received_at < now() - make_interval(days => %s)",
            (config.SUMMARY_RETENTION_DAYS,),
        ).rowcount
    return {"records": r, "sessions": s, "capability_reports": c}

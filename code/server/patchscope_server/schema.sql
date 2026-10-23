-- PatchScope 분석 서버 스키마 (멱등)
-- 모든 증거(records)는 session·host·inventory 와 연결된다.

CREATE TABLE IF NOT EXISTS agents (
    agent_id      text PRIMARY KEY,
    token_sha256  text NOT NULL UNIQUE,   -- 토큰 원문은 저장하지 않음
    created_at    timestamptz NOT NULL DEFAULT now(),
    rotated_at    timestamptz,
    revoked_at    timestamptz,
    last_seen     timestamptz
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id             text PRIMARY KEY,  -- /etc/machine-id
    agent_id            text NOT NULL REFERENCES agents(agent_id),
    hostname            text,
    os_id               text,
    os_version          text,
    kernel              text,
    boot_id             text,
    capability_status   text,
    service_criticality text,              -- 사용자 입력 (후속)
    first_seen          timestamptz NOT NULL DEFAULT now(),
    last_seen           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS capability_reports (
    id            bigserial PRIMARY KEY,
    agent_id      text NOT NULL,
    host_id       text NOT NULL,
    boot_id       text,
    kernel        text,
    session_id    text,
    status        text NOT NULL,
    agent_version text,
    report        jsonb NOT NULL,
    received_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS capability_reports_host ON capability_reports (host_id, received_at DESC);

CREATE TABLE IF NOT EXISTS inventories (
    host_id       text NOT NULL,
    inventory_id  text NOT NULL,
    captured_at   timestamptz,
    package_count int NOT NULL,
    received_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, inventory_id)
);

CREATE TABLE IF NOT EXISTS inventory_packages (
    host_id      text NOT NULL,
    inventory_id text NOT NULL,
    nevra        text NOT NULL,
    name         text NOT NULL,
    epoch        text,
    version      text,
    release      text,
    arch         text,
    requires     text[],
    provides     text[],
    PRIMARY KEY (host_id, inventory_id, nevra),
    FOREIGN KEY (host_id, inventory_id) REFERENCES inventories ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS inventory_packages_name ON inventory_packages (host_id, inventory_id, name);

CREATE TABLE IF NOT EXISTS sessions (
    session_id         text PRIMARY KEY,
    agent_id           text NOT NULL,
    host_id            text NOT NULL,
    boot_id            text,
    kernel             text,
    agent_version      text,
    first_window_start timestamptz,
    last_created_at    timestamptz,
    max_seq            bigint NOT NULL DEFAULT 0,
    batch_count        bigint NOT NULL DEFAULT 0,
    incomplete_batches bigint NOT NULL DEFAULT 0,
    dropped_batch_ids  text[] NOT NULL DEFAULT '{}',
    inventory_ids      text[] NOT NULL DEFAULT '{}',
    total              jsonb,
    policy             jsonb,
    ended              boolean NOT NULL DEFAULT false,
    end_reason         text
);
CREATE INDEX IF NOT EXISTS sessions_host ON sessions (host_id, last_created_at DESC);

CREATE TABLE IF NOT EXISTS batches (
    batch_id          text PRIMARY KEY,   -- agent 재전송 중복 제거 키
    session_id        text NOT NULL REFERENCES sessions ON DELETE CASCADE,
    seq               bigint NOT NULL,
    agent_id          text NOT NULL,
    host_id           text NOT NULL,
    inventory_id      text,
    window_start      timestamptz,
    created_at        timestamptz,
    received_at       timestamptz NOT NULL DEFAULT now(),
    reason            text,
    complete          boolean NOT NULL,
    record_count      int NOT NULL,
    delta             jsonb,
    dropped_batch_ids text[]
);
CREATE INDEX IF NOT EXISTS batches_session ON batches (session_id, seq);

CREATE TABLE IF NOT EXISTS records (
    id             bigserial PRIMARY KEY,
    batch_id       text NOT NULL REFERENCES batches ON DELETE CASCADE,
    session_id     text NOT NULL,
    host_id        text NOT NULL,
    inventory_id   text,
    kind           text NOT NULL,
    source         text NOT NULL,
    ts_mono_ns     bigint,
    ts_utc         timestamptz NOT NULL,
    last_ts_utc    timestamptz,
    count          bigint NOT NULL DEFAULT 1,
    proc_key       text,
    pid            bigint,
    start_ticks    bigint,
    tid            bigint,
    ppid           bigint,
    parent_key     text,
    comm           text,
    uid            bigint,
    unit           text,
    unit_source    text,
    path           text,
    requested_path text,
    path_status    text,
    dev            text,
    ino            bigint,
    deleted        boolean,
    ownership      text,
    packages       text[],
    file_note      text,
    ok             boolean,
    errno          int,
    flags          bigint,
    prot           bigint,
    perms          text,
    exit_code      int,
    signal         int,
    note           text
);
CREATE INDEX IF NOT EXISTS records_session ON records (session_id, proc_key);
CREATE INDEX IF NOT EXISTS records_host_ts ON records (host_id, ts_utc);
CREATE INDEX IF NOT EXISTS records_packages ON records USING gin (packages);
CREATE INDEX IF NOT EXISTS records_batch ON records (batch_id);

CREATE TABLE IF NOT EXISTS patch_plans (
    id           bigserial PRIMARY KEY,
    host_id      text NOT NULL,
    inventory_id text NOT NULL,
    plan_type    text NOT NULL,
    label        text,
    plan         jsonb NOT NULL,
    validation   jsonb NOT NULL,
    uploaded_by  text,
    uploaded_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id          bigserial PRIMARY KEY,
    plan_id     bigint NOT NULL REFERENCES patch_plans ON DELETE CASCADE,
    result      jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Alert store. Mirrors common/schema.py:Alert. Kept intentionally simple; the
-- structured signals live in the JSONB `evidence` column for explainability.
CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL,          -- when the alert fired
    flow_id      TEXT        NOT NULL,          -- source flow identifier
    threat_class TEXT        NOT NULL,          -- flood|beaconing|dga_dns|tls_malware|portscan|exfil
    confidence   DOUBLE PRECISION NOT NULL,     -- 0.0 - 1.0
    severity     TEXT        NOT NULL,          -- low|medium|high|critical
    src_ip       TEXT,
    src_port     INTEGER,
    dst_ip       TEXT,
    dst_port     INTEGER,
    evidence     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts           ON alerts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts (threat_class);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts (severity);

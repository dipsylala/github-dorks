-- GitHub Vulnerability Hunting Pipeline — SQLite schema
-- Applied automatically on first run via DatabasePool.run_script()

-- ------------------------------------------------------------------ --
-- Core tables
-- ------------------------------------------------------------------ --

CREATE TABLE IF NOT EXISTS repositories (
    id            TEXT     PRIMARY KEY,
    name          TEXT     NOT NULL,
    url           TEXT     NOT NULL UNIQUE,
    stars         INTEGER  NOT NULL DEFAULT 0,
    language      TEXT     NOT NULL,
    last_push     TEXT     NOT NULL,   -- ISO-8601 string
    size_mb       INTEGER  NOT NULL DEFAULT 0,
    archived      INTEGER  NOT NULL DEFAULT 0,  -- 0=false, 1=true
    framework     TEXT,
    score         INTEGER  NOT NULL DEFAULT 0,
    filtered           INTEGER  NOT NULL DEFAULT 0,  -- 0=not yet filtered, 1=passed filter
    scored             INTEGER  NOT NULL DEFAULT 0,  -- 0=not yet scored, 1=scorer has run
    framework_detected INTEGER  NOT NULL DEFAULT 0,  -- 0=not yet detected, 1=detector has run
    created_at         TEXT     NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS local_repositories (
    repository_id   TEXT     PRIMARY KEY
                             REFERENCES repositories(id) ON DELETE CASCADE,
    local_path      TEXT     NOT NULL,
    clone_timestamp TEXT     NOT NULL,   -- ISO-8601 string
    scanned         INTEGER  NOT NULL DEFAULT 0  -- 0=not yet scanned, 1=scanner has run
);

CREATE TABLE IF NOT EXISTS patterns (
    id                 TEXT     PRIMARY KEY,
    name               TEXT     NOT NULL,
    regex              TEXT     NOT NULL,
    vulnerability_type TEXT     NOT NULL,
    severity_score     INTEGER  NOT NULL DEFAULT 0,
    language           TEXT     NOT NULL DEFAULT '',
    cwe                TEXT     NOT NULL DEFAULT '',  -- e.g. "CWE-78"
    cwe_name           TEXT     NOT NULL DEFAULT ''   -- e.g. "OS Command Injection"
);

CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT     PRIMARY KEY,
    repository_id       TEXT     NOT NULL
                                 REFERENCES repositories(id) ON DELETE CASCADE,
    file_path           TEXT     NOT NULL,
    line_number         INTEGER  NOT NULL,
    pattern_id          TEXT     NOT NULL REFERENCES patterns(id),
    vulnerability_type  TEXT     NOT NULL,
    snippet             TEXT     NOT NULL DEFAULT '',
    matched_pattern_ids TEXT     NOT NULL DEFAULT '[]',  -- JSON array of all pattern IDs at this location
    score               INTEGER  NOT NULL DEFAULT 0,
    enriched            INTEGER  NOT NULL DEFAULT 0,  -- 0=not yet enriched, 1=enricher has run
    finding_scored      INTEGER  NOT NULL DEFAULT 0,  -- 0=not yet scored, 1=result-scorer has run
    created_at          TEXT     NOT NULL DEFAULT (datetime('now'))
);

-- ------------------------------------------------------------------ --
-- Indexes
-- ------------------------------------------------------------------ --

CREATE INDEX IF NOT EXISTS idx_findings_repository_id ON findings (repository_id);
CREATE INDEX IF NOT EXISTS idx_findings_score         ON findings (score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_pattern_id    ON findings (pattern_id);
CREATE INDEX IF NOT EXISTS idx_findings_unenriched     ON findings (id) WHERE enriched = 0;
CREATE INDEX IF NOT EXISTS idx_findings_unscored       ON findings (id) WHERE finding_scored = 0;
CREATE INDEX IF NOT EXISTS idx_repositories_score      ON repositories (score DESC);
CREATE INDEX IF NOT EXISTS idx_repositories_language   ON repositories (language);
CREATE INDEX IF NOT EXISTS idx_repositories_unfiltered ON repositories (id) WHERE filtered = 0;
CREATE INDEX IF NOT EXISTS idx_repositories_unscored   ON repositories (id) WHERE filtered = 1 AND scored = 0;
CREATE INDEX IF NOT EXISTS idx_repositories_undetected ON repositories (id) WHERE filtered = 1 AND framework_detected = 0;
CREATE INDEX IF NOT EXISTS idx_local_repos_unscanned   ON local_repositories (repository_id) WHERE scanned = 0;

-- ------------------------------------------------------------------ --
-- Convenience view — review queue
-- ------------------------------------------------------------------ --

DROP VIEW IF EXISTS review_queue;
CREATE VIEW review_queue AS
SELECT
    f.id                          AS finding_id,
    f.repository_id               AS repository_id,
    f.pattern_id                  AS pattern_id,
    r.name                        AS repository_name,
    r.url                         AS repository_url,
    r.framework,
    f.file_path,
    f.line_number,
    f.vulnerability_type,
    f.snippet,
    f.matched_pattern_ids,
    f.score                       AS finding_score,
    r.score                       AS repo_score,
    f.score + r.score             AS combined_score
FROM findings f
JOIN repositories r ON r.id = f.repository_id
ORDER BY combined_score DESC;

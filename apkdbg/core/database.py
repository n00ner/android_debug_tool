"""SQLite mapping database — the heart of the tool.

The dalvik/ART line number is the PIVOT of every mapping:

  jadx java line  ──(jadx_lines, when jadx emits a mapping json)──▶
  dalvik line     ══ .line N directives in apktool smali (identity) ══
  runtime LineNumberTable (JDWP Method.LineTable: line ↔ bytecode index)

Because the input APK is debuggable and not recompiled, the LineNumberTable
inside the DEX is untouched, so smali `.line` values == DEX line numbers ==
java source lines for unobfuscated code. For obfuscated code the runtime
table is still authoritative; we just lose source filenames.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# Static-index format/provenance version, recorded as meta.index_version
# (issue #35). Databases without the key are version 1: pre-#35 builds with
# non-transactional in-place re-indexing. Opening a DB with a NEWER version
# than this constant is an error; older versions are rebuilt by `init`.
INDEX_VERSION = 2

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS classes (
  id          INTEGER PRIMARY KEY,
  sig         TEXT NOT NULL UNIQUE,   -- runtime descriptor: Lcom/foo/Bar;
  fqcn        TEXT NOT NULL,          -- com.foo.Bar (as in smali; obfuscated if APK is)
  deobf_fqcn  TEXT,                   -- jadx-deobfuscated name, when available
  smali_path  TEXT,                   -- relative to apktool out dir
  source_file TEXT                    -- .source attribute, when present
);

CREATE TABLE IF NOT EXISTS methods (
  id         INTEGER PRIMARY KEY,
  class_id   INTEGER NOT NULL REFERENCES classes(id),
  name       TEXT NOT NULL,           -- runtime (possibly obfuscated) name
  sig        TEXT NOT NULL,           -- (I[Ljava/lang/String;)V
  flags      TEXT,
  is_native  INTEGER DEFAULT 0,
  line_start INTEGER,                 -- file line of .method directive
  line_end   INTEGER,                 -- file line of .end method
  UNIQUE(class_id, name, sig)
);
CREATE INDEX IF NOT EXISTS idx_methods_class ON methods(class_id);

CREATE TABLE IF NOT EXISTS line_map (
  method_id   INTEGER NOT NULL REFERENCES methods(id),
  dalvik_line INTEGER NOT NULL,       -- value of .line N  == DEX LineNumberTable line
  smali_line  INTEGER NOT NULL,       -- file line of first insn after the directive
  PRIMARY KEY (method_id, dalvik_line, smali_line)
);
CREATE INDEX IF NOT EXISTS idx_linemap_dl ON line_map(method_id, dalvik_line);

-- jadx java-source line -> dalvik line, when a mapping json is available
CREATE TABLE IF NOT EXISTS jadx_lines (
  class_id    INTEGER NOT NULL REFERENCES classes(id),
  java_line   INTEGER NOT NULL,
  dalvik_line INTEGER NOT NULL,
  PRIMARY KEY (class_id, java_line)
);

CREATE TABLE IF NOT EXISTS branch_sites (
  id                 INTEGER PRIMARY KEY,
  method_id          INTEGER NOT NULL REFERENCES methods(id),
  smali_line         INTEGER NOT NULL,   -- file line of the if-*/goto/switch insn
  dalvik_line        INTEGER,            -- its dalvik line (what JDWP reports)
  opcode             TEXT NOT NULL,
  kind               TEXT NOT NULL,      -- if | goto | switch
  target_smali_line  INTEGER,            -- resolved label target (if/goto)
  target_dalvik_line INTEGER
);
CREATE INDEX IF NOT EXISTS idx_branch ON branch_sites(method_id, dalvik_line);

CREATE TABLE IF NOT EXISTS resources (
  res_id INTEGER PRIMARY KEY,         -- 0x7f0f0001 as integer
  type   TEXT,
  name   TEXT,
  value  TEXT
);
CREATE INDEX IF NOT EXISTS idx_res_name ON resources(name);

-- call sites that load a resource const and (usually) pass it to a getter
CREATE TABLE IF NOT EXISTS resource_refs (
  id          INTEGER PRIMARY KEY,
  res_id      INTEGER NOT NULL,
  method_id   INTEGER NOT NULL REFERENCES methods(id),
  smali_line  INTEGER,
  dalvik_line INTEGER,
  kind        TEXT NOT NULL           -- getString | getDrawable | ... | const_load
);
CREATE INDEX IF NOT EXISTS idx_resref_res ON resource_refs(res_id);

CREATE TABLE IF NOT EXISTS coverage_hits (
  id          INTEGER PRIMARY KEY,
  run_id      TEXT NOT NULL,
  class_sig   TEXT,
  method_name TEXT,
  dalvik_line INTEGER,
  hits        INTEGER DEFAULT 0,
  UNIQUE(run_id, class_sig, method_name, dalvik_line)
);

-- investigation run manifests (issue #36): durable identity for runtime
-- observations, stored independently of the replaceable static index
-- (init rebuilds the derived tables above in a staged generation and
-- carries these rows across unchanged; they are additive)
CREATE TABLE IF NOT EXISTS runs (
  run_id            TEXT PRIMARY KEY,   -- durable id (uuid), stable across export/import
  manifest_version  INTEGER NOT NULL,
  kind              TEXT NOT NULL,      -- coverage | snapshot | crypto_watch | ...
  scenario          TEXT,               -- free-form scenario label
  apk_sha256        TEXT,
  index_generation  INTEGER NOT NULL,   -- static-index generation at capture time
  tool_version      TEXT,
  capture_config    TEXT,               -- JSON: mode/packages/budgets/hooks/scope
  environment       TEXT,               -- JSON: device, android api, vm name/version
  epoch             INTEGER,            -- connection epoch of the capturing session
  started_at        TEXT,
  ended_at          TEXT,
  completion_reason TEXT,               -- completed | duration | budget | max_events | ...
  counts            TEXT                -- JSON counters (events, hits, errors)
);

CREATE TABLE IF NOT EXISTS events (
  event_id         TEXT PRIMARY KEY,
  run_id           TEXT NOT NULL REFERENCES runs(run_id),
  index_generation INTEGER NOT NULL,    -- copied from the run at capture time
  epoch            INTEGER,             -- connection epoch of the capturing session
  kind             TEXT NOT NULL,       -- crypto_record | ...
  class_sig        TEXT,                -- original runtime descriptor (identity)
  method_name      TEXT,                -- original (possibly obfuscated) name
  method_sig       TEXT,
  dalvik_line      INTEGER,
  bytecode_index   INTEGER,
  payload          TEXT NOT NULL        -- JSON record body (deobf names are
                                        -- annotations inside, never identity)
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id      TEXT PRIMARY KEY,
  run_id           TEXT NOT NULL REFERENCES runs(run_id),
  parent_event_id  TEXT,                -- optional parent event
  kind             TEXT NOT NULL,       -- snapshot | coverage_report | export | ...
  format           TEXT NOT NULL,       -- json | ...
  index_generation INTEGER NOT NULL,
  epoch            INTEGER,
  budgets          TEXT,                -- JSON capture budgets
  truncation       TEXT,                -- JSON: trunc/budget/error summary
  errors           TEXT,                -- JSON list
  checksum         TEXT,                -- sha256 of body
  body             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);
"""


class MappingDB:
    """SQLite handle over the mapping schema.

    Context-manager protocol is transaction-safe (issue #35): exiting the
    `with` block commits only when no exception occurred; on exception the
    pending transaction is rolled back, so a failed parser/insertion never
    persists a partially rebuilt index.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        fresh = not self.path.exists()
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        if fresh:
            # stamp new databases with the current index format version;
            # pre-existing DBs keep whatever provenance they were built with
            self.conn.execute(
                "INSERT OR IGNORE INTO meta(key,value)"
                " VALUES('index_version',?)", (str(INDEX_VERSION),))
            self.conn.commit()

    def execute(self, sql: str, params=()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows) -> None:
        self.conn.executemany(sql, rows)

    def query(self, sql: str, params=()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, params)]

    def one(self, sql: str, params=()) -> dict | None:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                     (key, value))

    def get_meta(self, key: str) -> str | None:
        r = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return r["value"] if r else None

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def close(self) -> None:
        """Commit pending changes and close. Prefer the context manager:
        `__exit__` rolls back instead of committing on exception."""
        self.conn.commit()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()

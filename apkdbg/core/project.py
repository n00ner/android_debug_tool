"""Project layout.

<project>/
  project.json      state: apk path, package, created, tool versions
  mapping.db        SQLite mapping database (see database.py)
  apktool/          apktool d output (smali*, res, AndroidManifest.xml)
  jadx/             jadx -d output (sources + optional mapping json)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ..errors import MappingError
from .database import MappingDB

STATE_FILE = "project.json"


class Project:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()

    # paths ------------------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return self.root / STATE_FILE

    @property
    def db_path(self) -> Path:
        return self.root / "mapping.db"

    @property
    def apktool_dir(self) -> Path:
        return self.root / "apktool"

    @property
    def jadx_dir(self) -> Path:
        return self.root / "jadx"

    @property
    def manifest_path(self) -> Path:
        return self.apktool_dir / "AndroidManifest.xml"

    # lifecycle ----------------------------------------------------------------
    @classmethod
    def create(cls, root: str | Path) -> "Project":
        p = cls(root)
        p.root.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def open(cls, root: str | Path) -> "Project":
        p = cls(root)
        if not p.db_path.exists():
            raise MappingError(f"not an initialized apkdbg project: {p.root}",
                               hint="run: apkdbg init --apk app.apk --out <dir>")
        return p

    # state ---------------------------------------------------------------------
    def state(self) -> dict:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text("utf-8"))
        return {}

    def save_state(self, **kw) -> dict:
        st = self.state()
        st.update(kw)
        st["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.state_path.write_text(
            json.dumps(st, indent=1, ensure_ascii=False), "utf-8")
        return st

    def db(self) -> MappingDB:
        return MappingDB(self.db_path)

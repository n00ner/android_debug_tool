"""Project layout.

<project>/
  project.json        state: apk path, package, created, tool versions
  mapping.db          SQLite mapping database (see database.py)
  apktool/            apktool d output (smali*, res, AndroidManifest.xml)
  jadx/               jadx -d output (sources + optional mapping json)

Re-indexing (issue #35) is staged before it is published:

  mapping.staging.db  next-generation database under construction
  apktool.staging/    staging decompiler outputs
  jadx.staging/
  apktool.old/        previous outputs, kept while a publish is in flight
  jadx.old/
  publish.json        publish journal; present only between the first and
                      last swap step of an interrupted publication

The staging artifacts are never the selected index: mapping.db is replaced
in a single atomic os.replace at the end of a successful publish. Anything
left over (crash during staging, or a journal from an interrupted publish)
is resolved by recover_interrupted_publish(), which runs on Project.open
and at the start of every init.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

from ..errors import MappingError
from .database import INDEX_VERSION, MappingDB

STATE_FILE = "project.json"
PUBLISH_JOURNAL = "publish.json"


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

    # staging / publish paths (issue #35) --------------------------------------
    @property
    def staging_db_path(self) -> Path:
        return self.root / "mapping.staging.db"

    @property
    def apktool_staging_dir(self) -> Path:
        return self.root / "apktool.staging"

    @property
    def jadx_staging_dir(self) -> Path:
        return self.root / "jadx.staging"

    @property
    def apktool_old_dir(self) -> Path:
        return self.root / "apktool.old"

    @property
    def jadx_old_dir(self) -> Path:
        return self.root / "jadx.old"

    @property
    def publish_journal_path(self) -> Path:
        return self.root / PUBLISH_JOURNAL

    # lifecycle ----------------------------------------------------------------
    @classmethod
    def create(cls, root: str | Path) -> "Project":
        p = cls(root)
        p.root.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def open(cls, root: str | Path) -> "Project":
        p = cls(root)
        p.recover_interrupted_publish()
        if not p.db_path.exists():
            raise MappingError(f"not an initialized apkdbg project: {p.root}",
                               hint="run: apkdbg init --apk app.apk --out <dir>")
        with p.db() as db:
            version = int(db.get_meta("index_version") or 1)
        if version > INDEX_VERSION:
            raise MappingError(
                f"project index version {version} is newer than this apkdbg "
                f"supports ({INDEX_VERSION})",
                hint="upgrade apkdbg; never rebuild a newer project with an "
                     "older tool")
        return p

    # crash recovery (issue #35) ------------------------------------------------
    def recover_interrupted_publish(self) -> None:
        """Resolve staging/publish leftovers so the on-disk project always
        presents exactly one complete generation.

        - publish journal with db_swapped: the new generation is fully
          selected; only cleanup remained -> finish it.
        - journal with dirs_swapped only: decompiler dirs were swapped but
          the DB was not -> roll the dirs back to the previous generation.
        - journal with neither, or staging artifacts without a journal
          (crash while building): staging is an incomplete index -> discard.
        """
        journal_path = self.publish_journal_path
        journal = None
        if journal_path.exists():
            try:
                journal = json.loads(journal_path.read_text("utf-8"))
            except (OSError, json.JSONDecodeError):
                journal = {}
            if journal.get("db_swapped"):
                self._discard_staging()
                self._remove_dir(self.apktool_old_dir)
                self._remove_dir(self.jadx_old_dir)
            elif journal.get("dirs_swapped"):
                for swap in journal.get("swap", []):
                    live_dir = Path(swap["live"])
                    old_dir = Path(swap["old"])
                    self._remove_dir(live_dir)
                    if old_dir.exists():
                        os.rename(old_dir, live_dir)
                self._discard_staging()
            else:
                self._discard_staging()
            journal_path.unlink(missing_ok=True)
        else:
            self._discard_staging()

    def _discard_staging(self) -> None:
        _remove_db_files(self.staging_db_path)
        self._remove_dir(self.apktool_staging_dir)
        self._remove_dir(self.jadx_staging_dir)

    @staticmethod
    def _remove_dir(path: Path) -> None:
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)

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


def _remove_db_files(path: Path) -> None:
    """Remove a sqlite database plus WAL sidecar files, if present."""
    _remove_sidecars(path)
    Path(path).unlink(missing_ok=True)


def _remove_sidecars(path: Path) -> None:
    """Remove only the WAL sidecar files of a sqlite database."""
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)

"""Init Phase orchestration: decompile -> index -> build mapping DB.

Re-indexing is transactional (issue #35):

  1. Decompiler outputs and the next-generation database are built in
     *staging* (apktool.staging/, jadx.staging/, mapping.staging.db).
  2. The staging database is validated (no orphan derived rows).
  3. Publication swaps staging into place behind a journal; the database
     swap is a single atomic os.replace, so queries always see exactly one
     complete generation — never a mixture of old and new.

Any failure before or during publication leaves the previously published
generation selected and usable; leftovers are resolved by
Project.recover_interrupted_publish() on the next open/init.

Entity IDs are resolved deterministically with upsert ... RETURNING (SQLite
3.35+; bundled CPython 3.11+ ships 3.39+), never via cur.lastrowid after
INSERT OR IGNORE. All APK-derived tables are rebuilt from scratch per
generation, so entities absent from the new APK disappear.

Observation tables (runs/events/artifacts/coverage_hits, issue #36, and
the alias tables of issue #25) are historical runtime data: they are copied
unchanged into each new generation and keep the index_generation they were
captured against.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from ..decompile import mappings, smali_index, tools
from ..errors import DecompileError, MappingError
from ..protocol import log_progress
from . import manifests
from .database import INDEX_VERSION, SCHEMA_VERSION, MappingDB
from .project import Project, _remove_db_files, _remove_sidecars

# historical runtime observations (issue #36) and reviewable alias
# candidates (issue #25): retained across re-indexing, copied into each
# published generation with their original generation ids
OBSERVATION_TABLES = ("runs", "events", "artifacts", "coverage_hits",
                      "alias_candidates", "alias_decisions")


def run_init(apk: str | Path, project_root: str | Path, *,
             skip_apktool: bool = False, skip_jadx: bool = False,
             timeout: int = 1200) -> dict:
    apk = Path(apk).resolve()
    if not apk.exists():
        raise DecompileError(f"APK not found: {apk}")

    proj = Project.create(project_root)
    proj.recover_interrupted_publish()
    t0 = time.time()
    sha = _sha256(apk)
    summary: dict = {"apk": str(apk), "sha256": sha,
                     "project": str(proj.root)}

    # prior generation + provenance gate --------------------------------------
    live = proj.db_path.exists()
    prior_sha = None
    generation = 1
    if live:
        with proj.db() as db:
            prior_sha = db.get_meta("sha256")
            prior_version = int(db.get_meta("index_version") or 1)
            generation = manifests.index_generation(db) + 1
        if prior_version > INDEX_VERSION:
            raise MappingError(
                f"project index version {prior_version} is newer than this "
                f"apkdbg supports ({INDEX_VERSION})",
                hint="upgrade apkdbg; never rebuild a newer project with an "
                     "older tool")
    jadx_reuse = (skip_jadx and prior_sha is not None
                  and _cached_jadx_output(proj))
    _check_reuse_gate(proj, prior_sha, sha, skip_apktool=skip_apktool,
                      jadx_reuse=jadx_reuse)

    try:
        # 1. decompile into staging ------------------------------------------
        decompilers: dict = {}
        if skip_apktool:
            apktool_src = proj.apktool_dir
            decompilers["apktool"] = {"reused": True, "skipped": False,
                                      "version": None}
        else:
            summary["apktool"] = tools.apktool_decode(
                apk, proj.apktool_staging_dir, timeout=timeout)
            apktool_src = proj.apktool_staging_dir
            decompilers["apktool"] = {
                "reused": False, "skipped": False,
                "version": tools.tool_version("apktool",
                                              env_var="APKDBG_APKTOOL")}
        if skip_jadx:
            if jadx_reuse:
                jadx_mapping = mappings.load_jadx_mapping(
                    tools._find_mapping_file(proj.jadx_dir))
                decompilers["jadx"] = {"reused": True, "skipped": False,
                                       "version": None, "flags": None}
            else:
                # jadx is optional enrichment: with no provenanced cached
                # output, --skip-jadx simply means "proceed jadx-free"
                jadx_mapping = mappings.load_jadx_mapping(None)
                decompilers["jadx"] = {"skipped": True, "reused": False,
                                       "version": None, "flags": None}
        else:
            summary["jadx"] = tools.jadx_decompile(
                apk, proj.jadx_staging_dir, timeout=timeout)
            jadx_mapping = mappings.load_jadx_mapping(
                summary["jadx"].get("mapping_file"))
            decompilers["jadx"] = {
                "reused": False, "skipped": False,
                "version": tools.tool_version("jadx", env_var="APKDBG_JADX"),
                "flags": summary["jadx"].get("flags")}

        pkg = mappings.parse_manifest_package(
            apktool_src / "AndroidManifest.xml")
        if pkg:
            summary["package"] = pkg
        debuggable = mappings.parse_manifest_debuggable(
            apktool_src / "AndroidManifest.xml")
        md_str = {True: "true", False: "false", None: "unknown"}[debuggable]
        summary["manifest_debuggable"] = md_str

        # 2. build + validate the staging database ----------------------------
        counts = _build_staging_db(
            proj, apktool_src=apktool_src, jadx_mapping=jadx_mapping,
            live=live, summary=summary)
        lm_state, lm_reason = _line_map_state(counts["classes"],
                                              counts["line_rows"])
        provenance = {
            "apk_sha256": sha,
            "index_version": INDEX_VERSION,
            "generation": generation,
            "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "options": {"skip_apktool": skip_apktool,
                        "skip_jadx": skip_jadx},
            "decompilers": decompilers,
        }
        with MappingDB(proj.staging_db_path) as staging:
            _validate_staging(staging)
            staging.set_meta("apk", str(apk))
            staging.set_meta("sha256", sha)
            if pkg:
                staging.set_meta("package", pkg)
            staging.set_meta("manifest_debuggable", md_str)
            staging.set_meta("schema_version", SCHEMA_VERSION)
            staging.set_meta("index_version", str(INDEX_VERSION))
            staging.set_meta("index_generation", str(generation))
            # an aborted build never publishes, so a published generation is
            # always complete; tolerated per-file failures land in warnings
            staging.set_meta("index_complete", "true")
            staging.set_meta("index_warnings", json.dumps(counts["warnings"]))
            staging.set_meta("line_map_state", lm_state)
            staging.set_meta("line_map_reason", lm_reason)
            staging.set_meta("indexed_at", provenance["indexed_at"])
            staging.set_meta("tools", json.dumps(
                decompilers, separators=(",", ":"), ensure_ascii=False))
            staging.set_meta("provenance", json.dumps(
                provenance, separators=(",", ":"), ensure_ascii=False))
        _remove_sidecars(proj.staging_db_path)  # fold away WAL sidecars

        # 3. publish: one complete generation, atomically selected ------------
        _publish(proj, swap_apktool=not skip_apktool,
                 swap_jadx=not skip_jadx,
                 db_identity={"sha256": sha,
                              "index_generation": str(generation)})
    except Exception:
        if not proj.publish_journal_path.exists():
            # failure while staging: discard the incomplete generation
            proj._discard_staging()
        # else: publication was interrupted; the journal + staging state are
        # left for recover_interrupted_publish (next open/init) to resolve
        raise

    summary.update({"generation": generation, "index_version": INDEX_VERSION,
                    **counts, "index_complete": True,
                    "line_map": {"state": lm_state, "reason": lm_reason},
                    "elapsed_s": round(time.time() - t0, 2)})
    proj.save_state(**{k: summary[k] for k in
                       ("apk", "sha256", "package", "manifest_debuggable")
                       if k in summary})
    log_progress(f"init complete: generation {generation}, "
                 f"{counts['classes']} classes, {counts['methods']} methods")
    return summary


def _cached_jadx_output(proj: Project) -> bool:
    d = proj.jadx_dir
    return d.is_dir() and any(d.iterdir())


def _check_reuse_gate(proj: Project, prior_sha: str | None, sha: str, *,
                      skip_apktool: bool, jadx_reuse: bool) -> None:
    """Reuse of cached decompiler outputs is only allowed when their
    provenance (the APK they were built from) matches; anything else needs
    an explicit rebuild choice (issue #35).

    apktool is the primary index source: --skip-apktool always requires a
    prior index with matching provenance and cached output. jadx is
    optional enrichment: reuse of its cached output is provenance-checked
    the same way, but --skip-jadx with nothing to reuse (e.g. first init on
    a host without jadx) proceeds jadx-free instead of erroring."""
    if skip_apktool:
        if prior_sha is None:
            raise MappingError(
                "--skip-apktool requested but the project has no prior "
                "index to reuse",
                hint="run a full init first: "
                     "apkdbg init --apk app.apk --out <dir>")
        if prior_sha != sha:
            raise MappingError(
                f"cached decompiler outputs belong to APK sha256 "
                f"{prior_sha}, not {sha}",
                hint="explicit rebuild required: re-run init without "
                     "--skip-apktool/--skip-jadx")
        if not proj.manifest_path.exists():
            raise MappingError(
                "--skip-apktool requested but there is no cached apktool "
                "output",
                hint="re-run init without --skip-apktool")
    if jadx_reuse and prior_sha != sha:
        raise MappingError(
            f"cached jadx output belongs to APK sha256 {prior_sha}, "
            f"not {sha}",
            hint="explicit rebuild required: re-run init without "
                 "--skip-jadx, or use a fresh project directory")


# ------------------------------------------------------------- staging build
def _build_staging_db(proj: Project, *, apktool_src: Path,
                      jadx_mapping: dict, live: bool,
                      summary: dict) -> dict:
    """Build the complete next-generation database at proj.staging_db_path.

    Fresh file -> every derived row is a plain insert/upsert against exactly
    the new APK's content; observation tables are copied across from the
    live DB first. Committed and checkpointed before returning.
    """
    staging = MappingDB(proj.staging_db_path)
    try:
        if live:
            _copy_observations(staging, proj.db_path)

        # resources from public.xml
        res = mappings.parse_public_xml(
            apktool_src / "res" / "values" / "public.xml")
        staging.executemany(
            "INSERT OR REPLACE INTO resources(res_id,type,name) VALUES(?,?,?)",
            [(r["res_id"], r["type"], r["name"]) for r in res])

        # smali index
        warnings: list[str] = []
        n_files = 0
        n_cls = n_meth = n_lines = n_branch = n_refs = 0
        for smali_root, path in smali_index.iter_smali_files(apktool_src):
            n_files += 1
            rel = f"{smali_root}/{path.relative_to(apktool_src / smali_root)}"
            try:
                parsed = smali_index.parse_smali_file(path)
            except Exception as e:  # one bad file must not abort the index
                warnings.append(f"smali parse failed: {rel}: {e}")
                continue
            if not parsed["sig"]:
                continue
            fqcn = parsed["sig"][1:-1].replace("/", ".")
            class_id = _upsert_class(staging, parsed["sig"], fqcn, rel,
                                     parsed["source_file"])
            n_cls += 1

            for m in parsed["methods"]:
                mid = _upsert_method(staging, class_id, m)
                n_meth += 1

                # line map: one row per .line directive's first insn
                seen = set()
                for insn in m["insns"]:
                    if insn["dl"] is not None and (insn["dl"], insn["fl"]) not in seen:
                        seen.add((insn["dl"], insn["fl"]))
                        staging.execute(
                            "INSERT INTO line_map"
                            "(method_id,dalvik_line,smali_line) VALUES(?,?,?)",
                            (mid, insn["dl"], insn["fl"]))
                        n_lines += 1

                for br in m["branches"]:
                    staging.execute(
                        "INSERT INTO branch_sites(method_id,smali_line,"
                        "dalvik_line,opcode,kind,target_smali_line,"
                        "target_dalvik_line) VALUES(?,?,?,?,?,?,?)",
                        (mid, br["fl"], br["dl"], br["op"], br["kind"],
                         br["target_fl"], br["target_dl"]))
                    n_branch += 1

                for rc in m["res_consts"]:
                    staging.execute(
                        "INSERT INTO resource_refs(res_id,method_id,smali_line,"
                        "dalvik_line,kind) VALUES(?,?,?,?,?)",
                        (rc["res_id"], mid, rc["fl"], rc["dl"], rc["kind"]))
                    n_refs += 1

        if warnings and len(warnings) == n_files:
            # systemic parse failure: never publish an empty index over a
            # healthy prior generation
            raise MappingError(
                f"smali parsing failed for all {n_files} files",
                hint=warnings[0])

        # jadx mappings (deobf names + optional java<->dalvik lines)
        n_deobf = n_jlines = 0
        for obf, deobf in jadx_mapping["names"].items():
            staging.execute("UPDATE classes SET deobf_fqcn=? WHERE fqcn=?",
                            (deobf, obf))
            n_deobf += 1
        for obf, line_map in jadx_mapping["lines"].items():
            row = staging.one("SELECT id FROM classes WHERE fqcn=?", (obf,))
            if row:
                for jl, dl in line_map.items():
                    staging.execute(
                        "INSERT INTO jadx_lines(class_id,java_line,dalvik_line)"
                        " VALUES(?,?,?)"
                        " ON CONFLICT(class_id,java_line)"
                        " DO UPDATE SET dalvik_line=excluded.dalvik_line",
                        (row["id"], jl, dl))
                    n_jlines += 1

        staging.commit()
    except Exception:
        staging.conn.close()  # uncommitted transaction is discarded
        _remove_db_files(proj.staging_db_path)
        raise
    staging.conn.close()
    return {"resources": len(res), "classes": n_cls, "methods": n_meth,
            "line_rows": n_lines, "branch_sites": n_branch,
            "resource_refs": n_refs, "deobf_classes": n_deobf,
            "jadx_line_rows": n_jlines, "warnings": warnings}


def _copy_observations(staging: MappingDB, live_db_path: Path) -> None:
    """Copy historical observation tables from the live DB into staging.
    Rows are carried verbatim, keeping each run/event/artifact's original
    index_generation (issue #36). Tables absent from the live DB (a project
    created before the feature that added them) are skipped."""
    staging.execute("ATTACH DATABASE ? AS live", (str(live_db_path),))
    live_tables = {r["name"] for r in staging.query(
        "SELECT name FROM live.sqlite_master WHERE type='table'")}
    for t in OBSERVATION_TABLES:
        if t in live_tables:
            # column intersection: a live DB written by an older apkdbg may
            # lack newer additive columns (e.g. coverage_hits.method_sig,
            # issue #37); new columns keep their defaults for carried rows
            cols = [r["name"] for r in
                    staging.query(f"PRAGMA table_info({t})")]
            live_cols = {r["name"] for r in
                         staging.query(f"PRAGMA live.table_info({t})")}
            use = [c for c in cols if c in live_cols]
            colist = ",".join(use)
            staging.execute(
                f"INSERT INTO {t} ({colist}) SELECT {colist} FROM live.{t}")
    # no explicit DETACH: it cannot run inside the open transaction; the
    # attached handle is released when the staging connection closes


# -------------------------------------------------- deterministic ID resolution
def _upsert_class(db: MappingDB, sig: str, fqcn: str, rel: str,
                  source_file: str | None) -> int:
    """Insert the class, or refresh its metadata when the sig already exists
    in this generation (duplicate class across smali_roots); always returns
    the row's real id — never cur.lastrowid after an ignored insert."""
    return db.execute(
        "INSERT INTO classes(sig,fqcn,smali_path,source_file) VALUES(?,?,?,?)"
        " ON CONFLICT(sig) DO UPDATE SET fqcn=excluded.fqcn,"
        " smali_path=excluded.smali_path, source_file=excluded.source_file"
        " RETURNING id", (sig, fqcn, rel, source_file)).fetchone()["id"]


def _upsert_method(db: MappingDB, class_id: int, m: dict) -> int:
    """Same deterministic pattern for methods (see _upsert_class)."""
    return db.execute(
        "INSERT INTO methods"
        "(class_id,name,sig,flags,is_native,line_start,line_end)"
        " VALUES(?,?,?,?,?,?,?)"
        " ON CONFLICT(class_id,name,sig) DO UPDATE SET flags=excluded.flags,"
        " is_native=excluded.is_native, line_start=excluded.line_start,"
        " line_end=excluded.line_end RETURNING id",
        (class_id, m["name"], m["sig"], m["flags"], int(m["is_native"]),
         m["line_start"], m["line_end"])).fetchone()["id"]


# ------------------------------------------------------------------ validation
def _validate_staging(db: MappingDB) -> None:
    """Gate between staging and publication: every derived row must attach
    to an entity of the same generation."""
    checks = {
        "methods": "SELECT COUNT(*) AS n FROM methods m"
                   " LEFT JOIN classes c ON m.class_id=c.id"
                   " WHERE c.id IS NULL",
        "line_map": "SELECT COUNT(*) AS n FROM line_map l"
                    " LEFT JOIN methods m ON l.method_id=m.id"
                    " WHERE m.id IS NULL",
        "branch_sites": "SELECT COUNT(*) AS n FROM branch_sites b"
                        " LEFT JOIN methods m ON b.method_id=m.id"
                        " WHERE m.id IS NULL",
        "resource_refs": "SELECT COUNT(*) AS n FROM resource_refs r"
                         " LEFT JOIN methods m ON r.method_id=m.id"
                         " WHERE m.id IS NULL",
        "jadx_lines": "SELECT COUNT(*) AS n FROM jadx_lines j"
                      " LEFT JOIN classes c ON j.class_id=c.id"
                      " WHERE c.id IS NULL",
    }
    bad = [name for name, sql in checks.items() if db.one(sql)["n"]]
    if bad:
        raise MappingError(
            f"staging validation failed: orphan rows in {', '.join(bad)}",
            hint="the incomplete generation was discarded; re-run init")


# ------------------------------------------------------------------ publication
def _publish(proj: Project, *, swap_apktool: bool, swap_jadx: bool,
             db_identity: dict) -> None:
    """Atomically select the staged generation. Journaled: a crash anywhere
    in here is resolved by Project.recover_interrupted_publish(). The DB
    swap is last-but-cleanup and a single os.replace — the point at which
    the new generation becomes visible. db_identity (the staged DB's
    provenance meta) is journaled up front, so recovery can tell whether
    the os.replace committed even when the db_swapped write did not."""
    swaps = []
    if swap_apktool:
        swaps.append((proj.apktool_staging_dir, proj.apktool_dir,
                      proj.apktool_old_dir))
    if swap_jadx:
        swaps.append((proj.jadx_staging_dir, proj.jadx_dir,
                      proj.jadx_old_dir))
    journal = {"swap": [{"live": str(live), "old": str(old)}
                        for _, live, old in swaps],
               "db_identity": db_identity,
               "dirs_swapped": False, "db_swapped": False}
    _write_journal(proj, journal)

    for staging_dir, live_dir, old_dir in swaps:
        if old_dir.exists():
            shutil.rmtree(old_dir)
        if live_dir.exists():
            os.rename(live_dir, old_dir)
        os.rename(staging_dir, live_dir)
    if swaps:
        journal["dirs_swapped"] = True
        _write_journal(proj, journal)

    # atomic selection point: staging DB already carries the copied
    # observation rows, so this one replace publishes a complete generation
    _remove_sidecars(proj.db_path)
    os.replace(proj.staging_db_path, proj.db_path)
    journal["db_swapped"] = True
    _write_journal(proj, journal)

    for _, _, old_dir in swaps:
        if old_dir.exists():
            shutil.rmtree(old_dir)
    proj.publish_journal_path.unlink(missing_ok=True)


def _write_journal(proj: Project, journal: dict) -> None:
    tmp = proj.publish_journal_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(journal, indent=1), "utf-8")
    os.replace(tmp, proj.publish_journal_path)


def _line_map_state(n_cls: int, n_lines: int) -> tuple[str, str]:
    """Availability AND reason, recorded separately: zero rows after a
    completed index is NOT proof of stripped debug info by itself — it only
    says the smali carried no .line directives."""
    if n_lines > 0:
        return "complete", "ok"
    if n_cls > 0:
        return "empty", "no_line_directives"
    return "unknown", "no_classes_indexed"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

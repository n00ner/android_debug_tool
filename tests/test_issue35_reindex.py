"""Offline tests for issue #35 — transactional re-indexing.

The full init pipeline runs apktool/jadx; here the decompiler wrappers are
faked (they write small synthetic smali/public.xml/manifest trees into the
staging dirs) so the parsing/DB/publish stages run for real, offline.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apkdbg.core import init_pipeline
from apkdbg.core.database import INDEX_VERSION, MappingDB
from apkdbg.core.init_pipeline import run_init
from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.errors import DecompileError, MappingError

TOOLS = "apkdbg.core.init_pipeline.tools"
SMALI_INDEX = "apkdbg.core.init_pipeline.smali_index"


# ----------------------------------------------------------- synthetic inputs
def method_spec(name, sig="()V", flags="public", lines=(10, 11),
                branch=False, res=None):
    return {"name": name, "sig": sig, "flags": flags, "lines": list(lines),
            "branch": branch, "res": res}


def class_spec(sig, source="A.java", methods=(), smali_root="smali"):
    return {"sig": sig, "source": source, "methods": list(methods),
            "smali_root": smali_root}


def spec(classes, resources=(), package="com.example.app",
         jadx_names=None, jadx_lines=None):
    return {"classes": list(classes), "resources": dict(resources),
            "package": package, "jadx_names": jadx_names or {},
            "jadx_lines": jadx_lines or {}}


SPEC_A = spec(
    [class_spec("Lcom/foo/A;", "A.java", [
        method_spec("m", lines=[10, 11, 12], branch=True, res=0x7f0f0001),
        method_spec("removed", lines=[20])]),
     class_spec("Lcom/foo/Removed;", "Removed.java", [method_spec("x")])],
    resources={0x7f0f0001: ("string", "app_name"),
               0x7f0f0002: ("string", "removed_str")},
    jadx_names={"com.foo.A": "com.real.Alpha"},
    jadx_lines={"com.foo.A": {100: 10}})

SPEC_B = spec(
    [class_spec("Lcom/foo/A;", "A2.java", [  # source file + lines changed
        method_spec("m", flags="public static", lines=[30, 31], res=0x7f0f0003),
        method_spec("added", lines=[40])]),
     class_spec("Lcom/foo/New;", "New.java", [method_spec("y")])],
    resources={0x7f0f0001: ("string", "app_name_renamed"),
               0x7f0f0003: ("layout", "main")},
    package="com.example.repackaged")


def _method_smali(m: dict) -> str:
    out = [f'.method {m["flags"]} {m["name"]}{m["sig"]}', "    .locals 2"]
    for i, dl in enumerate(m["lines"]):
        out.append(f"    .line {dl}")
        if i == 0 and m["branch"]:
            out.append("    if-eqz v0, :end")
        elif i == 0 and m["res"] is not None:
            out.append(f"    const v0, 0x{m['res']:08x}")
            out.append("    invoke-virtual {p0, v0}, "
                       "Landroid/content/res/Resources;->getString(I)"
                       "Ljava/lang/String;")
        else:
            out.append("    nop")
    if m["branch"]:
        out.append("    :end")
    out.append("    return-void")
    out.append(".end method")
    return "\n".join(out)


def write_apktool_dir(root: Path, s: dict) -> None:
    (root / "res" / "values").mkdir(parents=True, exist_ok=True)
    (root / "AndroidManifest.xml").write_text(
        f'<manifest package="{s["package"]}"></manifest>', "utf-8")
    publics = "\n".join(
        f'    <public type="{t}" name="{n}" id="0x{i:08x}" />'
        for i, (t, n) in s["resources"].items())
    (root / "res" / "values" / "public.xml").write_text(
        f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{publics}\n'
        "</resources>\n", "utf-8")
    for c in s["classes"]:
        pkg_dir = "/".join(c["sig"][1:-1].split("/")[:-1])
        d = root / c["smali_root"] / pkg_dir
        d.mkdir(parents=True, exist_ok=True)
        methods = "\n\n".join(_method_smali(m) for m in c["methods"])
        (d / f"{c['sig'][1:-1].split('/')[-1]}.smali").write_text(
            f'.class public {c["sig"]}\n.super Ljava/lang/Object;\n'
            f'.source "{c["source"]}"\n\n{methods}\n', "utf-8")


def write_jadx_dir(root: Path, s: dict) -> str | None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "Stub.java").write_text("class Stub {}\n", "utf-8")
    if not s["jadx_names"] and not s["jadx_lines"]:
        return None
    classes = {}
    for obf, new in s["jadx_names"].items():
        classes.setdefault(obf, {})["newName"] = new
    for obf, lines in s["jadx_lines"].items():
        classes.setdefault(obf, {})["lines"] = [
            {"java": jl, "smali": dl} for jl, dl in lines.items()]
    mapping = root / "mappings.json"
    mapping.write_text(json.dumps({"classes": [
        {"oldName": obf, **body} for obf, body in classes.items()]}), "utf-8")
    return str(mapping)


# ------------------------------------------------------------------ test base
class ReindexTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proj_dir = self.root / "proj"
        self.apk_a = self.root / "a.apk"
        self.apk_b = self.root / "b.apk"
        self.apk_a.write_bytes(b"fake-apk-A")
        self.apk_b.write_bytes(b"fake-apk-B")
        self.specs = {b"fake-apk-A": SPEC_A, b"fake-apk-B": SPEC_B}

        def fake_apktool_decode(apk, out_dir, timeout=900):
            write_apktool_dir(Path(out_dir), self.specs[Path(apk).read_bytes()])
            return {"tool": "apktool", "out": str(out_dir)}

        def fake_jadx_decompile(apk, out_dir, timeout=1200):
            mapping = write_jadx_dir(
                Path(out_dir), self.specs[Path(apk).read_bytes()])
            return {"tool": "jadx", "out": str(out_dir), "flags": ["--deobf"],
                    "java_files": 1, "decompile_errors": False,
                    "mapping_file": mapping}

        for p in (mock.patch(f"{TOOLS}.apktool_decode", fake_apktool_decode),
                  mock.patch(f"{TOOLS}.jadx_decompile", fake_jadx_decompile),
                  mock.patch(f"{TOOLS}.tool_version",
                             lambda tool, *, env_var=None: f"{tool} 1.0-test")):
            p.start()
            self.addCleanup(p.stop)

    # helpers ------------------------------------------------------------------
    def init(self, apk, **kw):
        return run_init(apk, self.proj_dir, **kw)

    def proj(self):
        return Project(self.proj_dir)

    def derived(self, db) -> dict:
        """Full dump of the APK-derived tables (ids included)."""
        out = {}
        for t in ("classes", "methods", "line_map", "jadx_lines",
                  "branch_sites", "resources", "resource_refs"):
            out[t] = db.query(f"SELECT * FROM {t} ORDER BY rowid")
        return out

    def init_a(self):
        return self.init(self.apk_a)

    def meta(self, key):
        with self.proj().db() as db:
            return db.get_meta(key)


class ExactGenerationTests(ReindexTestBase):
    def test_reindex_leaves_exactly_new_generation(self):
        self.init_a()
        summary = self.init(self.apk_b)
        self.assertEqual(summary["generation"], 2)
        with self.proj().db() as db:
            d = self.derived(db)
            # classes: exactly B's, with B's metadata
            by_sig = {c["sig"]: c for c in d["classes"]}
            self.assertEqual(set(by_sig), {"Lcom/foo/A;", "Lcom/foo/New;"})
            self.assertEqual(by_sig["Lcom/foo/A;"]["source_file"], "A2.java")
            self.assertIsNone(by_sig["Lcom/foo/A;"]["deobf_fqcn"])  # B has none
            # methods: removed one gone, added one present, B's flags/lines
            methods = {(m["name"], m["sig"]): m for m in d["methods"]}
            self.assertEqual(set(methods),
                             {("m", "()V"), ("added", "()V"), ("y", "()V")})
            m = methods[("m", "()V")]
            self.assertEqual(m["flags"], "public static")
            self.assertEqual(m["class_id"], by_sig["Lcom/foo/A;"]["id"])
            # line map: exactly B's locations (one row per insn after each
            # .line directive; compare distinct dalvik lines per method)
            lm = {(r["method_id"], r["dalvik_line"]) for r in d["line_map"]}
            ids = {m["name"]: m["id"] for m in d["methods"]}
            self.assertEqual(lm, {(ids["m"], 30), (ids["m"], 31),
                                  (ids["added"], 40), (ids["y"], 10),
                                  (ids["y"], 11)})
            # no branch sites left from A (B's m has none)
            self.assertEqual(d["branch_sites"], [])
            # resources: removed gone, renamed updated
            res = {r["res_id"]: (r["type"], r["name"]) for r in d["resources"]}
            self.assertEqual(res, {0x7f0f0001: ("string", "app_name_renamed"),
                                   0x7f0f0003: ("layout", "main")})
            # resource refs point at B's method/res
            self.assertEqual([(r["res_id"], r["method_id"])
                              for r in d["resource_refs"]],
                             [(0x7f0f0003, ids["m"])])
            # jadx lines from A's generation are gone
            self.assertEqual(d["jadx_lines"], [])
            self.assertEqual(db.get_meta("package"), "com.example.repackaged")

    def test_repeat_index_equivalent_content(self):
        self.init_a()
        with self.proj().db() as db:
            first = self.derived(db)
        summary = self.init(self.apk_a)  # same APK, full rebuild
        self.assertEqual(summary["generation"], 2)
        with self.proj().db() as db:
            second = self.derived(db)
        self.assertEqual(first, second)  # ids included: no dup/cross-links
        # no duplicated primary/unique keys snuck in
        self.assertEqual(len(second["classes"]),
                         len({c["sig"] for c in second["classes"]}))

    def test_duplicate_class_sig_resolves_ids_deterministically(self):
        # same class sig in smali/ and smali_classes2/: the second insert is
        # an upsert conflict after other successful inserts; derived rows
        # must still attach to the single correct class/method
        dup = spec([
            class_spec("Lcom/foo/Before;", methods=[method_spec("b")]),
            class_spec("Lcom/foo/Dup;", "Dup.java",
                       [method_spec("m1", lines=[5, 6])]),
            class_spec("Lcom/foo/Dup;", "Dup2.java",
                       [method_spec("m2", lines=[7])],
                       smali_root="smali_classes2"),
            class_spec("Lcom/foo/After;", methods=[method_spec("a")]),
        ])
        self.specs[b"fake-apk-A"] = dup
        self.init_a()
        with self.proj().db() as db:
            d = self.derived(db)
            dup_rows = [c for c in d["classes"] if c["sig"] == "Lcom/foo/Dup;"]
            self.assertEqual(len(dup_rows), 1)
            dup_id = dup_rows[0]["id"]
            by_name = {m["name"]: m for m in d["methods"]}
            self.assertEqual(set(by_name), {"b", "m1", "m2", "a"})
            self.assertEqual(by_name["m1"]["class_id"], dup_id)
            self.assertEqual(by_name["m2"]["class_id"], dup_id)
            lm = {(r["method_id"], r["dalvik_line"]) for r in d["line_map"]}
            self.assertIn((by_name["m1"]["id"], 5), lm)
            self.assertIn((by_name["m2"]["id"], 7), lm)


class TransactionSemanticsTests(ReindexTestBase):
    def test_db_context_rolls_back_on_exception(self):
        self.init_a()
        with self.assertRaises(RuntimeError):
            with self.proj().db() as db:
                db.execute("INSERT INTO classes(sig,fqcn) VALUES('Lx;','x')")
                raise RuntimeError("boom")
        with self.proj().db() as db:
            self.assertIsNone(
                db.one("SELECT id FROM classes WHERE sig='Lx;'"))
        # success path still commits
        with self.proj().db() as db:
            db.execute("INSERT INTO classes(sig,fqcn) VALUES('Ly;','y')")
        with self.proj().db() as db:
            self.assertIsNotNone(
                db.one("SELECT id FROM classes WHERE sig='Ly;'"))


class FailureInjectionTests(ReindexTestBase):
    def assert_prior_generation_intact(self):
        self.assertEqual(self.meta("index_generation"), "1")
        self.assertFalse(self.proj().staging_db_path.exists())
        self.assertFalse(self.proj().apktool_staging_dir.exists())
        self.assertFalse(self.proj().jadx_staging_dir.exists())
        self.assertFalse(self.proj().publish_journal_path.exists())
        with self.proj().db() as db:
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/Removed;"})

    def test_decompile_failure_keeps_prior_generation(self):
        self.init_a()
        with mock.patch(f"{TOOLS}.apktool_decode",
                        side_effect=DecompileError("apktool blew up")):
            with self.assertRaises(DecompileError):
                self.init(self.apk_b)
        self.assert_prior_generation_intact()

    def test_parse_failure_keeps_prior_generation(self):
        self.init_a()
        # per-file parse failures are tolerated (warnings); a systemic
        # failure — every file unparsable — must abort instead of
        # publishing an empty index over the prior generation
        with mock.patch(f"{SMALI_INDEX}.parse_smali_file",
                        side_effect=ValueError("bad smali")):
            with self.assertRaises(MappingError):
                self.init(self.apk_b)
        self.assert_prior_generation_intact()

    def test_insert_failure_keeps_prior_generation(self):
        self.init_a()
        with mock.patch.object(MappingDB, "executemany",
                               side_effect=sqlite3.OperationalError("boom")):
            with self.assertRaises(sqlite3.OperationalError):
                self.init(self.apk_b)
        self.assert_prior_generation_intact()

    def test_validation_failure_keeps_prior_generation(self):
        self.init_a()
        with mock.patch("apkdbg.core.init_pipeline._validate_staging",
                        side_effect=MappingError("orphans everywhere")):
            with self.assertRaises(MappingError):
                self.init(self.apk_b)
        self.assert_prior_generation_intact()

    def test_publish_failure_keeps_prior_generation_then_recovers(self):
        self.init_a()
        real_replace = os.replace

        def fail_db_swap(src, dst):
            if Path(dst) == self.proj().db_path:
                raise OSError("disk full")
            return real_replace(src, dst)

        with mock.patch("os.replace", side_effect=fail_db_swap):
            with self.assertRaises(OSError):
                self.init(self.apk_b)
        # publish was interrupted: journal left behind, prior generation is
        # still the selected one
        self.assertTrue(self.proj().publish_journal_path.exists())
        self.assertEqual(self.meta("index_generation"), "1")
        with self.proj().db() as db:
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/Removed;"})
        # decompiler dirs were swapped before the failure: live dir currently
        # holds B's staging output
        self.assertIn("repackaged", (self.proj().manifest_path).read_text())
        # restart: recovery rolls dirs back to the published generation
        Project.open(self.proj_dir)
        self.assertFalse(self.proj().publish_journal_path.exists())
        self.assertFalse(self.proj().staging_db_path.exists())
        self.assertFalse(self.proj().apktool_old_dir.exists())
        self.assertIn("com.example.app",
                      self.proj().manifest_path.read_text())
        self.assertEqual(self.meta("index_generation"), "1")


class RestartRecoveryTests(ReindexTestBase):
    def test_restart_discards_incomplete_staging(self):
        self.init_a()
        # crash while building generation 2: staging leftovers, no journal
        self.proj().staging_db_path.write_bytes(b"half-built db")
        write_apktool_dir(self.proj().apktool_staging_dir, SPEC_B)
        Project.open(self.proj_dir)
        self.assertFalse(self.proj().staging_db_path.exists())
        self.assertFalse(self.proj().apktool_staging_dir.exists())
        with self.proj().db() as db:
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/Removed;"})

    def test_restart_rolls_back_interrupted_publish(self):
        self.init_a()
        proj = self.proj()
        # simulate a crash between the dir swap and the DB swap
        import os
        os.rename(proj.apktool_dir, proj.apktool_old_dir)
        write_apktool_dir(proj.apktool_dir, SPEC_B)
        proj.staging_db_path.write_bytes(b"staged but never swapped")
        proj.publish_journal_path.write_text(json.dumps({
            "swap": [{"live": str(proj.apktool_dir),
                      "old": str(proj.apktool_old_dir)}],
            "dirs_swapped": True, "db_swapped": False}), "utf-8")
        Project.open(self.proj_dir)
        self.assertIn("com.example.app", proj.manifest_path.read_text())
        self.assertFalse(proj.apktool_old_dir.exists())
        self.assertFalse(proj.staging_db_path.exists())
        self.assertFalse(proj.publish_journal_path.exists())
        self.assertEqual(self.meta("index_generation"), "1")

    def test_restart_finishes_cleanup_after_db_swap(self):
        self.init_a()
        proj = self.proj()
        proj.apktool_old_dir.mkdir()
        (proj.apktool_old_dir / "stale").write_text("x")
        proj.staging_db_path.write_bytes(b"leftover")
        proj.publish_journal_path.write_text(json.dumps({
            "swap": [], "dirs_swapped": True, "db_swapped": True}), "utf-8")
        Project.open(self.proj_dir)
        self.assertFalse(proj.apktool_old_dir.exists())
        self.assertFalse(proj.staging_db_path.exists())
        self.assertFalse(proj.publish_journal_path.exists())
        self.assertEqual(self.meta("index_generation"), "1")


class ProvenanceTests(ReindexTestBase):
    def test_provenance_recorded(self):
        summary = self.init_a()
        self.assertEqual(summary["index_version"], INDEX_VERSION)
        self.assertEqual(summary["generation"], 1)
        self.assertEqual(self.meta("index_version"), str(INDEX_VERSION))
        self.assertEqual(self.meta("index_generation"), "1")
        prov = json.loads(self.meta("provenance"))
        self.assertEqual(prov["apk_sha256"], self.meta("sha256"))
        self.assertEqual(prov["index_version"], INDEX_VERSION)
        self.assertEqual(prov["generation"], 1)
        self.assertEqual(prov["options"],
                         {"skip_apktool": False, "skip_jadx": False})
        self.assertEqual(prov["decompilers"]["apktool"]["version"],
                         "apktool 1.0-test")
        self.assertEqual(prov["decompilers"]["jadx"]["flags"], ["--deobf"])
        self.assertIn("indexed_at", prov)

    def test_cached_outputs_reuse_requires_matching_provenance(self):
        self.init_a()
        with self.proj().db() as db:
            first = self.derived(db)
        # same APK: cached outputs match their provenance -> reuse allowed
        summary = self.init(self.apk_a, skip_apktool=True, skip_jadx=True)
        self.assertEqual(summary["generation"], 2)
        prov = json.loads(self.meta("provenance"))
        self.assertTrue(prov["decompilers"]["apktool"]["reused"])
        with self.proj().db() as db:
            self.assertEqual(first, self.derived(db))
        # different APK with the same cached outputs -> explicit rebuild needed
        with self.assertRaises(MappingError) as cm:
            self.init(self.apk_b, skip_apktool=True, skip_jadx=True)
        self.assertIn("rebuild", cm.exception.hint)
        self.assertEqual(self.meta("index_generation"), "2")

    def test_skip_without_prior_index_is_a_clear_error(self):
        with self.assertRaises(MappingError) as cm:
            self.init(self.apk_a, skip_apktool=True)
        self.assertIn("no prior index", str(cm.exception))
        with self.assertRaises(MappingError) as cm:
            self.init(self.apk_a, skip_apktool=True, skip_jadx=True)
        self.assertIn("no prior index", str(cm.exception))

    def test_first_init_skip_jadx_proceeds_jadx_free(self):
        # jadx is optional enrichment: on a host without jadx, a first-time
        # init --skip-jadx must succeed with jadx-derived data simply empty
        summary = self.init(self.apk_a, skip_jadx=True)
        self.assertEqual(summary["generation"], 1)
        self.assertNotIn("jadx", summary)
        prov = json.loads(self.meta("provenance"))
        self.assertEqual(prov["decompilers"]["jadx"],
                         {"skipped": True, "reused": False,
                          "version": None, "flags": None})
        with self.proj().db() as db:
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/Removed;"})
            self.assertEqual(db.query("SELECT * FROM jadx_lines"), [])
            deobf = db.query("SELECT deobf_fqcn FROM classes")
            self.assertEqual({r["deobf_fqcn"] for r in deobf}, {None})

    def test_reindex_skip_jadx_without_cached_output_stays_jadx_free(self):
        self.init(self.apk_a, skip_jadx=True)  # jadx-free first generation
        summary = self.init(self.apk_a, skip_jadx=True)
        self.assertEqual(summary["generation"], 2)
        prov = json.loads(self.meta("provenance"))
        self.assertEqual(prov["decompilers"]["jadx"],
                         {"skipped": True, "reused": False,
                          "version": None, "flags": None})
        with self.proj().db() as db:
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/Removed;"})

    def test_skip_jadx_with_mismatched_cached_output_errors(self):
        self.init_a()  # full init: jadx output cached under APK A's sha
        with self.assertRaises(MappingError) as cm:
            self.init(self.apk_b, skip_jadx=True)
        self.assertIn("rebuild", cm.exception.hint)
        self.assertEqual(self.meta("index_generation"), "1")
        # same APK reuses the cached jadx output fine
        summary = self.init(self.apk_a, skip_jadx=True)
        self.assertEqual(summary["generation"], 2)
        prov = json.loads(self.meta("provenance"))
        self.assertEqual(prov["decompilers"]["jadx"]["reused"], True)
        self.assertEqual(prov["decompilers"]["jadx"]["skipped"], False)

    def test_newer_index_version_rejected(self):
        self.init_a()
        with self.proj().db() as db:
            db.set_meta("index_version", str(INDEX_VERSION + 1))
        with self.assertRaises(MappingError) as cm:
            self.init(self.apk_a)
        self.assertIn("newer", str(cm.exception))
        with self.assertRaises(MappingError):
            Project.open(self.proj_dir)


class ObservationRetentionTests(ReindexTestBase):
    def test_observations_retained_with_original_generation(self):
        self.init_a()
        proj = self.proj()
        store = RunStore(proj)
        run_id = store.begin_run("coverage", {"seconds": 5}, scenario="sc",
                                 epoch=1)
        event_id = store.add_event(run_id, "crypto_record", {"alg": "AES"},
                                   class_sig="Lcom/foo/A;", method_name="m",
                                   dalvik_line=10)
        artifact_id = store.add_artifact(run_id, "coverage_report",
                                         {"hits": 3})
        store.end_run(run_id, "completed")
        with proj.db() as db:
            db.execute(
                "INSERT INTO coverage_hits(run_id,class_sig,method_name,"
                "dalvik_line,hits) VALUES(?,?,?,?,?)",
                (run_id, "Lcom/foo/A;", "m", 10, 3))

        self.init(self.apk_b)  # re-index against a different generation

        with proj.db() as db:
            run = db.one("SELECT * FROM runs WHERE run_id=?", (run_id,))
            self.assertIsNotNone(run)
            self.assertEqual(run["index_generation"], 1)
            self.assertEqual(run["completion_reason"], "completed")
            ev = db.one("SELECT * FROM events WHERE event_id=?", (event_id,))
            self.assertEqual(ev["index_generation"], 1)
            art = db.one("SELECT * FROM artifacts WHERE artifact_id=?",
                         (artifact_id,))
            self.assertEqual(art["index_generation"], 1)
            hit = db.one("SELECT * FROM coverage_hits WHERE run_id=?",
                         (run_id,))
            self.assertEqual(hit["hits"], 3)
            # derived tables describe exactly generation 2
            sigs = {c["sig"] for c in db.query("SELECT sig FROM classes")}
            self.assertEqual(sigs, {"Lcom/foo/A;", "Lcom/foo/New;"})
        # new observations attach to the new generation
        new_run = store.begin_run("coverage")
        with proj.db() as db:
            self.assertEqual(
                db.one("SELECT index_generation FROM runs WHERE run_id=?",
                       (new_run,))["index_generation"], 2)


if __name__ == "__main__":
    unittest.main()

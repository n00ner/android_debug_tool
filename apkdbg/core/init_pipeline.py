"""Init Phase orchestration: decompile -> index -> build mapping DB."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from ..decompile import mappings, smali_index, tools
from ..protocol import log_progress
from . import manifests
from .project import Project


def run_init(apk: str | Path, project_root: str | Path, *,
             skip_apktool: bool = False, skip_jadx: bool = False,
             timeout: int = 1200) -> dict:
    apk = Path(apk).resolve()
    if not apk.exists():
        from ..errors import DecompileError
        raise DecompileError(f"APK not found: {apk}")

    proj = Project.create(project_root)
    t0 = time.time()
    summary: dict = {"apk": str(apk),
                     "sha256": _sha256(apk),
                     "project": str(proj.root)}

    # 1. decompile ------------------------------------------------------------
    if not skip_apktool:
        summary["apktool"] = tools.apktool_decode(apk, proj.apktool_dir,
                                                  timeout=timeout)
    if not skip_jadx:
        summary["jadx"] = tools.jadx_decompile(apk, proj.jadx_dir,
                                               timeout=timeout)

    pkg = mappings.parse_manifest_package(proj.manifest_path)
    if pkg:
        summary["package"] = pkg

    # 2. build the mapping database --------------------------------------------
    with proj.db() as db:
        # resources from public.xml
        res = mappings.parse_public_xml(
            proj.apktool_dir / "res" / "values" / "public.xml")
        db.executemany(
            "INSERT OR REPLACE INTO resources(res_id,type,name) VALUES(?,?,?)",
            [(r["res_id"], r["type"], r["name"]) for r in res])
        summary["resources"] = len(res)

        # smali index (idempotent: derived tables are rebuilt from scratch;
        # observation tables — runs/events/artifacts/coverage_hits — are
        # never touched, and the generation marks which index new
        # observations belong to, see core/manifests.py)
        for t in ("line_map", "branch_sites", "resource_refs", "jadx_lines"):
            db.execute(f"DELETE FROM {t}")
        if db.get_meta("index_generation") is None:
            db.set_meta("index_generation", "1")  # first index
        else:
            manifests.bump_index_generation(db)   # re-index
        n_cls = n_meth = n_lines = n_branch = n_refs = 0
        for smali_root, path in smali_index.iter_smali_files(proj.apktool_dir):
            rel = f"{smali_root}/{path.relative_to(proj.apktool_dir / smali_root)}"
            parsed = smali_index.parse_smali_file(path)
            if not parsed["sig"]:
                continue
            fqcn = parsed["sig"][1:-1].replace("/", ".")
            cur = db.execute(
                "INSERT OR IGNORE INTO classes(sig,fqcn,smali_path,source_file)"
                " VALUES(?,?,?,?)",
                (parsed["sig"], fqcn, rel, parsed["source_file"]))
            class_id = cur.lastrowid or db.one(
                "SELECT id FROM classes WHERE sig=?", (parsed["sig"],))["id"]
            n_cls += 1

            for m in parsed["methods"]:
                cur = db.execute(
                    "INSERT OR IGNORE INTO methods"
                    "(class_id,name,sig,flags,is_native,line_start,line_end)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (class_id, m["name"], m["sig"], m["flags"],
                     int(m["is_native"]), m["line_start"], m["line_end"]))
                mid = cur.lastrowid or db.one(
                    "SELECT id FROM methods WHERE class_id=? AND name=?"
                    " AND sig=?", (class_id, m["name"], m["sig"]))["id"]
                n_meth += 1

                # line map: one row per .line directive's first insn
                seen = set()
                for insn in m["insns"]:
                    if insn["dl"] is not None and (insn["dl"], insn["fl"]) not in seen:
                        seen.add((insn["dl"], insn["fl"]))
                        db.execute(
                            "INSERT OR IGNORE INTO line_map"
                            "(method_id,dalvik_line,smali_line) VALUES(?,?,?)",
                            (mid, insn["dl"], insn["fl"]))
                        n_lines += 1

                for br in m["branches"]:
                    db.execute(
                        "INSERT INTO branch_sites(method_id,smali_line,"
                        "dalvik_line,opcode,kind,target_smali_line,"
                        "target_dalvik_line) VALUES(?,?,?,?,?,?,?)",
                        (mid, br["fl"], br["dl"], br["op"], br["kind"],
                         br["target_fl"], br["target_dl"]))
                    n_branch += 1

                for rc in m["res_consts"]:
                    db.execute(
                        "INSERT INTO resource_refs(res_id,method_id,smali_line,"
                        "dalvik_line,kind) VALUES(?,?,?,?,?)",
                        (rc["res_id"], mid, rc["fl"], rc["dl"], rc["kind"]))
                    n_refs += 1

        # jadx mappings (deobf names + optional java<->dalvik lines)
        jm = mappings.load_jadx_mapping(
            summary.get("jadx", {}).get("mapping_file"))
        n_deobf = n_jlines = 0
        for obf, deobf in jm["names"].items():
            db.execute("UPDATE classes SET deobf_fqcn=? WHERE fqcn=?",
                       (deobf, obf))
            n_deobf += 1
        for obf, line_map in jm["lines"].items():
            row = db.one("SELECT id FROM classes WHERE fqcn=?", (obf,))
            if row:
                for jl, dl in line_map.items():
                    db.execute(
                        "INSERT OR IGNORE INTO jadx_lines"
                        "(class_id,java_line,dalvik_line) VALUES(?,?,?)",
                        (row["id"], jl, dl))
                    n_jlines += 1

        db.set_meta("apk", str(apk))
        db.set_meta("sha256", summary["sha256"])
        if pkg:
            db.set_meta("package", pkg)

    summary.update({"classes": n_cls, "methods": n_meth, "line_rows": n_lines,
                    "branch_sites": n_branch, "resource_refs": n_refs,
                    "deobf_classes": n_deobf, "jadx_line_rows": n_jlines,
                    "elapsed_s": round(time.time() - t0, 2)})
    proj.save_state(**{k: summary[k] for k in
                       ("apk", "sha256", "package") if k in summary})
    log_progress(f"init complete: {n_cls} classes, {n_meth} methods")
    return summary


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

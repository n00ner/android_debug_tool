"""Static-analysis capability reporting (offline by default).

Answers "what can this project/APK actually do?" from persistent index facts
(mapping.db meta + row counts + project.json), WITHOUT touching a device.
`probe()` is the only place live observations are collected, and only on an
explicit `capabilities --probe`; observations are reported as transient
evidence and never written back over the persistent APK/index facts.

Per-capability record:
  status    supported | limited | unsupported | unknown
  evidence  dict of the concrete facts behind the status (counts, flags, ...)
  source    static_index | mapping_db | static_inference | observed
  hint      actionable next step when not fully supported
"""

from __future__ import annotations

import json
import time

from ..device.adb import Adb
from ..device.jdwp import JdwpClient
from ..errors import ApkDbgError
from ..protocol import log_progress
from .database import INDEX_VERSION, SCHEMA_VERSION

REPORT_SCHEMA = 1

# runtime-dependent commands, each reported individually
RUNTIME_COMMANDS = [
    "connect", "bp", "bp_del", "bp_list", "events", "read_var", "write_var",
    "invoke", "step", "resume", "snapshot", "dump_object", "cond",
    "hook_crypto", "coverage", "native",
]

_COUNT_TABLES = {"classes": "classes", "methods": "methods",
                 "line_rows": "line_map", "jadx_line_rows": "jadx_lines",
                 "resources": "resources", "resource_refs": "resource_refs"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ------------------------------------------------------------------- facts
def index_facts(db) -> dict:
    """Persistent index facts from the mapping DB (works on legacy DBs that
    predate the meta keys by falling back to computed row counts)."""
    counts = {k: db.one(f"SELECT COUNT(*) AS n FROM {t}")["n"]
              for k, t in _COUNT_TABLES.items()}
    meta = {k: db.get_meta(k) for k in
            ("schema_version", "index_version", "index_complete",
             "index_warnings", "line_map_state", "line_map_reason",
             "manifest_debuggable", "indexed_at", "tools")}

    complete = {"true": True, "false": False}.get(
        meta["index_complete"] or "", None)
    try:
        warnings = json.loads(meta["index_warnings"] or "[]")
    except json.JSONDecodeError:
        warnings = [meta["index_warnings"]]

    state, reason = meta["line_map_state"], meta["line_map_reason"]
    if not state:
        state, reason = _compute_line_map(complete, counts)

    tools = None
    if meta["tools"]:
        try:
            tools = json.loads(meta["tools"])
        except json.JSONDecodeError:
            tools = None

    return {
        "schema_version": meta["schema_version"] or "1",  # absent == legacy
        "index_version": meta["index_version"] or "legacy",
        "tool_schema_target": {"schema": SCHEMA_VERSION, "index": INDEX_VERSION},
        "complete": complete,
        "warnings": warnings,
        "counts": counts,
        "line_map": {"state": state, "reason": reason},
        "manifest_debuggable": meta["manifest_debuggable"],
        "indexed_at": meta["indexed_at"],
        "tools": tools,
    }


def _compute_line_map(complete: bool | None, counts: dict) -> tuple[str, str]:
    """Line-map availability AND the reason for missing data, kept separate:
    zero rows after a *completed* index means the smali carried no .line
    directives (likely stripped debug info); an incomplete/legacy index means
    the empty map proves nothing."""
    if complete is False:
        return "unknown", "index_incomplete"
    if counts["line_rows"] > 0:
        return "complete", "ok"
    if complete is None:
        return "unknown", "no_index_metadata"
    if counts["classes"] > 0:
        return "empty", "no_line_directives"
    return "unknown", "no_classes_indexed"


# ------------------------------------------------------------------- report
def collect(project, *, probe_live: bool = False, serial: str | None = None,
            package: str | None = None) -> dict:
    state = project.state()
    with project.db() as db:
        facts = index_facts(db)
    md = _manifest_debuggable(facts, state)

    caps = _static_caps(facts)
    caps.update(_runtime_caps(facts, md))

    report = {
        "report_schema": REPORT_SCHEMA,
        "mode": _mode(facts),
        "apk": {
            "path": state.get("apk"),
            "package": state.get("package"),
            "sha256": state.get("sha256"),
            # separately sourced APK manifest fact — NOT ro.debuggable
            "manifest_debuggable": md,
        },
        "index": facts,
        "capabilities": caps,
    }
    if probe_live:
        obs = probe(project, serial=serial,
                    package=package or state.get("package"))
        report["probe"] = obs
        _fold_probe(caps, obs)
    return report


def _manifest_debuggable(facts: dict, state: dict) -> str:
    """true | false | unknown — persisted by init; legacy projects fall back
    to project.json, then unknown (never inferred from device state)."""
    md = facts.get("manifest_debuggable")
    if md in ("true", "false"):
        return md
    v = state.get("manifest_debuggable")
    if v is True or v == "true":
        return "true"
    if v is False or v == "false":
        return "false"
    return "unknown"


def _cap(status: str, source: str, evidence: dict | None = None,
         hint: str | None = None) -> dict:
    d = {"status": status, "source": source, "evidence": evidence or {}}
    if hint:
        d["hint"] = hint
    return d


def _static_caps(facts: dict) -> dict:
    counts, complete = facts["counts"], facts["complete"]
    caps = {}
    for name, key, empty_hint in (
            ("classes", "classes", "index contains no classes — re-run init"),
            ("methods", "methods", "index contains no methods — re-run init"),
            ("res", "resources",
             "no resources indexed (public.xml missing?) — re-run init"),
            ("res_refs", "resource_refs",
             "no resource call sites indexed — re-run init")):
        n = counts[key]
        if n > 0:
            caps[name] = _cap("supported", "mapping_db", {"count": n})
        elif complete is False:
            caps[name] = _cap("unknown", "mapping_db",
                              {"count": 0, "index_complete": False},
                              "index generation did not finish; "
                              "re-run init, then see 'capabilities'")
        else:
            caps[name] = _cap("unsupported", "mapping_db", {"count": 0},
                              empty_hint)

    lm = facts["line_map"]
    ev = {"line_rows": counts["line_rows"],
          "jadx_line_rows": counts["jadx_line_rows"], "reason": lm["reason"]}
    if lm["state"] == "complete":
        caps["source_line_resolution"] = _cap(
            "supported", "static_index", ev,
            "runtime LineNumberTable stays authoritative at bp time")
    elif lm["state"] == "empty":
        caps["source_line_resolution"] = _cap(
            "unsupported", "static_index", ev,
            "APK carries no .line directives (likely stripped debug info) — "
            "java:line cannot be resolved; use smali-level coordinates")
    else:
        caps["source_line_resolution"] = _cap(
            "unknown", "static_index", ev,
            "line-map availability is unverified (index incomplete or "
            "pre-metadata) — re-run init to rebuild the index")
    return caps


def _runtime_caps(facts: dict, manifest_debuggable: str) -> dict:
    lm_state = facts["line_map"]["state"]
    caps = {}
    for name in RUNTIME_COMMANDS:
        caps[name] = _cap(
            "unknown", "static_inference",
            {"requires": ["adb_device", "jdwp_attach"]},
            "offline assessment only — run 'capabilities --probe' with a "
            "device attached to verify")

    md_ev = {"manifest_debuggable": manifest_debuggable}
    if manifest_debuggable == "true":
        caps["jdwp_attach"] = _cap(
            "unknown", "static_inference", md_ev,
            "manifest declares android:debuggable=true — attach should work; "
            "verify with 'capabilities --probe'")
    elif manifest_debuggable == "false":
        caps["jdwp_attach"] = _cap(
            "limited", "static_inference", md_ev,
            "android:debuggable=false — JDWP attach needs ro.debuggable=1, "
            "root (run-as/injected agent), or a rebuild; not proven "
            "impossible — verify with 'capabilities --probe'")
    else:
        caps["jdwp_attach"] = _cap(
            "unknown", "static_inference", md_ev,
            "manifest debuggable state could not be established — verify "
            "with 'capabilities --probe'")

    caps["runtime_line_table"] = _cap(
        "unknown", "static_inference",
        {"static_line_map": lm_state},
        "runtime line tables can only be observed on an attached VM — "
        "run 'capabilities --probe'")

    if lm_state != "complete":
        caps["bp"] = _cap(
            "limited", "static_inference",
            {"requires": ["adb_device", "jdwp_attach"],
             "source_line_resolution": lm_state},
            "source-line breakpoints fail early with E_LINE_MAPPING while "
            "the line map is not verified; use smali/method-entry "
            "coordinates")
    return caps


def _mode(facts: dict) -> str:
    """Summary only — the per-capability records are the authoritative data."""
    if facts["complete"] is False:
        return "static_incomplete"
    if facts["line_map"]["state"] == "complete":
        return "static_full"
    if facts["counts"]["classes"] > 0:
        return "static_no_line_map"
    return "unknown"


# --------------------------------------------------------------------- probe
def probe(project, *, serial: str | None = None, package: str | None = None,
          timeout: float = 15.0) -> dict:
    """Explicit live observations: device presence, process presence, JDWP
    attach state, observed runtime line-table availability. Each step records
    what it saw (or why it stopped) and preserves 'unknown' where nothing
    could be observed. Nothing here is persisted."""
    obs: dict = {"observed_at": _now(), "device": None, "process": None,
                 "jdwp": None, "runtime_line_table": None}
    try:
        adb = Adb(serial)
    except ApkDbgError as e:
        obs["device"] = {"present": "unknown", "error": e.to_dict()}
        return obs

    try:
        state = adb.ensure_device()
        obs["device"] = {"present": True, "state": state}
    except ApkDbgError as e:
        obs["device"] = {"present": False, "error": e.to_dict()}
        return obs

    if not package:
        obs["process"] = {"present": "unknown", "reason": "no_package_known"}
        return obs
    pid = adb.pidof(package)
    obs["process"] = {"present": bool(pid), "package": package, "pid": pid}
    if not pid:
        return obs

    port = None
    client = None
    try:
        port = adb.forward_jdwp(pid)
        client = JdwpClient("127.0.0.1", port, timeout=timeout)
        try:
            client.connect()
        except ApkDbgError as e:
            obs["jdwp"] = {"attached": False, "error": e.to_dict()}
            return obs
        obs["jdwp"] = {"attached": True,
                       "vm": client.handshake_info.get("vm_name"),
                       "jdwp": f"{client.handshake_info.get('jdwp_major')}."
                               f"{client.handshake_info.get('jdwp_minor')}"}
        obs["runtime_line_table"] = _probe_line_table(client, project)
    except ApkDbgError as e:
        obs["jdwp"] = {"attached": "unknown", "error": e.to_dict()}
    finally:
        if client is not None:
            client.close()
        if port:
            adb.remove_forward(port)
    return obs


def _probe_line_table(client: JdwpClient, project, sample: int = 5) -> dict:
    """Observe Method.LineTable availability for a few indexed classes.
    Scans beyond the first rows (library classes are often not loaded),
    preferring the app package, until `sample` loaded classes are found."""
    pkg = (project.state().get("package") or "").replace(".", "/")
    with project.db() as db:
        rows = db.query(
            "SELECT c.sig FROM classes c JOIN methods m ON m.class_id=c.id "
            "WHERE m.is_native=0 GROUP BY c.id "
            "ORDER BY (c.sig LIKE ?) DESC LIMIT 200",
            (f"L{pkg}%",))
    sampled = with_lines = 0
    for row in rows:
        if sampled >= sample:
            break
        try:
            classes = client.classes_by_signature(row["sig"])
            if not classes:
                continue
            tid = classes[0]["type_id"]
            observed = False
            for m in client.rt_methods(tid)[:5]:
                if m.get("mod_bits", 0) & 0x0500:  # native | abstract
                    continue
                try:
                    lt = client.method_line_table(tid, m["id"])
                except ApkDbgError as e:
                    log_progress(
                        f"line-table probe: {row['sig']}.{m['name']}: {e}")
                    continue
                observed = True
                if lt["lines"]:
                    with_lines += 1
                    break
            if not observed:
                continue
            sampled += 1
        except ApkDbgError as e:
            log_progress(f"line-table probe: {row['sig']}: {e}")
    if not sampled:
        availability = "unknown"
    elif with_lines:
        availability = "present"
    else:
        availability = "absent"
    return {"observed": True, "classes_sampled": sampled,
            "classes_with_line_tables": with_lines,
            "availability": availability}


def _fold_probe(caps: dict, obs: dict) -> None:
    """Fold transient observations into runtime capabilities (source becomes
    'observed'); persistent static facts are untouched."""
    dev = obs.get("device") or {}
    if dev.get("present") is False:
        caps["connect"] = _cap(
            "unsupported", "observed", {"device": "absent"},
            "no device at observation time — transient state, retry with a "
            "device attached")
    jdwp = obs.get("jdwp") or {}
    if jdwp.get("attached") is True:
        caps["jdwp_attach"] = _cap("supported", "observed",
                                   {k: jdwp[k] for k in ("vm", "jdwp") if k in jdwp})
        caps["connect"] = _cap("supported", "observed",
                               {"jdwp_attach": True})
    elif jdwp.get("attached") is False:
        caps["jdwp_attach"] = _cap("unsupported", "observed",
                                   {"error": jdwp.get("error")},
                                   "JDWP handshake refused at observation "
                                   "time — app may be non-debuggable or a "
                                   "previous debugger detached uncleanly")
    rlt = obs.get("runtime_line_table") or {}
    if rlt.get("observed"):
        av = rlt["availability"]
        caps["runtime_line_table"] = _cap(
            {"present": "supported", "absent": "unsupported"}.get(av, "unknown"),
            "observed", rlt)

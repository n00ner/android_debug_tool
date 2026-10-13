"""Versioned, machine-readable command catalog (issue #33).

For every public command the catalog exposes: name, version, parameter
schema (name/type/required/default/description), a result description,
pagination metadata where applicable, whether the call mutates target
state, project/session requirements, and retry properties (idempotent,
retryable). Entries are built by introspecting the signatures in
``commands.COMMANDS`` and enriching them with the ``_META`` overlay below,
so the catalog can never drift from the dispatch table.

Two protocol methods — ``describe`` (this catalog, whole or per-command)
and ``capabilities`` (per-command availability states) — work WITHOUT an
initialized project or a connected device. Capability states:

  supported                   callable right now in this session
  unavailable_in_this_session needs a live JDWP session (run `connect`)
  unverified_runtime          scaffolded; depends on runtime behavior that
                              has not been verified against a device
"""

from __future__ import annotations

import inspect
import types
import typing

from .. import __version__
from ..commands import COMMANDS, MAX_PAGE
from ..errors import InvalidParamsError

CATALOG_VERSION = 1
COMMAND_VERSION = 1

PROTOCOL_VERSIONS = ["1.0", "2.0"]  # 1.0 = legacy envelope, 2.0 = JSON-RPC
DEFAULT_PROTOCOL_VERSION = "1.0"    # requests without a "jsonrpc" member

# Commands whose usefulness depends on runtime behavior not yet verified
# against a device (scaffolds / roadmap surface).
_RUNTIME_UNVERIFIED = {"native"}

# Command metadata overlay; introspection supplies names/types/defaults.
_META: dict[str, dict] = {
    "init": {
        "summary": "decompile an APK and build the mapping DB",
        "result": "project state: package, output paths, tool versions",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": False, "session": False,
        "params": {"apk": "path to the target APK",
                   "out": "project output directory",
                   "skip_apktool": "reuse existing apktool output",
                   "skip_jadx": "reuse existing jadx output"},
    },
    "classes": {
        "summary": "search classes in the mapping DB",
        "result": "{\"classes\": [...], count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"filter": "substring match on (deobfuscated) FQCN"},
    },
    "methods": {
        "summary": "list methods of a class",
        "result": "{\"methods\": [...], count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"class_": "FQCN, deobfuscated FQCN, or runtime sig"},
    },
    "res": {
        "summary": "look up resources by name substring or exact id",
        "result": "{\"resource\": {...}} for id lookups, else "
                  "{\"resources\": [...], count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"name": "substring match on resource name",
                   "id": "resource id, decimal or 0x-prefixed hex"},
    },
    "res_refs": {
        "summary": "call sites of a resource id in smali",
        "result": "{\"res_id\": hex, \"refs\": [...], "
                  "count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"id": "resource id, decimal or 0x-prefixed hex"},
    },
    "capabilities": {
        "summary": "offline capability matrix for this project/APK; "
                   "probe=true adds live device/runtime observations",
        "result": "capability states with index facts and reasons",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False,
        "params": {"probe": "also probe the live device/runtime"},
    },
    "connect": {
        "summary": "attach JDWP to the app (optionally launch it first)",
        "result": "session info: pkg, pid, port, handshake metadata",
        "mutates": True, "idempotent": False, "retryable": True,
        "project": True, "session": False,
        "params": {"pkg": "package name; defaults to project state",
                   "launch": "force-start the app before attaching",
                   "activity": "activity to launch (default: launcher)",
                   "timeout": "adb/JDWP attach timeout in seconds",
                   "recovery": "escalation policy; omit for session-scoped "
                               "recovery only, \"kill-server\" explicitly "
                               "allows a global adb server restart"},
    },
    "restore": {
        "summary": "re-install symbolic breakpoint/hook definitions after "
                   "a reconnect or process restart (issue #32)",
        "result": "{\"epoch\", installed (NEW request ids) / pending / "
                  "failed / deferred}; old ids are never revived",
        "mutates": True, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"defer": "also arm CLASS_PREPARE auto-install for "
                            "hooks whose class is not loaded yet"},
    },
    "bp": {
        "summary": "set a breakpoint: com.foo.Class.method:42",
        "result": "breakpoint record with JDWP request_id and location",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"spec": "java class[:method]:line breakpoint spec"},
    },
    "bp_del": {
        "summary": "clear a breakpoint/event request by id",
        "result": "clear confirmation with the resolved request kind",
        "mutates": True, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"request_id": "JDWP request id returned by bp"},
    },
    "bp_list": {
        "summary": "list live breakpoints/event requests of this session",
        "result": "{\"breakpoints\": [...], "
                  "count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": True, "pagination": True,
    },
    "events": {
        "summary": "wait for debug events (breakpoint hits, steps, ...)",
        "result": "composite event set; suspensions belong to the caller",
        "mutates": False, "idempotent": False, "retryable": True,
        "project": True, "session": True,
        "params": {"timeout": "max seconds to wait; retries are the "
                              "normal polling pattern"},
    },
    "read_var": {
        "summary": "read a local variable / slot of a suspended thread",
        "result": "{\"name\", \"slot\", \"tag\", \"v\"} per variable",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id of a suspended thread",
                   "name": "variable name (else all visible vars)",
                   "slot": "dalvik register slot (alternative to name)",
                   "frame": "stack frame index, 0 = top"},
    },
    "write_var": {
        "summary": "mutate a local variable of a suspended thread",
        "result": "write confirmation echoing slot/tag/value",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id of a suspended thread",
                   "value": "JSON value to write (null allowed)",
                   "name": "variable name", "slot": "register slot",
                   "frame": "stack frame index, 0 = top",
                   "vtype": "target type tag (int/boolean/...); inferred "
                            "from the slot when omitted"},
    },
    "invoke": {
        "summary": "force-invoke a method on a live object",
        "result": "{\"result\": tagged value} or raised exception info",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id of a suspended thread",
                   "obj": "object id (from read_var/snapshot)",
                   "method": "method name", "sig": "JNI-style signature",
                   "args": "JSON argument list"},
    },
    "step": {
        "summary": "single-step a suspended thread",
        "result": "step event with the new location",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id",
                   "kind": "into | over | out",
                   "timeout": "seconds to wait for the step event"},
    },
    "resume": {
        "summary": "resume one thread or the whole VM",
        "result": "resume confirmation",
        "mutates": True, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id; omit to resume all"},
    },
    "snapshot": {
        "summary": "budget-capped snapshot of a thread's top frame",
        "result": "frame variable tree with explicit trunc markers; with "
                  "record=true also run_id/artifact_id; additive \"alias\" "
                  "field carries the accepted runtime alias of the frame "
                  "class (issue #25)",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"thread": "JDWP thread id of a suspended thread",
                   "depth": "max object-graph depth",
                   "record": "persist as an artifact under a run manifest",
                   "run_id": "existing run to attach the artifact to",
                   "scenario": "scenario label for a new run",
                   "collect_aliases": "feed captured strings to the alias "
                                      "collector (implies record)"},
    },
    "dump_object": {
        "summary": "budget-capped dump of an object graph",
        "result": "object tree with explicit trunc markers; with "
                  "record=true also run_id/artifact_id; additive \"alias\" "
                  "field carries the accepted runtime alias (issue #25)",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": True,
        "params": {"obj": "object id", "depth": "max graph depth",
                   "record": "persist as an artifact under a run manifest",
                   "run_id": "existing run to attach the artifact to",
                   "scenario": "scenario label for a new run",
                   "collect_aliases": "feed captured strings to the alias "
                                      "collector (implies record)"},
    },
    "cond": {
        "summary": "host-side conditional breakpoint: capture -> evaluate "
                   "-> resume until the predicate matches",
        "result": "match record with captured values, or budget/timeout "
                  "exhaustion report; with collect_aliases also an "
                  "alias_collection report (issue #25)",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"spec": "breakpoint spec",
                   "pred": "JSON predicate over captured labels",
                   "capture": "JSON capture spec (slots/fields)",
                   "max_events": "safety bound on evaluated hits",
                   "timeout": "safety bound in seconds",
                   "collect_aliases": "feed captured strings to the alias "
                                      "collector"},
    },
    "hook_crypto": {
        "summary": "watch javax.crypto/javax.mac calls for N seconds",
        "result": "captured crypto records (keys, plaintexts, ivs) with "
                  "budget/truncation metadata; with collect_aliases also "
                  "an alias_collection report with measured JDWP reads "
                  "and added pause time (issue #25)",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"duration": "watch window in seconds",
                   "hooks": "hook names to install (default: all)",
                   "returns": "also capture method-exit return values",
                   "max_events": "safety bound on captured events",
                   "max_bytes": "safety bound on captured payload bytes",
                   "defer": "auto-install hooks when their class loads",
                   "record": "persist the watch as a run manifest",
                   "scenario": "scenario label for the run",
                   "collect_aliases": "feed captured strings to the alias "
                                      "collector (implies record)"},
    },
    "watch_strings": {
        "summary": "scoped string watchers (issue #26): producer-return "
                   "and consumer-argument observation points via method-exit "
                   "events, with explicit best_effort/attributed capture "
                   "modes — observation points only, never full string "
                   "coverage",
        "result": "captured string records with attribution status, "
                  "received/filtered/matched/unavailable/truncated/dropped "
                  "counts, stop reason, and a coverage note; with "
                  "collect_aliases also an alias_collection report",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"duration": "watch window in seconds",
                   "profiles": "builtin names and/or explicit "
                               "{\"cls\",\"method\",\"sig\"} objects "
                               "(default: stringbuilder.tostring)",
                   "mode": "best_effort (SP_NONE, no attribution, object "
                           "loss counted) | attributed (SP_EVENT_THREAD, "
                           "string + bounded stack while suspended)",
                   "scope": "app scope for attribution, JDWP class-match "
                            "pattern, e.g. com.example.*",
                   "text_regex": "keep only matching texts (applied AFTER "
                                 "the text read)",
                   "min_printable": "min printable-char ratio 0..1 "
                                    "(post-read filter)",
                   "dedupe": "value-based session dedupe of identical texts",
                   "max_events": "safety bound on emitted records",
                   "max_reads": "safety bound on JDWP reads issued by "
                                "extraction",
                   "max_output_bytes": "safety bound on captured payload "
                                       "bytes",
                   "max_queue": "stop when unrelated stashed composites "
                                "exceed this (queue pressure)",
                   "max_stack": "stack depth bound for attribution",
                   "max_str": "per-string length bound (longer strings are "
                              "truncated and counted)",
                   "thread": "restrict capture to this thread "
                             "(request-level ThreadOnly modifier)",
                   "mod_count": "MOD_COUNT=N: deliver ONE event after N-1 "
                                "earlier matches are skipped — NOT a "
                                "first-N budget",
                   "defer": "CLASS_PREPARE-watch pending profiles and "
                            "auto-install when their class loads",
                   "record": "persist the watch as a run manifest",
                   "scenario": "scenario label for the run",
                   "collect_aliases": "feed captured strings to the alias "
                                      "collector (implies record)"},
    },
    "strings": {
        "summary": "offline query over persisted string-watch records "
                   "(issue #26)",
        "result": "{\"records\": [...], count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"run_id": "restrict to one run",
                   "profile": "restrict to one source profile",
                   "mode": "restrict to one capture mode (run config)",
                   "text": "substring match on captured text"},
    },
    "watch_framework": {
        "summary": "opt-in framework watcher profiles (issue #27): "
                   "navigation requests, SharedPreferences staged edits / "
                   "submissions, and system-service lookups at the hooked "
                   "framework methods — observation points with explicit "
                   "coverage notes, never full-coverage claims",
        "result": "watcher records with attribution status and "
                  "correlation ids, derived per-editor transaction view "
                  "(discarded editors explicit), service lookup counts, "
                  "received/filtered/matched/unavailable counts, stop "
                  "reason, per-profile install states, coverage notes",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"duration": "watch window in seconds",
                   "families": "profile families to enable: navigation | "
                               "storage | services (default: all three)",
                   "profiles": "builtin profile names, family names, "
                               "and/or explicit {\"cls\",\"method\",\"sig\"} "
                               "objects (overrides families)",
                   "mode": "best_effort (SP_NONE, no attribution/args) | "
                           "attributed (SP_EVENT_THREAD, args + bounded "
                           "stack while suspended)",
                   "scope": "app scope for attribution, JDWP class-match "
                            "pattern, e.g. com.example.*",
                   "exclude": "class-match patterns excluded from "
                              "attribution (framework wrappers are never "
                              "reported as app callers)",
                   "invoke_getters": "EXPLICIT opt-in: invoke metadata "
                                     "getters (Intent.getAction/"
                                     "getComponent/...) on the suspended "
                                     "thread — runs application code; "
                                     "off by default",
                   "corr_window_ms": "correlation window for one call "
                                     "traversing several watched methods; "
                                     "0 disables correlation",
                   "max_events": "safety bound on emitted records",
                   "max_reads": "safety bound on JDWP reads issued by "
                                "extraction",
                   "max_output_bytes": "safety bound on captured payload "
                                       "bytes",
                   "max_queue": "stop when unrelated stashed composites "
                                "exceed this (queue pressure)",
                   "max_stack": "stack depth bound for attribution",
                   "max_str": "per-string length bound (longer strings "
                              "are truncated and counted)",
                   "thread": "restrict capture to this thread "
                             "(request-level ThreadOnly modifier)",
                   "mod_count": "MOD_COUNT=N: deliver ONE event after N-1 "
                                "earlier matches are skipped — NOT a "
                                "first-N budget",
                   "defer": "CLASS_PREPARE-watch pending profiles and "
                            "auto-install when their class loads",
                   "record": "persist the watch as a run manifest",
                   "scenario": "scenario label for the run"},
    },
    "framework_events": {
        "summary": "offline query over persisted framework-watch records "
                   "(issue #27)",
        "result": "{\"records\": [...], count/total/limit/offset/truncated}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"run_id": "restrict to one run",
                   "family": "restrict to one profile family",
                   "profile": "restrict to one source profile",
                   "role": "restrict to one role: request | lifecycle | "
                           "staged | submit | lookup"},
    },
    "coverage": {
        "summary": "method- or line-level coverage for the given packages",
        "result": "hit tables with budget/truncation metadata",
        "mutates": True, "idempotent": False, "retryable": False,
        "project": True, "session": True,
        "params": {"packages": "package prefixes to instrument",
                   "mode": "method | line",
                   "thread": "scope line mode to one thread",
                   "budget": "max recorded hits",
                   "seconds": "capture window",
                   "scenario": "scenario label for the run"},
    },
    "runs": {
        "summary": "investigation run manifests: list | get | export | "
                   "import (import writes the project DB)",
        "result": "list: bounded page with count/total/limit/offset; "
                  "get/export: full manifest with events and artifacts",
        "mutates": False, "idempotent": False, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"action": "list | get | export | import",
                   "run_id": "target run for get/export",
                   "file": "export destination / import source path",
                   "kind": "list filter: coverage | snapshot | ...",
                   "replace": "import: overwrite an existing run_id"},
    },
    "snapshot_diff": {
        "summary": "structural diff of two persisted snapshot artifacts",
        "result": "node-level diff with compatibility qualifications",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": False,
        "params": {"a": "artifact id (or run id with one snapshot)",
                   "b": "artifact id (or run id with one snapshot)",
                   "force": "compare despite incompatibilities"},
    },
    "aliases": {
        "summary": "review runtime alias candidates (issue #25): list | "
                   "get | accept | reject | revise | add | export — stored "
                   "separately from deobf/imported mappings, never used "
                   "for resolution or breakpoint targeting",
        "result": "list: bounded page of candidates with "
                  "count/total/limit/offset/truncated; get: candidate with "
                  "decision trail, source events, and smali links; "
                  "accept/reject/revise/add: new status plus superseded "
                  "ids; export: full manifest with decision history",
        "mutates": True, "idempotent": False, "retryable": True,
        "project": True, "session": False, "pagination": True,
        "params": {"action": "list | get | accept | reject | revise | "
                             "add | export",
                   "candidate_id": "target candidate for get/accept/"
                                   "reject/revise",
                   "class_sig": "original runtime descriptor (add, or "
                                "list filter), e.g. Lcom/foo/Bar;",
                   "alias": "alias text for add/revise",
                   "method": "method-scoped alias: method name",
                   "method_sig": "method-scoped alias: descriptor",
                   "status": "list filter: suggested | accepted | "
                             "rejected | superseded",
                   "filter": "list: substring match on candidate/class",
                   "note": "decision note recorded in the trail",
                   "file": "export destination path",
                   "all_apks": "list candidates of every indexed APK"},
    },
    "native": {
        "summary": "native-method inventory + lldb-server orchestration "
                   "plan (scaffold: lldb attach is not implemented)",
        "result": "{\"native_methods\": [...], pagination metadata, "
                  "lldb status and plan}",
        "mutates": False, "idempotent": True, "retryable": True,
        "project": True, "session": True, "pagination": True,
    },
}

# Hand-written entries for the two protocol methods (no COMMANDS entry).
_PROTOCOL_ENTRIES: dict[str, dict] = {
    "describe": {
        "name": "describe", "version": COMMAND_VERSION,
        "summary": "machine-readable catalog of every public command "
                   "(whole catalog, or one command via `command`)",
        "params": [{"name": "command", "type": "string", "required": False,
                    "default": None, "nullable": True,
                    "description": "command name; omit for the full catalog"}],
        "result": "{\"catalog_version\": int, \"commands\": [...]} or one "
                  "command entry",
        "mutates": False, "idempotent": True, "retryable": True,
        "requires": {"project": False, "session": False},
    },
    "capabilities": {
        "name": "capabilities", "version": COMMAND_VERSION,
        "summary": "protocol/catalog versions plus per-command capability "
                   "states for this session",
        "params": [],
        "result": "{\"protocol\": {...}, \"commands\": {name: state}, ...}",
        "mutates": False, "idempotent": True, "retryable": True,
        "requires": {"project": False, "session": False},
    },
}

_TYPE_NAMES = {str: "string", int: "integer", float: "number",
               bool: "boolean", list: "array", dict: "object"}

_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float))
    and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "any": lambda v: True,
}


def _json_type(ann) -> tuple[str, bool]:
    """(JSON type name, nullable) for a Python annotation."""
    if ann is None:
        return "any", False
    nullable = False
    origin = typing.get_origin(ann)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        nullable = len(args) != len(typing.get_args(ann))
        if len(args) != 1:
            return "any", nullable
        ann = args[0]
        origin = typing.get_origin(ann)
    return _TYPE_NAMES.get(origin or ann, "any"), nullable


def _build_entry(name: str, fn) -> dict:
    meta = _META[name]
    hints = typing.get_type_hints(fn)
    params = []
    for pname, p in inspect.signature(fn).parameters.items():
        if pname == "ctx":
            continue
        jtype, nullable = _json_type(hints.get(pname))
        spec: dict = {"name": pname, "type": jtype,
                      "required": p.default is inspect.Parameter.empty}
        if nullable:
            spec["nullable"] = True
        if not spec["required"]:
            spec["default"] = p.default
        desc = meta.get("params", {}).get(pname)
        if desc:
            spec["description"] = desc
        params.append(spec)
    entry = {
        "name": name,
        "version": COMMAND_VERSION,
        "summary": meta["summary"],
        "params": params,
        "result": meta["result"],
        "mutates": meta["mutates"],
        "idempotent": meta["idempotent"],
        "retryable": meta["retryable"],
        "requires": {"project": meta["project"], "session": meta["session"]},
    }
    if meta.get("pagination"):
        entry["pagination"] = {"params": ["limit", "offset"],
                               "max_limit": MAX_PAGE,
                               "metadata": ["count", "total", "limit",
                                            "offset", "truncated"]}
    if name in _RUNTIME_UNVERIFIED:
        entry["runtime_unverified"] = True
    return entry


def entry_for(name: str) -> dict | None:
    """Catalog entry for a command or protocol method, or None. A command
    shadows a same-named protocol method (the command is the richer,
    parameter-bearing surface)."""
    fn = COMMANDS.get(name)
    if fn is not None:
        return _build_entry(name, fn)
    return _PROTOCOL_ENTRIES.get(name)


def catalog() -> dict:
    """The full catalog: every COMMANDS entry plus the protocol methods."""
    entries = [_build_entry(name, fn) for name, fn in COMMANDS.items()]
    entries += [e for name, e in _PROTOCOL_ENTRIES.items()
                if name not in COMMANDS]
    return {"catalog_version": CATALOG_VERSION, "tool_version": __version__,
            "commands": entries}


def describe(command: str | None = None) -> dict:
    """`describe` protocol method: full catalog or one command's entry."""
    if command is None:
        return catalog()
    entry = entry_for(command)
    if entry is None:
        raise InvalidParamsError(
            f"no such command {command!r}",
            hint="call describe without params for the full catalog")
    return entry


def capabilities(session_live: bool) -> dict:
    """`capabilities` protocol method: per-command availability states."""
    states = {}
    for entry in catalog()["commands"]:
        name = entry["name"]
        if entry.get("runtime_unverified"):
            states[name] = "unverified_runtime"
        elif entry["requires"]["session"] and not session_live:
            states[name] = "unavailable_in_this_session"
        else:
            states[name] = "supported"
    return {
        "tool_version": __version__,
        "catalog_version": CATALOG_VERSION,
        "protocol": {"versions": PROTOCOL_VERSIONS,
                     "default": DEFAULT_PROTOCOL_VERSION,
                     "jsonrpc": "2.0"},
        "session": {"live": session_live},
        "capability_states": ["supported", "unavailable_in_this_session",
                              "unverified_runtime"],
        "commands": states,
        "features": {
            "method_exit_return_capture": "unverified_runtime",
            "native_lldb_dual_debug": "unverified_runtime",
            "resource_getidentifier_watch": "unverified_runtime",
        },
    }


def _type_ok(v, spec: dict) -> bool:
    if v is None:
        return spec["type"] == "any" or spec.get("nullable", False)
    return _CHECKS[spec["type"]](v)


def validate_params(entry: dict, params: dict) -> dict:
    """Validate call params against a catalog entry; returns the kwargs to
    dispatch. Deterministic: first unknown name, then declaration order.
    Raises InvalidParamsError before any project/session context exists."""
    specs = entry["params"]
    unknown = sorted(set(params) - {p["name"] for p in specs})
    if unknown:
        raise InvalidParamsError(
            f"unknown params for {entry['name']}: {', '.join(unknown)}",
            hint="valid: "
                 + (", ".join(p["name"] for p in specs) or "(none)"))
    kwargs = {}
    for p in specs:
        if p["name"] in params:
            v = params[p["name"]]
            if not _type_ok(v, p):
                want = p["type"] + (" or null" if p.get("nullable") else "")
                raise InvalidParamsError(
                    f"param {p['name']!r} of {entry['name']} must be "
                    f"{want}, got {type(v).__name__}")
            kwargs[p["name"]] = v
        elif p["required"]:
            raise InvalidParamsError(
                f"missing required param {p['name']!r} of {entry['name']}")
    return kwargs

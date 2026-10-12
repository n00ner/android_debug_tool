"""Runtime DEX payload discovery at Java-visible loading/decryption
boundaries (issue #28).

This is an EXPERIMENTAL workflow, not a universal unpacker. It observes
selected boundaries:

  InMemoryDexClassLoader.<init>(ByteBuffer, ClassLoader)
  InMemoryDexClassLoader.<init>(ByteBuffer[], ClassLoader)
      consumed bytes are each buffer's [position, limit) window, exported
      through the #38 BufferExporter capabilities: heap buffers, slices,
      read-only views, and direct/native buffers have DISTINCT support —
      unsupported buffers produce a capability outcome, never empty data
      presented as a dump. On ART the single-buffer constructor delegates
      to the array constructor, so one construction can produce one
      observation at EACH boundary (verified on Android 15).
  DexClassLoader.<init>(String, String, String, ClassLoader)
      receives file PATHS, not memory: reported as loader/file path
      evidence only; no memory recovery is promised from this boundary.
  Cipher.doFinal(...) — only overloads EXPLICITLY selected via
      cipher_overloads. The return byte[] (decryption output) is the
      candidate; entry events contribute algorithm context via field reads
      (no invokes: class-scoped exit requests are armed, see crypto.py).

Candidate pipeline per buffer: bounded prefix read -> DEX magic + header
validation (recognized version, header/file sizes, endian tag, section
offset/length bounds) -> bounded full export -> full validation on the
completed artifact (file size, Adler-32 checksum, SHA-1 signature).
Magic-only match is a CANDIDATE, never a recovered executable. Shannon
entropy is recorded as optional evidence only: it neither promotes a
candidate nor rejects a valid DEX.

Outcomes are reported DISTINCTLY (never silently merged):
  validated | candidate | invalid | truncated | incomplete |
  unsupported | not_dex | empty | path_evidence | error
Complete artifacts are deduplicated by content SHA-256 while every
observation is retained. No payload bytes are ever inlined into records —
only hashes, paths, and metadata.

Consistency: captures run at SP_EVENT_THREAD stops owned by the
dispatcher lease (released exactly once after export/error/cancel).
Suspending the event thread does NOT freeze other writers; the exported
bytes are not an atomic snapshot (see buffers.CONSISTENCY_NOTE, carried
into every artifact's metadata).

Explicit follow-up: a validated artifact can be registered as an
additional project artifact (register_artifact / `unpack_index`) into the
observation-only runtime_artifacts table, preserving hash + origin; the
original APK static index is never touched or replaced.
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
import zlib
from pathlib import Path

from ..core.manifests import RunStore, capture_environment, index_generation
from ..device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, TAG_STRING,
)
from ..errors import (
    CapabilityError, ExportIncompleteError, SessionError,
)
from ..protocol import log_progress
from . import buffers
from .capture import arg_vreg_map, read_fields
from .hooks.crypto import ClassNotLoaded, MethodNotFound, UnsupportedHook

# --------------------------------------------------------------------- hooks
IMDCL_CLS = "Ldalvik/system/InMemoryDexClassLoader;"
DCL_CLS = "Ldalvik/system/DexClassLoader;"
CIPHER_CLS = "Ljavax/crypto/Cipher;"

BOUNDARY_HOOKS: list[dict] = [
    {"name": "InMemoryDexClassLoader.<init>(ByteBuffer)",
     "cls": IMDCL_CLS, "method": "<init>",
     "sig": "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
     "boundary": "in_memory_dex_class_loader",
     "capture": [{"slot": 1, "kind": "bytebuffer"}]},
    {"name": "InMemoryDexClassLoader.<init>(ByteBuffer[])",
     "cls": IMDCL_CLS, "method": "<init>",
     "sig": "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
     "boundary": "in_memory_dex_class_loader",
     "capture": [{"slot": 1, "kind": "bytebuffer[]"}]},
    {"name": "DexClassLoader.<init>(String,String,String,ClassLoader)",
     "cls": DCL_CLS, "method": "<init>",
     "sig": "(Ljava/lang/String;Ljava/lang/String;"
            "Ljava/lang/String;Ljava/lang/ClassLoader;)V",
     "boundary": "dex_class_loader_path", "evidence": "path_only",
     "capture": [{"slot": 1, "kind": "string", "label": "dex_path"},
                 {"slot": 2, "kind": "string", "label": "optimized_dir"},
                 {"slot": 3, "kind": "string",
                  "label": "library_search_path"}]},
]

# Cipher boundaries are OPT-IN: selected explicitly by overload name.
CIPHER_HOOKS: dict[str, dict] = {
    "Cipher.doFinal(byte[])": {
        "name": "Cipher.doFinal(byte[])", "cls": CIPHER_CLS,
        "method": "doFinal", "sig": "([B)[B", "boundary": "cipher_dofinal",
        "returns": True},
    "Cipher.doFinal(byte[],int,int)": {
        "name": "Cipher.doFinal(byte[],int,int)", "cls": CIPHER_CLS,
        "method": "doFinal", "sig": "([BII)[B", "boundary": "cipher_dofinal",
        "returns": True},
    "Cipher.doFinal()": {
        "name": "Cipher.doFinal()", "cls": CIPHER_CLS,
        "method": "doFinal", "sig": "()[B", "boundary": "cipher_dofinal",
        "returns": True},
}

FLD_TRANSFORMATION = {"name": "transformation", "label": "algorithm"}

# ------------------------------------------------------------------ defaults
PREFIX_BYTES = 4096                 # bounded prefix read before any export
DEFAULT_MAX_EVENTS = 200
DEFAULT_MAX_CANDIDATES = 25
DEFAULT_MAX_CANDIDATE_BYTES = 16 << 20
DEFAULT_MAX_RUN_BYTES = 64 << 20
MAX_BUFFER_ARRAY_ELEMENTS = 64      # ByteBuffer[] elements inspected per hit
MAX_CIPHER_CONTEXT = 128            # retained entry contexts (thread -> ctx)

OUTCOMES = ("validated", "candidate", "invalid", "truncated",
            "incomplete", "unsupported", "not_dex", "empty",
            "path_evidence", "error")

CONSISTENCY_NOTE = buffers.CONSISTENCY_NOTE

# ------------------------------------------------------------- DEX structure
DEX_MAGIC = b"dex\n"
RECOGNIZED_VERSIONS = ("035", "036", "037", "038", "039", "040", "041")
HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678
REVERSE_ENDIAN_TAG = 0x78563412
# name, size offset, entry size (offset field follows the size field)
_SECTIONS = (("string_ids", 0x38, 4), ("type_ids", 0x40, 4),
             ("proto_ids", 0x48, 12), ("field_ids", 0x50, 8),
             ("method_ids", 0x58, 8), ("class_defs", 0x60, 32))


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def shannon_entropy(data: bytes) -> float:
    """Optional evidence only (see module docstring): never gates a
    candidate, never rejects a valid DEX."""
    if not data:
        return 0.0
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def dex_header_check(prefix: bytes) -> dict:
    """Structural validation of a bounded prefix (>= HEADER_SIZE needed for
    field checks) against the DEX header spec. Magic + recognized version,
    header/file sizes, endian tag, and every present id/data section's
    offset+length bounds against the DECLARED file_size. A failure is a
    decisive rejection of the candidate — never exported as a dump."""
    out: dict = {"result": "invalid", "errors": []}
    errors = out["errors"]
    if len(prefix) < 4 or prefix[:4] != DEX_MAGIC:
        errors.append("no DEX magic")
        return out
    if len(prefix) < 8:
        errors.append("prefix shorter than the 8-byte magic")
        return out
    try:
        version = prefix[4:7].decode("ascii")
    except UnicodeDecodeError:
        version = ""
    if prefix[7] != 0 or version not in RECOGNIZED_VERSIONS:
        errors.append(f"unrecognized DEX version {version!r}")
        return out
    out["version"] = version
    if len(prefix) < HEADER_SIZE:
        errors.append(f"prefix of {len(prefix)} bytes is shorter than the "
                      f"{HEADER_SIZE}-byte header; structure unverifiable")
        return out

    file_size = _u32(prefix, 0x20)
    header_size = _u32(prefix, 0x24)
    endian = _u32(prefix, 0x28)
    map_off = _u32(prefix, 0x34)
    data_size = _u32(prefix, 0x68)
    data_off = _u32(prefix, 0x6C)
    out.update({"file_size": file_size, "header_size": header_size,
                "endian_tag": f"0x{endian:08x}", "map_off": map_off,
                "data_off": data_off, "data_size": data_size})
    if header_size != HEADER_SIZE:
        errors.append(f"header_size is {header_size}, expected {HEADER_SIZE}")
    if file_size < header_size:
        errors.append(f"file_size {file_size} < header_size {header_size}")
    if endian == REVERSE_ENDIAN_TAG:
        errors.append("reverse-endian (big-endian) DEX is unsupported")
    elif endian != ENDIAN_TAG:
        errors.append(f"endian tag 0x{endian:08x} is neither standard "
                      f"(0x{ENDIAN_TAG:08x}) nor reverse-endian")
    sections = {}
    for name, size_off, entry in _SECTIONS:
        size = _u32(prefix, size_off)
        off = _u32(prefix, size_off + 4)
        sections[name] = {"size": size, "off": off}
        if not size:
            continue
        if off < HEADER_SIZE:
            errors.append(f"{name}: offset {off} < header end {HEADER_SIZE}")
        elif off + size * entry > file_size:
            errors.append(f"{name}: [{off}, {off + size * entry}) escapes "
                          f"file_size {file_size}")
    out["sections"] = sections
    if map_off and not HEADER_SIZE <= map_off < file_size:
        errors.append(f"map_off {map_off} outside "
                      f"[{HEADER_SIZE}, {file_size})")
    if data_size:
        if data_off < HEADER_SIZE or data_off + data_size > file_size:
            errors.append(f"data section [{data_off}, "
                          f"{data_off + data_size}) escapes file_size "
                          f"{file_size}")
    if not errors:
        out["result"] = "valid"
    return out


def dex_full_check(data: bytes) -> dict:
    """Full validation of a completed export: header structure, declared
    file size vs captured length, Adler-32 checksum, SHA-1 signature.
    Trailing bytes beyond file_size are excluded from validation and
    reported; fewer bytes than file_size is a truncated capture, never
    byte identity."""
    out = dex_header_check(data)
    if out["result"] != "valid":
        return out
    file_size = out["file_size"]
    out["captured"] = len(data)
    if len(data) < file_size:
        out["result"] = "invalid"
        out["errors"].append(f"captured {len(data)} bytes < file_size "
                             f"{file_size}: truncated capture")
        return out
    body = data[:file_size]
    if len(data) > file_size:
        out["trailing_bytes"] = len(data) - file_size
    checksum = _u32(body, 0x08)
    if zlib.adler32(body[12:]) != checksum:
        out["result"] = "invalid"
        out["errors"].append("Adler-32 checksum mismatch")
    signature = body[0x0C:0x20]
    if hashlib.sha1(body[32:]).digest() != signature:
        out["result"] = "invalid"
        out["errors"].append("SHA-1 signature mismatch")
    return out


def assess_prefix(prefix: bytes) -> dict:
    """Classify a bounded prefix: empty | not_dex | candidate (magic match;
    header validation decides candidate vs invalid downstream). Entropy is
    attached as non-gating evidence."""
    ev = {"entropy": round(shannon_entropy(prefix), 4),
          "entropy_note": "evidence only: neither proves decryption/"
                          "executable content nor rejects a valid DEX"}
    if not prefix:
        return {"kind": "empty", "evidence": ev}
    if prefix[:4] != DEX_MAGIC:
        ev["prefix_hex"] = prefix[:16].hex()
        return {"kind": "not_dex", "evidence": ev}
    return {"kind": "candidate", "evidence": ev,
            "header": dex_header_check(prefix)}


# ------------------------------------------------------------------- install
def _hooks_for(boundaries: list[str] | None,
               cipher_overloads: list[str] | None) -> list[dict]:
    if boundaries is None:
        boundaries = ["in_memory_dex_class_loader"]
    hooks = [h for h in BOUNDARY_HOOKS if h["boundary"] in boundaries
             or h["name"] in boundaries]
    for name in cipher_overloads or []:
        hook = CIPHER_HOOKS.get(name)
        if hook is None:
            raise SessionError(
                f"unknown Cipher.doFinal overload {name!r}",
                hint="supported: " + ", ".join(sorted(CIPHER_HOOKS)))
        hooks.append(hook)
    return hooks


def install(session, boundaries: list[str] | None = None,
            cipher_overloads: list[str] | None = None,
            defer: bool = False) -> dict:
    """Register entry breakpoints (+ class-scoped method-exit for selected
    Cipher overloads) for every selected boundary. Same state model as the
    crypto hooks: installed / pending (deferrable) / not-found /
    unsupported / failed, idempotent per (hook, type_id, phase)."""
    d = session.events
    installed, pending, deferred = [], [], []
    states = {}
    for hook in _hooks_for(boundaries, cipher_overloads):
        try:
            regs = _install_one(session, hook)
        except ClassNotLoaded as e:
            states[hook["name"]] = "pending"
            pending.append({"hook": hook["name"], "state": "pending",
                            "reason": str(e)[:120]})
            if defer:
                rid = d.defer_hook(
                    "unpack", hook["name"], _class_pattern(hook["cls"]),
                    _make_on_prepare(session, hook),
                    symbolic={"owner": "unpack", "hook": hook["name"],
                              "hook_def": hook})
                deferred.append({"hook": hook["name"], "request_id": rid})
            continue
        except (MethodNotFound, UnsupportedHook) as e:
            state = ("not-found" if isinstance(e, MethodNotFound)
                     else "unsupported")
            states[hook["name"]] = state
            pending.append({"hook": hook["name"], "state": state,
                            "reason": str(e)[:120]})
            continue
        except Exception as e:
            states[hook["name"]] = "failed"
            pending.append({"hook": hook["name"], "state": "failed",
                            "reason": str(e)[:120]})
            continue
        states[hook["name"]] = "installed"
        installed.append({"hook": hook["name"],
                          "request_ids": [r["rid"] for r in regs]})
    return {"installed": installed, "pending": pending,
            "deferred": deferred, "states": states}


def _install_one(session, hook: dict,
                 only_type_ids: set[int] | None = None) -> list[dict]:
    c = session.client
    classes = c.classes_by_signature(hook["cls"])
    if not classes:
        raise ClassNotLoaded(f"{hook['cls']} not loaded")
    live = {rid: m for rid, m in session.bp_registry.items()
            if m.get("owner") == "unpack" and m.get("hook") == hook["name"]
            and session.events.is_live(m)}
    done = {(m["type_id"], m["phase"]) for m in live.values()}
    regs = [{"rid": rid, "kind": m["kind"], "phase": m["phase"],
             "type_id": m["type_id"], "method_id": m["method_id"],
             "vregs": m.get("vregs")}
            for rid, m in live.items()]
    new = []
    try:
        for cls in classes:
            tid = cls["type_id"]
            if only_type_ids is not None and tid not in only_type_ids:
                continue
            want_exit = hook.get("returns") and (tid, "return") not in done
            if (tid, "entry") in done and not want_exit:
                continue
            m = next((m for m in c.rt_methods(tid)
                      if m["name"] == hook["method"]
                      and m["sig"] == hook["sig"]), None)
            if not m:
                raise MethodNotFound(
                    f"{hook['method']}{hook['sig']} not found")
            if m.get("mod_bits", 0) & 0x0100:
                raise UnsupportedHook(
                    f"{hook['method']}{hook['sig']} is native")
            try:
                lt = c.method_line_table(tid, m["id"])
                idx = lt["lines"][0]["index"] if lt["lines"] else 0
            except Exception:
                idx = 0
            vregs = arg_vreg_map(c, tid, m["id"])
            try:
                loader = c.rt_class_loader(tid)
            except Exception:
                loader = None
            if (tid, "entry") not in done:
                rid = c.set_breakpoint(tid, m["id"], idx, SP_EVENT_THREAD)
                new.append({"rid": rid, "kind": EVK_BREAKPOINT,
                            "phase": "entry", "type_id": tid,
                            "method_id": m["id"], "vregs": vregs,
                            "loader": loader})
            if want_exit:
                rid = c.set_event(
                    EVK_METHOD_EXIT_RET, SP_EVENT_THREAD,
                    [c.mod_class_only(tid)])
                new.append({"rid": rid, "kind": EVK_METHOD_EXIT_RET,
                            "phase": "return", "type_id": tid,
                            "method_id": m["id"], "vregs": vregs,
                            "loader": loader})
    except Exception:
        for r in new:
            try:
                c.clear_event(r["kind"], r["rid"])
            except Exception:
                pass
        raise
    for r in new:
        session.events.register(r["rid"], {
            "owner": "unpack", "hook": hook["name"], "hook_def": hook,
            "entry": "hook", "kind": r["kind"], "phase": r["phase"],
            "cls": hook["cls"], "type_id": r["type_id"],
            "loader": r["loader"], "method": hook["method"],
            "sig": hook["sig"], "method_id": r["method_id"],
            "vregs": r["vregs"],
            "spec": hook["method"] + hook["sig"]})
    return regs + new


def _class_pattern(sig: str) -> str:
    return sig[1:-1].replace("/", ".") if sig.startswith("L") else sig


def _make_on_prepare(session, hook: dict):
    def on_prepare(ev: dict, handler: dict) -> None:
        regs = _install_one(session, hook,
                            only_type_ids={ev.get("type_id")})
        handler["installed_rids"].extend(r["rid"] for r in regs)
    return on_prepare


# --------------------------------------------------------------- run context
class RunContext:
    """Per-watch budgets and artifact bookkeeping shared by every boundary
    event of one run. Enforces candidate-size, per-run bytes, candidate
    count, and event limits; all counters land in the run summary."""

    def __init__(self, session, *, max_events=DEFAULT_MAX_EVENTS,
                 max_candidates=DEFAULT_MAX_CANDIDATES,
                 max_candidate_bytes=DEFAULT_MAX_CANDIDATE_BYTES,
                 max_run_bytes=DEFAULT_MAX_RUN_BYTES,
                 prefix_bytes=PREFIX_BYTES, export_dir=None, cancel=None):
        self.session = session
        self.max_events = max_events
        self.max_candidates = max_candidates
        self.max_candidate_bytes = max_candidate_bytes
        self.max_run_bytes = max_run_bytes
        self.prefix_bytes = prefix_bytes
        self.export_dir = Path(export_dir) if export_dir else None
        self.cancel = cancel
        self.records: list[dict] = []
        self.candidates = 0
        self.exported_bytes = 0
        self.seen: dict[str, dict] = {}   # sha256 -> first artifact ref
        self.budget_exceeded: str | None = None  # stop reason once hit

    def over_event_budget(self) -> bool:
        return len(self.records) >= self.max_events


# -------------------------------------------------------- candidate pipeline
def process_buffer(session, ctx: RunContext, obj: int, *,
                   source: str, hook: dict, thread: int,
                   meta_extra: dict | None = None) -> dict:
    """Run one ByteBuffer/byte[] handle through the candidate pipeline and
    return its observation record (never raises for per-buffer failures:
    capability, incomplete, and error outcomes are records, not run
    failures). Pure reads only; the caller owns the suspended thread."""
    rec = {"kind": "unpack_observation", "boundary": hook["boundary"],
           "hook": hook["name"], "thread": thread, "source_kind": source,
           "handle": obj}
    if meta_extra:
        rec.update(meta_extra)
    c = session.client
    epoch = session.events.epoch
    try:
        plan = buffers.BufferExporter(
            c, max_bytes=ctx.max_candidate_bytes)._resolve(
            obj, source, None, None)
    except CapabilityError as e:
        rec.update(outcome="unsupported",
                   capability={"reason": e.context.get("reason"),
                               "message": str(e)[:200]})
        return _emit(ctx, rec)
    window = plan["range"]["length"]
    rec["buffer"] = {"window": window,
                     "class_sig": plan["source"].get("class_sig")}
    if window == 0:
        rec.update(outcome="empty")
        return _emit(ctx, rec)

    # bounded prefix read (never more than prefix_bytes, never the window)
    n = min(ctx.prefix_bytes, window)
    try:
        items = c.array_get_values(plan["array_handle"],
                                   plan["backing_offset"], n)["items"]
        prefix = bytes(v & 0xFF if isinstance(v, int)
                       else v["v"] & 0xFF for v in items)
    except Exception as e:
        rec.update(outcome="error", error=f"prefix read: {str(e)[:160]}")
        return _emit(ctx, rec)
    assess = assess_prefix(prefix)
    rec["evidence"] = assess["evidence"]
    if assess["kind"] != "candidate":
        rec.update(outcome=assess["kind"])
        return _emit(ctx, rec)

    header = assess["header"]
    rec["header"] = header
    if header["result"] != "valid":
        # magic matched but the structure is decisively broken: rejected
        # as a candidate, never exported as a dump
        rec.update(outcome="invalid", errors=header["errors"])
        return _emit(ctx, rec)

    expected = header["file_size"]
    rec["expected"] = expected
    if expected > ctx.max_candidate_bytes:
        rec.update(outcome="candidate",
                   reason="candidate_size_limit",
                   detail=f"file_size {expected} exceeds max_candidate_bytes "
                          f"{ctx.max_candidate_bytes}; magic + header valid, "
                          "no export attempted")
        return _emit(ctx, rec)
    if ctx.exported_bytes + expected > ctx.max_run_bytes:
        ctx.budget_exceeded = "max_run_bytes"
        rec.update(outcome="candidate",
                   reason="run_byte_budget",
                   detail="per-run byte budget exhausted; no export "
                          "attempted")
        return _emit(ctx, rec)
    if ctx.candidates >= ctx.max_candidates:
        ctx.budget_exceeded = "max_candidates"
        rec.update(outcome="candidate",
                   reason="candidate_budget",
                   detail="per-run candidate budget exhausted; no export "
                          "attempted")
        return _emit(ctx, rec)
    ctx.candidates += 1

    dest = _export_path(session, ctx)
    try:
        res = session.export_buffer(
            obj, epoch, source=source, dest=str(dest),
            max_bytes=ctx.max_candidate_bytes, cancel=ctx.cancel)
    except ExportIncompleteError as e:
        rec.update(outcome="incomplete",
                   incomplete={"reason": e.context.get("reason"),
                               "bytes_exported": e.context.get(
                                   "bytes_exported"),
                               "bytes_requested": e.context.get(
                                   "bytes_requested")},
                   note="the partial temp file was removed; an incomplete "
                        "capture is never reported as complete")
        return _emit(ctx, rec)
    except Exception as e:
        rec.update(outcome="error", error=f"export: {str(e)[:160]}")
        return _emit(ctx, rec)

    captured = res["bytes"]["exported"]
    sha = res["bytes"]["sha256"]
    ctx.exported_bytes += captured
    data = dest.read_bytes()
    full = dex_full_check(data)
    rec.update(captured=captured, sha256=sha, validation=full,
               state_preserved=res.get("state_preserved"),
               export={"file": str(dest),
                       "consistency": res["consistency"],
                       "range": res["range"]})
    if len(data) < expected:
        rec.update(outcome="truncated",
                   note=f"captured {len(data)} of the declared {expected} "
                        "bytes; byte identity is NOT claimed")
        _write_sidecar(dest, rec)
        return _emit(ctx, rec)
    if full["result"] != "valid":
        # decisive post-export failure: not a recovered executable
        dest.unlink(missing_ok=True)
        rec.pop("export", None)
        rec.update(outcome="invalid", errors=full["errors"],
                   note="exported bytes failed full validation; the file "
                        "was removed — never kept as a dump")
        return _emit(ctx, rec)

    dup = ctx.seen.get(sha)
    if dup is not None:
        dest.unlink(missing_ok=True)
        rec.update(outcome="validated", deduplicated=True,
                   duplicate_of=dup,
                   note="identical content already recovered in this run; "
                        "the duplicate file was removed, the observation "
                        "is retained")
        return _emit(ctx, rec)
    artifact = {"file": str(dest), "sha256": sha, "captured": captured,
                "expected": expected}
    ctx.seen[sha] = artifact
    rec.update(outcome="validated", deduplicated=False)
    _write_sidecar(dest, rec)
    return _emit(ctx, rec)


def _export_path(session, ctx: RunContext) -> Path:
    import uuid
    base = ctx.export_dir
    if base is None:
        project = getattr(session, "project", None)
        root = Path(project.root) if project is not None else Path(".")
        base = root / "exports"
    base.mkdir(parents=True, exist_ok=True)
    return base / f"dex-{uuid.uuid4().hex[:12]}.dex"


def _write_sidecar(dest: Path, rec: dict) -> None:
    """JSON metadata next to the artifact file: id/path, hashes,
    captured/expected lengths, validation result, source/boundary, buffer
    range, caller status, completeness. Payload bytes are never inlined."""
    meta = {k: rec[k] for k in
            ("kind", "boundary", "hook", "thread", "source_kind",
             "outcome", "captured", "expected", "sha256", "validation",
             "buffer", "evidence", "state_preserved", "export",
             "deduplicated", "note")
            if k in rec}
    meta["consistency_note"] = CONSISTENCY_NOTE
    try:
        dest.with_name(dest.name + ".json").write_text(
            json.dumps(meta, indent=1, ensure_ascii=False), "utf-8")
    except OSError as e:
        log_progress(f"unpack sidecar: {e}")


def _emit(ctx: RunContext, rec: dict) -> dict:
    ctx.records.append(rec)
    return rec


# ------------------------------------------------------------ event handling
def extract_event(session, ctx: RunContext, ev: dict) -> list[dict]:
    """Handle one unpack-owned event; returns the observation records it
    produced ([] for entry-phase context-only events and non-matching
    class-scoped exits)."""
    reg = session.bp_registry.get(ev.get("request_id"))
    thread = ev.get("thread")
    if reg is None or reg.get("owner") != "unpack" or thread is None:
        return []
    hook = reg["hook_def"]
    if hook["boundary"] == "cipher_dofinal":
        return _cipher_event(session, ctx, ev, reg, hook, thread)
    if ev.get("kind_id") != EVK_BREAKPOINT:
        return []
    if hook.get("evidence") == "path_only":
        return [_path_evidence(session, ctx, ev, reg, hook, thread)]
    return _loader_event(session, ctx, ev, reg, hook, thread)


def _frame0(c, thread: int) -> dict:
    frames = c.thread_frames(thread, 1)
    if not frames:
        raise SessionError(f"thread {thread} has no frames")
    return frames[0]


def _slot(vregs: dict | None, jvm_slot: int) -> int:
    return vregs.get(jvm_slot, jvm_slot) if vregs else jvm_slot


def _loader_event(session, ctx, ev, reg, hook, thread) -> list[dict]:
    c = session.client
    try:
        fr = _frame0(c, thread)
        slot = _slot(reg.get("vregs"), hook["capture"][0]["slot"])
        kind = hook["capture"][0]["kind"]
        tag = 91 if kind == "bytebuffer[]" else 76
        v = c.frame_get_values(thread, fr["frame_id"], [(slot, tag)])[0]
    except Exception as e:
        return [_emit(ctx, {"kind": "unpack_observation",
                            "boundary": hook["boundary"], "hook": hook["name"],
                            "thread": thread, "outcome": "error",
                            "error": f"arg read: {str(e)[:160]}"})]
    out = []
    if kind == "bytebuffer[]":
        arr = v.get("v")
        if not arr:
            out.append(_emit(ctx, {"kind": "unpack_observation",
                                   "boundary": hook["boundary"],
                                   "hook": hook["name"], "thread": thread,
                                   "outcome": "empty",
                                   "note": "null ByteBuffer[]"}))
            return out
        try:
            n = min(c.array_length(arr), MAX_BUFFER_ARRAY_ELEMENTS)
            items = c.array_get_values(arr, 0, n)["items"]
        except Exception as e:
            return [_emit(ctx, {"kind": "unpack_observation",
                                "boundary": hook["boundary"],
                                "hook": hook["name"], "thread": thread,
                                "outcome": "error",
                                "error": f"buffer array read: {str(e)[:160]}"})]
        for i, item in enumerate(items):
            buf = item["v"] if isinstance(item, dict) else item
            if not buf:
                continue
            out.append(process_buffer(
                session, ctx, buf, source="bytebuffer", hook=hook,
                thread=thread, meta_extra={"array_index": i}))
            if ctx.budget_exceeded or ctx.over_event_budget():
                break
    else:
        buf = v.get("v")
        if not buf:
            out.append(_emit(ctx, {"kind": "unpack_observation",
                                   "boundary": hook["boundary"],
                                   "hook": hook["name"], "thread": thread,
                                   "outcome": "empty",
                                   "note": "null ByteBuffer"}))
        else:
            out.append(process_buffer(
                session, ctx, buf, source="bytebuffer", hook=hook,
                thread=thread))
    return out


def _path_evidence(session, ctx, ev, reg, hook, thread) -> dict:
    """DexClassLoader receives file paths: report loader/file evidence
    only — memory recovery is NOT promised from this boundary."""
    c = session.client
    rec = {"kind": "unpack_observation", "boundary": hook["boundary"],
           "hook": hook["name"], "thread": thread,
           "outcome": "path_evidence",
           "note": "DexClassLoader loads from file paths; no in-memory "
                   "payload is recoverable from this boundary"}
    try:
        fr = _frame0(c, thread)
        paths = {}
        for cap in hook["capture"]:
            slot = _slot(reg.get("vregs"), cap["slot"])
            v = c.frame_get_values(thread, fr["frame_id"],
                                   [(slot, TAG_STRING)])
            oid = v[0].get("v")
            paths[cap["label"]] = c.string_value(oid) if oid else None
        rec["paths"] = paths
    except Exception as e:
        rec["outcome"] = "error"
        rec["error"] = f"path read: {str(e)[:160]}"
    return _emit(ctx, rec)


def _cipher_event(session, ctx, ev, reg, hook, thread) -> list[dict]:
    """Entry: retain algorithm context (field reads only — class-scoped
    exit requests are armed, so invokes are forbidden). Exit (filtered to
    the hooked method): the return byte[] is the candidate."""
    c = session.client
    if ev.get("kind_id") == EVK_METHOD_EXIT_RET:
        loc = ev.get("location") or {}
        if loc.get("method") != reg.get("method_id"):
            return []
        entry_ctx = getattr(ctx, "_cipher_ctx", {}).pop(thread, None)
        rv = ev.get("return_value") or {}
        if rv.get("tag") != 91 or not rv.get("v"):
            return [_emit(ctx, {"kind": "unpack_observation",
                                "boundary": hook["boundary"],
                                "hook": hook["name"], "thread": thread,
                                "outcome": "not_dex",
                                "note": "doFinal returned null or a "
                                        "non-array value"})]
        meta = {"cipher": entry_ctx} if entry_ctx else {}
        return [process_buffer(session, ctx, rv["v"], source="array",
                               hook=hook, thread=thread,
                               meta_extra=meta)]
    # entry breakpoint: field-read the transformation (deadlock-free)
    cctx = {}
    try:
        fr = _frame0(c, thread)
        this = c.frame_this_object(thread, fr["frame_id"])
        if this.get("v"):
            cctx = read_fields(c, this["v"], [FLD_TRANSFORMATION])
    except Exception as e:
        cctx = {"error": str(e)[:120]}
    store = getattr(ctx, "_cipher_ctx", None)
    if store is None:
        store = ctx._cipher_ctx = {}
    if len(store) >= MAX_CIPHER_CONTEXT:
        store.clear()
    store[thread] = cctx
    return []


# ------------------------------------------------------------------ run loop
def run_watch(session, duration_s: float = 60.0,
              boundaries: list[str] | None = None,
              cipher_overloads: list[str] | None = None,
              defer: bool = False,
              max_events: int = DEFAULT_MAX_EVENTS,
              max_candidates: int = DEFAULT_MAX_CANDIDATES,
              max_candidate_bytes: int = DEFAULT_MAX_CANDIDATE_BYTES,
              max_run_bytes: int = DEFAULT_MAX_RUN_BYTES,
              prefix_bytes: int = PREFIX_BYTES,
              export_dir: str | None = None,
              record: bool = False, scenario: str | None = None,
              index: bool = False,
              cancel=None, on_record=None) -> dict:
    """Blocking discovery watch: install the selected boundaries, consume
    unpack-owned events through the dispatcher for duration_s, and run the
    candidate pipeline per observed buffer. Events the watch does NOT own
    are stashed for the public wait_events caller (counted "unrelated");
    owned suspensions are released by the dispatcher lease after each
    capture (export, error, or cancel). Teardown clears every unpack
    request on every exit path; a mid-watch reconnect reports the old
    epoch's requests as "unconfirmed" instead of clearing reused ids.

    With record=True (project-backed session), the watch is persisted as a
    versioned run manifest (kind "unpack_watch"): one event row per
    observation and one artifact row per exported candidate (metadata
    only — payload bytes stay in the export files). With index=True, every
    newly validated artifact is additionally registered in the project's
    runtime_artifacts table (see register_artifact)."""
    d = session.events
    epoch = d.epoch
    rep = install(session, boundaries=boundaries,
                  cipher_overloads=cipher_overloads, defer=defer)
    owned = {rid for i in rep["installed"] for rid in i["request_ids"]}
    owned |= {dfr["request_id"] for dfr in rep["deferred"]}
    base_owned = set(owned)
    errors, cleanup_errors = [], []
    unrelated = 0
    reason = "duration"

    ctx = RunContext(session, max_events=max_events,
                     max_candidates=max_candidates,
                     max_candidate_bytes=max_candidate_bytes,
                     max_run_bytes=max_run_bytes, prefix_bytes=prefix_bytes,
                     export_dir=export_dir, cancel=cancel)
    store = RunStore.for_session(session) if record else None
    run_id = None
    if store is not None:
        run_id = store.begin_run(
            "unpack_watch",
            capture_config={"duration_s": duration_s,
                            "boundaries": boundaries,
                            "cipher_overloads": cipher_overloads,
                            "max_events": max_events,
                            "max_candidates": max_candidates,
                            "max_candidate_bytes": max_candidate_bytes,
                            "max_run_bytes": max_run_bytes,
                            "defer": defer, "index": index},
            scenario=scenario, epoch=epoch,
            environment=capture_environment(session))
    indexed: list[dict] = []

    def on_event(ev: dict, lease) -> None:
        for rec in extract_event(session, ctx, ev):
            event_id = None
            if store is not None:
                event_id = store.add_event(
                    run_id, "unpack_observation", rec,
                    class_sig=reg_cls(session, ev), epoch=epoch)
                rec["event_id"] = event_id
            if store is not None and rec.get("outcome") == "validated" \
                    and not rec.get("deduplicated"):
                rec["artifact_id"] = store.add_artifact(
                    run_id, "unpack_dex", _artifact_meta(rec, run_id),
                    format="json", parent_event_id=event_id, epoch=epoch)
            if index and rec.get("outcome") == "validated" \
                    and not rec.get("deduplicated"):
                indexed.append(register_artifact(
                    session.project, sha256=rec["sha256"],
                    path=rec["export"]["file"], kind="dex",
                    origin={"run_id": run_id,
                            "event_id": rec.get("event_id"),
                            "artifact_id": rec.get("artifact_id"),
                            "boundary": rec["boundary"],
                            "hook": rec["hook"], "epoch": epoch},
                    validation=rec["validation"],
                    file_size=rec["captured"]))
            if on_record is not None:
                on_record(rec)

    sub = d.subscribe("unpack", on_event)
    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
                break
            if ctx.budget_exceeded:
                reason = ctx.budget_exceeded
                break
            wait = max(1.0, deadline - time.time())
            if cancel is not None:
                wait = min(wait, 1.0)
            try:
                r = d.next_routed(timeout=wait)
            except Exception as e:
                if cancel is not None \
                        and getattr(e, "code", None) == "E_JDWP_TIMEOUT" \
                        and time.time() < deadline:
                    continue
                if getattr(e, "code", None) != "E_JDWP_TIMEOUT":
                    reason = "error"
                    errors.append(f"wait: {str(e)[:120]}")
                    log_progress(f"unpack watch loop: {e}")
                break
            errors.extend(r.lease.errors)
            for h in d.deferred_handlers("unpack"):
                owned.update(h["installed_rids"])
            if r["events"]:
                unrelated += len(r["events"])
                d.stash(r)
            if ctx.over_event_budget():
                reason = "max_events"
                break
    finally:
        sub.close()
        for h in d.deferred_handlers("unpack"):
            owned.update(h["installed_rids"])
        auto_installed = sorted(owned - base_owned)
        unconfirmed = []
        if d.epoch != epoch:
            unconfirmed = sorted(owned)
        else:
            for rid in sorted(owned):
                if d.lookup(rid) is None:
                    continue
                try:
                    session.clear_request(rid)
                except Exception as e:
                    cleanup_errors.append(f"clear {rid}: {str(e)[:120]}")
        if store is not None:
            store.end_run(run_id, reason,
                          counts=_counts(ctx, unrelated, errors))

    out = {"records": ctx.records, "observations": len(ctx.records),
           "outcome_counts": _outcome_counts(ctx.records),
           "candidates": ctx.candidates,
           "exported_bytes": ctx.exported_bytes,
           "validated_unique": len(ctx.seen),
           "installed": len(rep["installed"]), "pending": rep["pending"],
           "states": rep["states"], "deferred": rep["deferred"],
           "auto_installed": auto_installed,
           "reason": reason,
           "truncated": reason in ("max_events", "max_run_bytes",
                                   "max_candidates"),
           "unrelated": unrelated, "unconfirmed": unconfirmed,
           "errors": errors, "cleanup_errors": cleanup_errors,
           "consistency_note": CONSISTENCY_NOTE,
           "run_id": run_id}
    if indexed:
        out["indexed"] = indexed
    return out


def reg_cls(session, ev: dict) -> str | None:
    reg = session.bp_registry.get(ev.get("request_id")) or {}
    return reg.get("cls")


def _artifact_meta(rec: dict, run_id: str | None) -> dict:
    """Persisted per-artifact JSON metadata (payload bytes are never
    inlined): id/path, hashes, captured/expected, validation, boundary,
    buffer range, caller status, completeness."""
    return {"run_id": run_id, "boundary": rec["boundary"],
            "hook": rec["hook"], "thread": rec["thread"],
            "outcome": rec["outcome"], "file": rec["export"]["file"],
            "sha256": rec["sha256"], "captured": rec["captured"],
            "expected": rec["expected"], "validation": rec["validation"],
            "buffer": rec.get("buffer"), "range": rec["export"]["range"],
            "state_preserved": rec.get("state_preserved"),
            "complete": rec["captured"] == rec["expected"],
            "consistency_note": CONSISTENCY_NOTE}


def _counts(ctx: RunContext, unrelated: int, errors: list) -> dict:
    return {"observations": len(ctx.records),
            "outcomes": _outcome_counts(ctx.records),
            "candidates": ctx.candidates,
            "exported_bytes": ctx.exported_bytes,
            "unrelated": unrelated, "errors": len(errors)}


def _outcome_counts(records: list[dict]) -> dict:
    out: dict = {}
    for r in records:
        out[r.get("outcome", "error")] = out.get(r.get("outcome", "error"),
                                                 0) + 1
    return out


# ------------------------------------------------- artifact index (issue #35)
def register_artifact(project, *, sha256: str, path: str, kind: str,
                      origin: dict, validation: dict,
                      file_size: int) -> dict:
    """Register a validated runtime artifact as an ADDITIONAL project
    artifact: one observation row in the runtime_artifacts table keyed by
    content hash (re-registration of the same content increments
    observations and updates last_seen/origin). This never touches the
    static index tables (classes/methods/...) — the original APK index is
    preserved untouched."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    body = {"sha256": sha256, "path": path, "kind": kind,
            "file_size": file_size, "origin": origin,
            "validation": validation}
    with project.db() as db:
        gen = index_generation(db)
        apk_sha = db.get_meta("sha256")
        row = db.one("SELECT artifact_key, observations FROM "
                     "runtime_artifacts WHERE artifact_key=?", (sha256,))
        if row is None:
            db.execute(
                "INSERT INTO runtime_artifacts(artifact_key,kind,sha256,"
                "file_size,path,origin,validation,apk_sha256,"
                "index_generation,first_seen,observations,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (sha256, kind, sha256, file_size, path,
                 json.dumps(origin, separators=(",", ":"), default=str),
                 json.dumps(validation, separators=(",", ":"), default=str),
                 apk_sha, gen, now, 1, now))
            observations = 1
        else:
            observations = row["observations"] + 1
            db.execute(
                "UPDATE runtime_artifacts SET observations=?, last_seen=?,"
                " path=?, origin=? WHERE artifact_key=?",
                (observations, now, path,
                 json.dumps(origin, separators=(",", ":"), default=str),
                 sha256))
    return {"artifact_key": sha256, "kind": kind, "path": path,
            "observations": observations,
            "deduplicated": observations > 1, "body": body}


def list_artifacts(project, *, limit: int = 50, offset: int = 0) -> dict:
    with project.db() as db:
        rows = db.query("SELECT * FROM runtime_artifacts "
                        "ORDER BY rowid LIMIT ? OFFSET ?", (limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM runtime_artifacts")["n"]
    for r in rows:
        for k in ("origin", "validation"):
            try:
                r[k] = json.loads(r[k]) if r.get(k) else None
            except Exception:
                pass
    return {"artifacts": rows, "count": len(rows), "total": total,
            "limit": limit, "offset": offset,
            "truncated": offset + len(rows) < total}

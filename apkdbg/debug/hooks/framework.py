"""Opt-in framework watcher profiles (issue #27) — navigation requests,
SharedPreferences edits, and system-service lookups, observed at selected
framework method exits (METHOD_EXIT_WITH_RETURN_VALUE, event kind 42) with
explicit per-profile coverage, correlation, and honest target reporting.

These are observation points on the runtime classes actually hooked, never
claims of full coverage:

Navigation
  startActivity is watched on Activity, ContextWrapper, and ContextImpl
  (the concrete context implementation), per overload actually present.
  An override that bypasses a superclass body is NOT observed at that
  class: an app's `startActivity(Intent)` override that never calls
  `super.startActivity` produces no Activity-class event; a ContextImpl
  call path never traverses ContextWrapper/Activity. Each record is a
  REQUEST observed at the hooked method's exit (the body returned
  normally; exceptional exits produce no exit event and are unobserved).
  A request is not a confirmed navigation: destination/lifecycle
  observation happens only via the lifecycle profiles (Activity.onCreate /
  onNewIntent) and only when the concrete activity actually calls the
  superclass body.

Storage
  SharedPreferences$Editor is an INTERFACE: the profile names the
  interface and resolves concrete implementations through cls_alts-style
  alternates (AOSP SharedPreferencesImpl$EditorImpl / $Editor) and, for
  custom or late-loaded implementations, defer=True (CLASS_PREPARE
  auto-install per classloader instance) or an explicit custom profile.
  put*/remove/clear are STAGED edits; apply/commit are SUBMISSIONS
  correlated to the editor instance (object identity, per connection
  epoch). commit's boolean return is captured from the exit event when
  readable. A staged edit is not persisted data; an observed apply is not
  proof of disk durability; an editor with staged edits and no observed
  submission is reported as DISCARDED in the derived transaction view.

Services
  getSystemService(String) and getSystemService(Class) are watched on the
  Context declaration plus concrete alternates (ContextImpl,
  ContextWrapper, Activity). A lookup record is a CAPABILITY REQUEST, not
  use of the capability. Repeated/hot lookups are counted per service
  name/class — no human-frequency assumption.

Attribution
  Bounded stack (SP_EVENT_THREAD, attributed mode) + the nearest frame
  matching the configured include scope, minus explicit exclude patterns
  (framework wrappers such as android.app.* are excludable and are never
  reported as app callers; frame[1] is never assumed). Records carry the
  original class/method descriptors, bytecode index, matched watcher
  target, thread, and an explicit attribution status; source coordinates
  are not attached unless a valid mapping exists (only the bytecode index
  is reported).

Bounded object capture and metadata invokes
  Intent and editor objects get bounded capture: runtime class, declared
  AOSP backing fields read deadlock-free (mAction/mFlags/mComponent/
  mExtras/mCategories on Intent, mClear on editor impls) — custom
  implementations report per-field error nodes, never fabricated values.
  Metadata getter invocation (Intent.getAction/getFlags/getComponent/
  getCategories, Class.getName for class-based lookups) is an EXPLICIT
  option (invoke_getters, off by default): it runs application/runtime
  code on the suspended thread through the validated #22 invoke path
  (resolve_instance_method + validated invoke_object_method), handles
  exceptions/reply timeouts per getter as error nodes, and honors the
  class-scoped exit-request reentrancy policy from #21: a getter declared
  by a class with an armed class-scoped exit request is NOT invoked (the
  invoked method's own exit would suspend the thread mid-invoke and the
  reply would never arrive) — the record carries an explicit
  reentrancy-blocked note instead. toString() is never invoked to format
  output.

Correlation
  One logical call traversing several watched methods (e.g.
  Activity.startActivity -> ContextWrapper.startActivity ->
  ContextImpl.startActivity) fires one event per watched method. Records
  whose target identity (navigation: event thread + Intent object id;
  storage: editor object id; services: event thread + service name/class
  id) matches within corr_window_ms share a correlation id; a new window
  opens a new group, so repeated hot calls stay distinct. Individual
  capture failures are preserved on their own records and visible in the
  correlation summary — a failed sibling never drops the group.

Lifecycle, limits, persistence
  Same contract as the string watchers (#26): cooperative cancellation,
  independent limits (max_events, max_reads, max_output_bytes, max_queue,
  duration_s), per-profile states installed/pending/not-found/unsupported/
  failed (missing and native targets are reported, never silently treated
  as installed), unrelated composites stashed for the public wait_events
  caller, teardown clearing every owned request with its original kind,
  and UNCONFIRMED remote cleanup after an epoch change (issue #32). With
  record=True the watch persists as a run manifest (kind
  "framework_watch", issue #36) with one "framework_event" row per
  emitted record; query_events() is the offline paginated query.
"""

from __future__ import annotations

import json
import time

from ...core.manifests import RunStore, capture_environment
from ...device.jdwp import (
    EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, SP_NONE, TAG_OBJECT, TAG_STRING,
)
from ...errors import SessionError
from ...protocol import log_progress
from ..capture import arg_vreg_map, capture_spec, decode_tagged, read_fields
from .crypto import ClassNotLoaded, MethodNotFound, UnsupportedHook
from .strings import (
    _ABSTRACT, _NATIVE, _STATIC, _class_match, _class_pattern, parse_sig,
)

OWNER = "framework"

MODES = ("best_effort", "attributed")

ACT = "Landroid/app/Activity;"
CTXW = "Landroid/content/ContextWrapper;"
CTX = "Landroid/content/Context;"
CIMPL = "Landroid/app/ContextImpl;"
EDITOR = "Landroid/content/SharedPreferences$Editor;"
EDITOR_ALTS = ["Landroid/app/SharedPreferencesImpl$EditorImpl;",
               "Landroid/app/SharedPreferencesImpl$Editor;"]

NAVIGATION_NOTE = (
    "request = a startActivity call observed at the hooked method's exit "
    "(normal return; exceptional exits are unobserved); a request is NOT "
    "a confirmed navigation — destination/lifecycle observation comes "
    "only from the lifecycle profiles actually hooked, and overrides "
    "that bypass a hooked superclass body (app startActivity overrides, "
    "direct ContextImpl paths) never traverse the hooked method")
STORAGE_NOTE = (
    "staged put*/remove/clear edits are NOT persisted data; an observed "
    "apply() is NOT proof of disk durability; commit's boolean result is "
    "the return of the hooked concrete implementation only; editors with "
    "staged edits and no observed submission are reported as discarded; "
    "unwatched custom Editor implementations are invisible unless given "
    "as custom profiles or reached via defer auto-install")
SERVICES_NOTE = (
    "a getSystemService lookup is a capability request, not use of the "
    "capability; repeated lookups are counted per service name/class "
    "without assuming human-frequency calls")

# AOSP backing fields read deadlock-free (issue #21 field-read idiom);
# missing fields (custom impls, OEM renames) become explicit error nodes
FLD_INTENT = [{"name": "mAction", "label": "action"},
              {"name": "mFlags", "label": "flags"},
              {"name": "mComponent", "label": "component"},
              {"name": "mExtras", "label": "extras"},
              {"name": "mCategories", "label": "categories"}]
FLD_COMPONENT = [{"name": "mPackage", "label": "package"},
                 {"name": "mClass", "label": "class"}]
FLD_EDITOR = [{"name": "mClear", "label": "clear_flag"}]

_INTENT_GETTERS = [
    {"method": "getAction", "sig": "()Ljava/lang/String;",
     "label": "action"},
    {"method": "getFlags", "sig": "()I", "label": "flags"},
    {"method": "getComponent", "sig": "()Landroid/content/ComponentName;",
     "label": "component"},
    {"method": "getCategories", "sig": "()Ljava/util/Set;",
     "label": "categories"},
]
_CLASS_GETTER = {"method": "getName", "sig": "()Ljava/lang/String;",
                 "label": "class_name"}

_PRIM_CAPTURE = {"I": "int", "Z": "boolean", "J": "long", "F": "float",
                 "B": "byte", "S": "short", "C": "char", "D": "double"}


def _profile(name, family, role, cls, method, sig, note, args=None,
             cls_alts=(), ret=None):
    return {"name": name, "family": family, "role": role, "cls": cls,
            "method": method, "sig": sig, "args": list(args or []),
            "cls_alts": list(cls_alts), "ret": ret, "note": note}


def _nav(name, cls, method, sig, args, note, role="request"):
    return _profile(name, "navigation", role, cls, method, sig, note,
                    args=args)


def _store(name, method, sig, args, note, role="staged", ret=None):
    return _profile(name, "storage", role, EDITOR, method, sig, note,
                    args=args, cls_alts=EDITOR_ALTS, ret=ret)


_INTENT = "Landroid/content/Intent;"
_INTENT_B = "(Landroid/content/Intent;Landroid/os/Bundle;)V"
_INTENT_ONLY = "(Landroid/content/Intent;)V"
_ED_RET = "Landroid/content/SharedPreferences$Editor;"

BUILTIN_PROFILES: list[dict] = [
    # -------------------------------------------------------- navigation
    _nav("nav.activity.start", ACT, "startActivity", _INTENT_ONLY,
         [("intent", "object")],
         "Activity.startActivity(Intent); overrides that skip the "
         "superclass body bypass this observation point"),
    _nav("nav.activity.start.opts", ACT, "startActivity", _INTENT_B,
         [("intent", "object"), None],
         "Activity.startActivity(Intent, Bundle) overload"),
    _nav("nav.contextwrapper.start", CTXW, "startActivity", _INTENT_ONLY,
         [("intent", "object")],
         "ContextWrapper.startActivity(Intent); NOT universal — "
         "ContextImpl and app overrides bypass it"),
    _nav("nav.contextwrapper.start.opts", CTXW, "startActivity", _INTENT_B,
         [("intent", "object"), None],
         "ContextWrapper.startActivity(Intent, Bundle) overload"),
    _nav("nav.contextimpl.start", CIMPL, "startActivity", _INTENT_ONLY,
         [("intent", "object")],
         "ContextImpl.startActivity(Intent) — the concrete dispatch path"),
    _nav("nav.contextimpl.start.opts", CIMPL, "startActivity", _INTENT_B,
         [("intent", "object"), None],
         "ContextImpl.startActivity(Intent, Bundle) overload"),
    _nav("nav.lifecycle.oncreate", ACT, "onCreate",
         "(Landroid/os/Bundle;)V", [],
         "observed destination only when the concrete activity calls "
         "super.onCreate", role="lifecycle"),
    _nav("nav.lifecycle.onnewintent", ACT, "onNewIntent", _INTENT_ONLY,
         [("intent", "object")],
         "observed redelivery only when the activity calls "
         "super.onNewIntent", role="lifecycle"),
    # ----------------------------------------------------------- storage
    _store("store.putstring", "putString",
           "(Ljava/lang/String;Ljava/lang/String;)" + _ED_RET,
           [("key", "string"), ("value", "string")],
           "staged edit; not persisted until apply/commit"),
    _store("store.putstringset", "putStringSet",
           "(Ljava/lang/String;Ljava/util/Set;)" + _ED_RET,
           [("key", "string"), ("value", "object")],
           "staged edit; value captured as a bounded object node"),
    _store("store.putint", "putInt", "(Ljava/lang/String;I)" + _ED_RET,
           [("key", "string"), ("value", "int")], "staged edit"),
    _store("store.putlong", "putLong", "(Ljava/lang/String;J)" + _ED_RET,
           [("key", "string"), ("value", "long")], "staged edit"),
    _store("store.putfloat", "putFloat", "(Ljava/lang/String;F)" + _ED_RET,
           [("key", "string"), ("value", "float")], "staged edit"),
    _store("store.putboolean", "putBoolean",
           "(Ljava/lang/String;Z)" + _ED_RET,
           [("key", "string"), ("value", "boolean")], "staged edit"),
    _store("store.remove", "remove", "(Ljava/lang/String;)" + _ED_RET,
           [("key", "string")], "staged removal"),
    _store("store.clear", "clear", "()" + _ED_RET, [], "staged clear"),
    _store("store.apply", "apply", "()V", [],
           "submission; observation is NOT proof of disk durability",
           role="submit"),
    _store("store.commit", "commit", "()Z", [],
           "submission; the boolean result is captured from the exit "
           "event when readable", role="submit", ret="boolean"),
    # ---------------------------------------------------------- services
    _profile("svc.name", "services", "lookup", CTX, "getSystemService",
             "(Ljava/lang/String;)Ljava/lang/Object;",
             "string-based capability request; not use of the service",
             args=[("name", "string")],
             cls_alts=[CIMPL, CTXW, ACT], ret="object"),
    _profile("svc.class", "services", "lookup", CTX, "getSystemService",
             "(Ljava/lang/Class;)Ljava/lang/Object;",
             "class-based capability request; the Class argument's name "
             "needs invoke_getters (else a bounded object node)",
             args=[("cls", "object")],
             cls_alts=[CIMPL, CTXW, ACT], ret="object"),
]

_BUILTINS = {p["name"]: p for p in BUILTIN_PROFILES}

FAMILIES = {
    "navigation": [p["name"] for p in BUILTIN_PROFILES
                   if p["family"] == "navigation"],
    "storage": [p["name"] for p in BUILTIN_PROFILES
                if p["family"] == "storage"],
    "services": [p["name"] for p in BUILTIN_PROFILES
                 if p["family"] == "services"],
}

COVERAGE_NOTES = {"navigation": NAVIGATION_NOTE, "storage": STORAGE_NOTE,
                  "services": SERVICES_NOTE}


# ------------------------------------------------------------------ profiles
def resolve_profiles(specs) -> list[dict]:
    """Resolve profile selectors to profile dicts. A selector is a builtin
    profile name ("store.commit"), a family name ("navigation" expands to
    every profile of that family), or an explicit custom dict
    {"cls","method","sig", "family"?, "role"?, "args"?, "cls_alts"?,
    "ret"?, "name"?}. Custom profiles watch custom/late-loaded
    implementations (e.g. an app's own SharedPreferences$Editor); arg
    capture defaults to one bounded node per declared argument."""
    out = []
    for spec in specs or []:
        if isinstance(spec, str) and spec in FAMILIES:
            out.extend(dict(_BUILTINS[n]) for n in FAMILIES[spec])
            continue
        out.append(resolve_profile(spec))
    return out


def resolve_profile(spec) -> dict:
    if isinstance(spec, str):
        p = _BUILTINS.get(spec)
        if p is None:
            raise SessionError(
                f"unknown builtin profile {spec!r}",
                hint="available: " + ", ".join(sorted(_BUILTINS)) + " — or "
                     "a family (" + ", ".join(sorted(FAMILIES)) + "), or "
                     'an explicit {"cls","method","sig"} profile')
        return dict(p)
    if not isinstance(spec, dict):
        raise SessionError("profile must be a builtin name, a family name, "
                           'or an explicit {"cls","method","sig"} object')
    cls, method, sig = spec.get("cls"), spec.get("method"), spec.get("sig")
    if not (isinstance(cls, str) and cls.startswith("L")
            and isinstance(method, str) and method
            and isinstance(sig, str) and sig.startswith("(")):
        raise SessionError(
            "custom profile needs cls (L...; descriptor), method, and sig "
            "((...)... descriptor)",
            hint='{"cls":"Lcom/foo/MyEditor;","method":"commit",'
                 '"sig":"()Z","family":"storage","role":"submit",'
                 '"ret":"boolean"}')
    family = spec.get("family") or "custom"
    role = spec.get("role") or "custom"
    ret = spec.get("ret")
    if ret not in (None, "boolean", "object"):
        raise SessionError(f"unknown ret kind {ret!r}",
                           hint="boolean | object")
    args = spec.get("args")
    if args is None:
        args = _auto_args(sig)
    return {"name": spec.get("name") or f"custom:{method}{sig}",
            "family": family, "role": role, "cls": cls, "method": method,
            "sig": sig, "args": list(args), "ret": ret,
            "cls_alts": list(spec.get("cls_alts") or []),
            "note": spec.get("note") or "user-selected profile"}


def _auto_args(sig: str) -> list:
    """Default bounded capture: one node per declared argument."""
    args, _ = parse_sig(sig)
    return [(f"arg{i}", _capture_type(t)) for i, t in enumerate(args)]


def _capture_type(sig_type: str) -> str:
    if sig_type == "Ljava/lang/String;":
        return "string"
    if sig_type == "[B":
        return "byte[]"
    return _PRIM_CAPTURE.get(sig_type, "object")


def _capture_slots(prof: dict, is_static: bool) -> list[dict]:
    """JVM-slot capture spec for the profile's selected arguments
    (aligned with the sig; None entries are skipped). Translated to ART
    DEX vregs at install time via capture.arg_vreg_map."""
    args, _ = parse_sig(prof["sig"])
    slot = 0 if is_static else 1
    spec = []
    for idx, t in enumerate(args):
        sel = prof["args"][idx] if idx < len(prof["args"]) else None
        if sel:
            label, ctype = sel
            spec.append({"slot": slot, "type": ctype, "label": label})
        slot += 2 if t in ("J", "D") else 1
    return spec


# ------------------------------------------------------------------- install
def install(session, profiles: list, mode: str = "attributed", *,
            defer: bool = False, thread: int | None = None,
            mod_count: int | None = None) -> dict:
    """Register class-scoped METHOD_EXIT_WITH_RETURN_VALUE requests for
    the resolved profiles. Every profile ends in one distinct state:
    installed / pending (class not loaded — deferrable) / not-found /
    unsupported (native, or abstract/interface-only) / failed. Overloads
    match by exact (name, sig); defer=True arms a CLASS_PREPARE watch that
    auto-installs exactly once per classloader instance — the path for
    late-loaded custom implementations."""
    if mode not in MODES:
        raise SessionError(f"unknown capture mode {mode!r}",
                           hint=" | ".join(MODES))
    sp = SP_NONE if mode == "best_effort" else SP_EVENT_THREAD
    d = session.events
    installed, pending, deferred = [], [], []
    states = {}
    for spec in profiles:
        prof = resolve_profile(spec)  # idempotent for resolved dicts
        try:
            regs = _install_one(session, prof, sp, thread, mod_count)
        except ClassNotLoaded as e:
            states[prof["name"]] = "pending"
            pending.append({"profile": prof["name"], "state": "pending",
                            "reason": str(e)[:120]})
            if defer:
                rid = d.defer_hook(
                    OWNER, prof["name"], _class_pattern(prof["cls"]),
                    _make_on_prepare(session, prof, sp, thread, mod_count))
                deferred.append({"profile": prof["name"], "request_id": rid})
            continue
        except (MethodNotFound, UnsupportedHook) as e:
            state = ("not-found" if isinstance(e, MethodNotFound)
                     else "unsupported")
            states[prof["name"]] = state
            pending.append({"profile": prof["name"], "state": state,
                            "reason": str(e)[:120]})
            continue
        except Exception as e:
            states[prof["name"]] = "failed"
            pending.append({"profile": prof["name"], "state": "failed",
                            "reason": str(e)[:120]})
            continue
        states[prof["name"]] = "installed"
        installed.append({"profile": prof["name"],
                          "request_ids": [r["rid"] for r in regs]})
    return {"installed": installed, "pending": pending,
            "deferred": deferred, "states": states,
            "note": "pending profiles: class not loaded yet; re-install "
                    "later or install with defer=True for CLASS_PREPARE "
                    "auto-install (custom/late-loaded implementations)"}


def _install_one(session, prof: dict, sp: int, thread: int | None,
                 mod_count: int | None,
                 only_type_ids: set[int] | None = None) -> list[dict]:
    """Register the exit request of one profile for every loaded class
    (primary sig first, then alternates such as the AOSP editor impl).
    Idempotent per (profile, type_id); abstract methods (the Editor
    interface, abstract Context declarations) are skipped so only
    concrete implementations are watched. On partial failure only the
    requests registered by THIS call are cleared."""
    c = session.client
    live = {rid: m for rid, m in session.bp_registry.items()
            if m.get("owner") == OWNER and m.get("profile_name")
            == prof["name"] and session.events.is_live(m)}
    regs = [{"rid": rid} for rid in live]
    new = []
    loaded, saw_method = 0, False
    try:
        for sig in [prof["cls"], *prof.get("cls_alts", [])]:
            for cls in c.classes_by_signature(sig):
                tid = cls["type_id"]
                if only_type_ids is not None and tid not in only_type_ids:
                    continue
                if any(m["type_id"] == tid for m in live.values()):
                    continue
                loaded += 1
                m = next((m for m in c.rt_methods(tid)
                          if m["name"] == prof["method"]
                          and m["sig"] == prof["sig"]), None)
                if not m:
                    continue
                saw_method = True
                bits = m.get("mod_bits", 0)
                if bits & _NATIVE:
                    raise UnsupportedHook(
                        f"{prof['method']}{prof['sig']} is native")
                if bits & _ABSTRACT:
                    continue  # e.g. the SharedPreferences$Editor interface
                mods = [c.mod_class_only(tid)]
                if thread is not None:
                    mods.append(c.mod_thread_only(thread))
                if mod_count is not None:
                    mods.append(c.mod_count(mod_count))
                spec = _capture_slots(prof, bool(bits & _STATIC))
                vregs = arg_vreg_map(c, tid, m["id"]) if spec else None
                try:
                    loader = c.rt_class_loader(tid)
                except Exception:
                    loader = None  # type_id identity still dedupes per loader
                rid = c.set_event(EVK_METHOD_EXIT_RET, sp, mods)
                new.append({"rid": rid, "type_id": tid, "cls_sig": sig,
                            "method_id": m["id"], "spec": spec,
                            "vregs": vregs, "loader": loader})
    except Exception:
        for r in new:
            try:
                c.clear_event(EVK_METHOD_EXIT_RET, r["rid"])
            except Exception:
                pass
        raise
    if not new and not regs:
        if not loaded:
            raise ClassNotLoaded(f"{prof['cls']} not loaded")
        if not saw_method:
            raise MethodNotFound(
                f"{prof['method']}{prof['sig']} not found "
                f"(overloaded methods need the exact sig)")
        raise UnsupportedHook(
            f"{prof['method']}{prof['sig']} has no concrete implementation "
            f"in the loaded classes (abstract/interface only)")
    for r in new:
        session.events.register(r["rid"], {
            "owner": OWNER, "profile_name": prof["name"],
            "profile": {k: prof[k] for k in
                        ("name", "family", "role", "cls", "method", "sig",
                         "ret", "note")},
            "entry": "hook", "hook": prof["name"],
            "kind": EVK_METHOD_EXIT_RET, "cls": r["cls_sig"],
            "type_id": r["type_id"], "loader": r["loader"],
            "method": prof["method"], "sig": prof["sig"],
            "method_id": r["method_id"], "capture_spec": r["spec"],
            "vregs": r["vregs"], "suspend_policy": sp,
            "spec": prof["method"] + prof["sig"]})
    return regs + new


def _make_on_prepare(session, prof: dict, sp: int, thread: int | None,
                     mod_count: int | None):
    def on_prepare(ev: dict, handler: dict) -> None:
        regs = _install_one(session, prof, sp, thread, mod_count,
                            only_type_ids={ev.get("type_id")})
        handler["installed_rids"].extend(r["rid"] for r in regs)
    return on_prepare


# ------------------------------------------------------------------ extract
def _new_stats() -> dict:
    return {"received": 0, "filtered": 0, "matched": 0, "unavailable": 0,
            "truncated": 0, "dropped": 0, "reads": 0}


def extract_event(session, ev: dict, cfg: dict) -> dict | None:
    """Build the watcher record for one owned exit event, or None when
    the event is not ours or is host-side filtered (class-scoped requests
    fire for every method of the class). Counters accumulate in
    cfg["_stats"]; cfg["_stop"] is set when a read budget is exhausted.
    The suspension (attributed mode) is owned by the dispatcher lease,
    never resumed here."""
    stats = cfg["_stats"]
    reg = session.bp_registry.get(ev.get("request_id"))
    if reg is None or reg.get("owner") != OWNER:
        return None
    if ev.get("kind_id") != EVK_METHOD_EXIT_RET:
        return None
    stats["received"] += 1
    loc = ev.get("location") or {}
    if loc.get("method") != reg.get("method_id"):
        stats["filtered"] += 1
        return None
    if cfg.get("_stop"):
        stats["dropped"] += 1
        return None
    prof = reg["profile"]
    rec = {"profile": prof["name"], "family": prof["family"],
           "role": prof["role"], "thread": ev.get("thread"),
           "cls": reg["cls"], "method": reg["method"], "sig": reg["sig"],
           "status": "ok"}
    c = session.client
    mode = cfg["mode"]
    thread = ev.get("thread")
    frames = None
    if mode == "attributed" and thread is not None:
        try:
            frames = c.thread_frames(thread, max(1, cfg.get("max_stack", 8)))
            stats["reads"] += 1
        except Exception as e:
            rec["attribution"] = {"status": "unavailable",
                                  "reason": f"frames: {str(e)[:100]}"}
    args, this_oid = _read_args(session, ev, reg, cfg, stats, frames, rec)
    _read_return(session, ev, reg, cfg, stats, rec)
    if args:
        rec["args"] = args
    _enrich(session, rec, reg, cfg, stats, args, this_oid)
    rec["attribution"] = rec.get("attribution") or _attribute(
        session, ev, reg, cfg, stats, frames)
    stats["matched"] += 1
    return rec


def _read_args(session, ev: dict, reg: dict, cfg: dict, stats: dict,
               frames: list | None, rec: dict) -> tuple[dict, int | None]:
    """this-object id and bounded argument capture at frame 0 of the
    suspended event thread. best_effort events have no valid frames:
    reported as unavailable, never fabricated."""
    if not reg["capture_spec"]:
        spec_needed = False
    else:
        spec_needed = True
    if cfg["mode"] != "attributed":
        if spec_needed:
            stats["unavailable"] += 1
            rec["status"] = "unavailable"
            rec["unavailable_reason"] = (
                "argument capture requires a suspended thread "
                "(attributed mode)")
        return {}, None
    if not frames:
        if spec_needed:
            stats["unavailable"] += 1
            rec["status"] = "unavailable"
            rec["unavailable_reason"] = "no frames on the suspended thread"
        return {}, None
    c = session.client
    thread = ev["thread"]
    frame_id = frames[0]["frame_id"]
    this_oid = None
    try:
        this = c.frame_this_object(thread, frame_id)
        stats["reads"] += 1
        this_oid = this.get("v") or None
        if this_oid:
            rec["this"] = {"id": this_oid, "cls": reg["cls"]}
    except Exception as e:
        rec.setdefault("capture_errors", {})["this"] = str(e)[:100]
    out = {}
    if reg["capture_spec"]:
        try:
            got = capture_spec(c, thread, frame_id, reg["capture_spec"],
                               vregs=reg.get("vregs"),
                               max_str=cfg.get("max_str", 512) + 1)
            stats["reads"] += len(reg["capture_spec"])
        except Exception as e:
            stats["unavailable"] += 1
            rec["status"] = "unavailable"
            rec["unavailable_reason"] = f"argument read failed: {str(e)[:100]}"
            return out, this_oid
        for label in sorted(got):
            node = got[label]
            if isinstance(node, dict) and "error" in node:
                stats["unavailable"] += 1
                rec.setdefault("capture_errors", {})[label] = \
                    str(node["error"])[:100]
            out[label] = node
    return out, this_oid


def _read_return(session, ev: dict, reg: dict, cfg: dict, stats: dict,
                 rec: dict) -> None:
    """Decode the exit event's return value per the profile's ret kind:
    'boolean' (commit result) and 'object' (looked-up service: bounded
    runtime-class read while suspended)."""
    kind = reg["profile"].get("ret")
    if not kind:
        return
    c = session.client
    rv = ev.get("return_value") or {}
    try:
        node = decode_tagged(c, rv, max_str=cfg.get("max_str", 512) + 1)
        stats["reads"] += 1
    except Exception as e:
        stats["unavailable"] += 1
        rec.setdefault("capture_errors", {})["return"] = str(e)[:100]
        return
    if kind == "boolean":
        rec["result"] = (bool(node["v"]) if node.get("type") == "boolean"
                         else None)
        if rec["result"] is None:
            rec.setdefault("capture_errors", {})["return"] = \
                f"expected boolean return, got {node.get('type')}"
        return
    # ret == "object": the returned service/result object, bounded
    if rv.get("tag") != TAG_OBJECT or not rv.get("v"):
        rec["return"] = {"type": node.get("type"), "v": node.get("v")}
        return
    out = {"id": rv["v"]}
    try:
        _, tid = c.object_reftype(rv["v"])
        out["cls"] = c.rt_signature(tid)
        stats["reads"] += 2
    except Exception as e:
        # best_effort: the VM moved on and the id may be dead
        out["cls_error"] = str(e)[:100]
        stats["unavailable"] += 1
    rec["return"] = out


# ------------------------------------------------------------------ enrich
def _enrich(session, rec: dict, reg: dict, cfg: dict, stats: dict,
            args: dict, this_oid: int | None) -> None:
    family = reg["profile"]["family"]
    if family == "navigation":
        _enrich_navigation(session, rec, reg, cfg, stats, args)
    elif family == "storage":
        _enrich_storage(session, rec, reg, cfg, stats, args, this_oid)
    elif family == "services":
        _enrich_services(session, rec, reg, cfg, stats, args)
    elif this_oid is not None:
        _correlate(rec, cfg, (family, this_oid))


def _node_value(node):
    """Plain JSON value of a captured node for summaries/correlation."""
    if isinstance(node, dict):
        if node.get("type") == "string":
            return node.get("v")
        return node.get("v", node.get("id"))
    return node


def _enrich_navigation(session, rec: dict, reg: dict, cfg: dict,
                       stats: dict, args: dict) -> None:
    intent = (args or {}).get("intent") or {}
    oid = intent.get("id") if isinstance(intent, dict) else None
    if rec["role"] == "request":
        if oid:
            rec["target"] = {"intent_id": oid,
                             "cls": intent.get("cls")}
            rec["intent"] = _intent_detail(session, rec["thread"], oid,
                                           cfg, stats)
            _correlate(rec, cfg, ("navigation", rec["thread"], oid))
        else:
            stats["unavailable"] += 1
            rec.setdefault("capture_errors", {})["intent"] = \
                "intent argument not captured"
    elif oid:
        rec["target"] = {"intent_id": oid, "cls": intent.get("cls")}


def _intent_detail(session, thread: int, oid: int, cfg: dict,
                   stats: dict) -> dict:
    """Bounded Intent capture: deadlock-free declared-field reads always;
    metadata getters only with invoke_getters=True (explicit opt-in, #22
    validated path, reentrancy policy from #21). toString() is never
    invoked."""
    c = session.client
    out = {"fields": read_fields(c, oid, FLD_INTENT)}
    stats["reads"] += 1
    if not cfg.get("invoke_getters"):
        out["meta"] = {"status": "not_requested",
                       "reason": "getter invocation is off "
                                 "(invoke_getters=False)"}
        return out
    meta = {}
    for inv in _INTENT_GETTERS:
        node = _run_getter(session, thread, oid, inv, cfg, stats)
        if inv["label"] == "component" and isinstance(node, dict) \
                and node.get("id"):
            try:
                node["fields"] = read_fields(c, node["id"], FLD_COMPONENT)
                stats["reads"] += 1
            except Exception as e:
                node["fields_error"] = str(e)[:100]
        meta[inv["label"]] = node
    out["meta"] = meta
    return out


def _run_getter(session, thread: int, oid: int, inv: dict, cfg: dict,
                stats: dict):
    """One validated metadata invoke (#22) with the #21 reentrancy
    policy: a getter declared by a class with an armed class-scoped exit
    request is never invoked — the exit of the invoked method would
    suspend the thread mid-invoke and the reply would never arrive."""
    c = session.client
    label = inv["label"]
    if thread is None:
        return {"error": "no suspended thread for getter invocation"}
    try:
        _, tid = c.object_reftype(oid)
        def_cls, mid = c.resolve_instance_method(tid, inv["method"],
                                                 inv["sig"])
        stats["reads"] += 1
    except Exception as e:
        return {"error": str(e)[:120]}
    if def_cls in _armed_types(session):
        return {"error": "reentrancy: declaring class has an armed "
                         "class-scoped exit request; invoke blocked by "
                         "policy", "declaring_type": def_cls}
    try:
        r = c.invoke_object_method(oid, thread, def_cls, mid, [])
        stats["reads"] += 1
    except Exception as e:
        return {"error": str(e)[:120]}
    if r.get("exception"):
        return {"error": "threw", "exc_id": r["exception"]}
    val = r["value"]
    try:
        node = decode_tagged(c, val, max_str=cfg.get("max_str", 512) + 1)
    except Exception as e:
        return {"error": str(e)[:120]}
    if node.get("type") == "string":
        return node.get("v")
    if val.get("tag") == TAG_OBJECT and val.get("v"):
        node["id"] = val["v"]
    return node


def _armed_types(session) -> set[int]:
    """Type ids with a live class-scoped exit request in this epoch (any
    owner — crypto/strings/framework requests all reenter)."""
    return {m["type_id"] for m in session.bp_registry.values()
            if m.get("kind") == EVK_METHOD_EXIT_RET
            and m.get("type_id") is not None
            and session.events.is_live(m)}


def _editor_of(cfg: dict, oid: int) -> dict:
    ed = cfg["_editors"].get(oid)
    if ed is None:
        ed = {"alias": f"E{len(cfg['_editors']) + 1}", "oid": oid,
              "staged": [], "submitted": None, "commit_result": None}
        cfg["_editors"][oid] = ed
    return ed


def _enrich_storage(session, rec: dict, reg: dict, cfg: dict,
                    stats: dict, args: dict, this_oid: int | None) -> None:
    if this_oid is None:
        stats["unavailable"] += 1
        rec.setdefault("capture_errors", {})["editor"] = \
            "editor object (this) not captured; cannot correlate"
        return
    ed = _editor_of(cfg, this_oid)
    rec["editor"] = ed["alias"]
    rec["editor_oid"] = this_oid
    _correlate(rec, cfg, ("storage", this_oid))
    if rec["role"] == "staged":
        op = {"op": rec["method"]}
        if args:
            if "key" in args:
                op["key"] = _node_value(args["key"])
            if "value" in args:
                op["value"] = _node_value(args["value"])
        ed["staged"].append(op)
        rec["op"] = op
    else:  # submit
        ed["submitted"] = rec["method"]
        if rec["method"] == "commit" and "result" in rec:
            ed["commit_result"] = rec["result"]
        rec["op"] = {"op": rec["method"]}
        if "result" in rec:
            rec["op"]["result"] = rec["result"]


def _enrich_services(session, rec: dict, reg: dict, cfg: dict,
                     stats: dict, args: dict) -> None:
    name_node = (args or {}).get("name") or {}
    cls_node = (args or {}).get("cls") or {}
    if name_node:
        name = _node_value(name_node)
        rec["service"] = {"name": name}
        counts = cfg["_svc_counts"]
        key = ("name", name)
        counts[key] = counts.get(key, 0) + 1
        rec["lookup_count"] = counts[key]
        _correlate(rec, cfg, ("services", rec["thread"], "n", name))
    elif cls_node:
        ident = cls_node.get("id") if isinstance(cls_node, dict) else None
        svc = {"class_id": ident}
        if ident and cfg.get("invoke_getters"):
            svc["class_name"] = _run_getter(session, rec["thread"], ident,
                                            _CLASS_GETTER, cfg, stats)
        elif ident:
            svc["class_name"] = {"status": "not_requested",
                                 "reason": "getter invocation is off "
                                           "(invoke_getters=False)"}
        rec["service"] = svc
        counts = cfg["_svc_counts"]
        key = ("class", svc.get("class_name") if isinstance(
            svc.get("class_name"), str) else ident)
        counts[key] = counts.get(key, 0) + 1
        rec["lookup_count"] = counts[key]
        _correlate(rec, cfg, ("services", rec["thread"], "c", ident))
    else:
        stats["unavailable"] += 1
        rec.setdefault("capture_errors", {})["service"] = \
            "service argument not captured"


def _correlate(rec: dict, cfg: dict, key) -> None:
    """Assign the correlation id for `key`: events on the same identity
    (thread+intent / editor / thread+service) within corr_window_ms share
    a group; a later call with the same identity opens a NEW group, so
    repeated hot calls stay distinct. window 0 disables correlation."""
    window = cfg.get("corr_window_ms", 250)
    if not window:
        return
    now = time.monotonic() * 1000.0
    open_groups = cfg["_corr_open"]
    grp = open_groups.get(key)
    if grp is None or now - grp["last_ms"] > window:
        cfg["_corr_seq"] += 1
        grp = {"id": f"C{cfg['_corr_seq']}", "last_ms": now}
        open_groups[key] = grp
    else:
        grp["last_ms"] = now
    rec["corr"] = grp["id"]


def _attribute(session, ev: dict, reg: dict, cfg: dict, stats: dict,
               frames: list | None) -> dict:
    """Nearest frame matching the configured include scope, minus the
    exclude patterns (framework wrappers are never reported as app
    callers). Full original descriptors + bytecode index; explicit status
    when attribution is impossible — a caller is never fabricated."""
    if cfg["mode"] != "attributed":
        return {"status": "not_captured",
                "reason": "best_effort mode does not suspend; no stack "
                          "attribution is promised"}
    scope = cfg.get("scope")
    if not scope:
        return {"status": "no_scope_configured",
                "reason": "pass scope (e.g. 'com.example.*') to select "
                          "the nearest app frame"}
    if not frames:
        return {"status": "unavailable",
                "reason": "no frames on the suspended thread"}
    excludes = cfg.get("exclude") or []
    c = session.client
    for fr in frames:
        floc = fr.get("location") or {}
        if floc.get("class") == reg["type_id"] \
                and floc.get("method") == reg["method_id"]:
            continue  # the hooked method itself
        try:
            stats["reads"] += 1
            csig = session._sig_of(floc["class"])
        except Exception:
            continue
        dotted = _class_pattern(csig)
        if any(_class_match(x, dotted) for x in excludes):
            continue  # framework wrapper / explicitly excluded frame
        if not _class_match(scope, dotted):
            continue
        caller = {"class_sig": csig, "class": dotted,
                  "index": floc.get("index")}
        try:
            stats["reads"] += 1
            m = next((m for m in c.rt_methods(floc["class"])
                      if m["id"] == floc.get("method")), None)
            if m:
                caller["method"] = m["name"]
                caller["method_sig"] = m["sig"]
        except Exception:
            pass
        return {"status": "matched", "caller": caller}
    return {"status": "no_app_frame",
            "reason": f"no frame within {len(frames)} frames matches "
                      f"scope {scope!r} (excludes: {excludes or 'none'})"}


# ------------------------------------------------------------- derived views
def _transactions(cfg: dict) -> list[dict]:
    """Derived per-editor transaction view (raw records stay in
    "records"): staged edits, submission, commit result, and DISCARDED
    editors (staged but never submitted)."""
    out = []
    for ed in cfg["_editors"].values():
        out.append({"editor": ed["alias"], "oid": ed["oid"],
                    "staged": ed["staged"],
                    "staged_count": len(ed["staged"]),
                    "submitted": ed["submitted"],
                    "commit_result": ed["commit_result"],
                    "discarded": bool(ed["staged"])
                    and ed["submitted"] is None})
    return out


def _correlation_summary(records: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for rec in records:
        cid = rec.get("corr")
        if not cid:
            continue
        g = groups.setdefault(cid, {"id": cid, "family": rec["family"],
                                    "profiles": [], "statuses": [],
                                    "records": 0})
        g["profiles"].append(rec["profile"])
        g["statuses"].append(rec.get("status", "ok"))
        g["records"] += 1
    # multi-record groups: one logical call traversing several watched
    # methods; individual capture failures stay visible in "statuses"
    return [g for g in groups.values() if g["records"] > 1]


def _lookup_summary(cfg: dict) -> list[dict]:
    return [{"kind": kind, "service": name, "lookups": n}
            for (kind, name), n in sorted(cfg["_svc_counts"].items(),
                                          key=lambda kv: str(kv[0]))]


# ----------------------------------------------------------------- run_watch
def run_watch(session, profiles=None, families=None,
              mode: str = "attributed", *,
              duration_s: float = 60.0, max_events: int = 1000,
              max_reads: int = 5000, max_output_bytes: int = 1 << 20,
              max_queue: int = 64, max_stack: int = 8, max_str: int = 512,
              scope: str | None = None, exclude: list | None = None,
              invoke_getters: bool = False, corr_window_ms: int = 250,
              thread: int | None = None, mod_count: int | None = None,
              defer: bool = False, record: bool = False,
              scenario: str | None = None, cancel=None) -> dict:
    """Blocking framework-watch loop: install the selected profiles
    (families: navigation|storage|services — default all three; explicit
    profile names/custom dicts narrow or extend the selection), then
    consume framework-owned events through the session dispatcher until a
    limit stops it. Stop reasons: duration | max_events | max_reads |
    max_output_bytes | queue_pressure | cancelled | error.

    Claims only its own events (unrelated stops are stashed for the
    public wait_events caller, whose consumer owns their suspensions).
    Cooperative cancellation via any object with is_set(). Teardown
    clears every owned request with its original kind while the transport
    epoch is unchanged; after a reconnect the old ids are reported in
    "unconfirmed" and the remote is left untouched (issue #32). Capture
    exceptions never block resume or teardown.

    With record=True (and a project-backed session) the watch persists as
    a run manifest (kind "framework_watch", issue #36): capture config +
    limits on the run, one "framework_event" event per emitted record
    carrying profile family, role, and attribution status."""
    if profiles is not None:
        profs = resolve_profiles(profiles)
    else:
        profs = resolve_profiles(families or sorted(FAMILIES))
    cfg = {"mode": mode, "scope": scope, "exclude": list(exclude or []),
           "invoke_getters": invoke_getters,
           "corr_window_ms": corr_window_ms,
           "max_stack": max_stack, "max_str": max_str,
           "_stats": _new_stats(), "_stop": None,
           "_editors": {}, "_svc_counts": {},
           "_corr_open": {}, "_corr_seq": 0}
    d = session.events
    epoch = d.epoch
    rep = install(session, profs, mode=mode, defer=defer, thread=thread,
                  mod_count=mod_count)
    owned = {rid for i in rep["installed"] for rid in i["request_ids"]}
    owned |= {dfr["request_id"] for dfr in rep["deferred"]}
    base_owned = set(owned)
    records, errors, cleanup_errors = [], [], []
    out_bytes, unrelated = 0, 0
    reason = "duration"

    store = RunStore.for_session(session) if record else None
    run_id = None
    if store is not None:
        run_id = store.begin_run(
            "framework_watch",
            capture_config={
                "profiles": [{k: p[k] for k in
                              ("name", "family", "role", "cls", "method",
                               "sig", "ret", "note")} for p in profs],
                "mode": mode, "scope": scope, "exclude": cfg["exclude"],
                "invoke_getters": invoke_getters,
                "corr_window_ms": corr_window_ms,
                "limits": {"duration_s": duration_s,
                           "max_events": max_events,
                           "max_reads": max_reads,
                           "max_output_bytes": max_output_bytes,
                           "max_queue": max_queue, "max_stack": max_stack,
                           "max_str": max_str},
                "defer": defer, "thread": thread,
                "mod_count": mod_count},
            scenario=scenario, epoch=epoch,
            environment=capture_environment(session))

    def on_event(ev: dict, lease) -> None:
        nonlocal out_bytes
        try:
            rec = extract_event(session, ev, cfg)
        except Exception as e:
            # capture exceptions never block resume or teardown
            errors.append(f"capture: {str(e)[:120]}")
            cfg["_stats"]["dropped"] += 1
            return
        if rec is None:
            return
        records.append(rec)
        out_bytes += len(json.dumps(rec, default=str))
        # budgets apply mid-composite too: once exhausted, further events
        # of the batch are counted dropped (not read) and the loop stops
        if cfg["_stats"]["reads"] >= max_reads:
            cfg["_stop"] = "max_reads"
        elif len(records) >= max_events:
            cfg["_stop"] = "max_events"
        if store is not None:
            store.add_event(run_id, "framework_event", rec,
                            class_sig=rec.get("cls"),
                            method_name=rec.get("method"),
                            method_sig=rec.get("sig"), epoch=epoch)

    sub = d.subscribe(OWNER, on_event)
    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
                break
            try:
                r = d.next_routed(
                    timeout=max(1.0, deadline - time.time()))
            except Exception as e:
                if getattr(e, "code", None) != "E_JDWP_TIMEOUT":
                    reason = "error"
                    errors.append(f"wait: {str(e)[:120]}")
                    log_progress(f"framework watch loop: {e}")
                break
            errors.extend(r.lease.errors)
            for h in d.deferred_handlers(OWNER):
                owned.update(h["installed_rids"])
            if r["events"]:
                unrelated += len(r["events"])
                d.stash(r)
                if len(d._pending) > max_queue:
                    reason = "queue_pressure"
                    break
            if cfg["_stop"]:
                reason = cfg["_stop"]
                break
            if out_bytes >= max_output_bytes:
                reason = "max_output_bytes"
                break
    finally:
        sub.close()
        for h in d.deferred_handlers(OWNER):
            owned.update(h["installed_rids"])
        auto_installed = sorted(owned - base_owned)
        unconfirmed = []
        if d.epoch != epoch:
            # reconnected mid-watch: handles are dead and the numeric ids
            # may have been reused by the new connection — never clear
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
                          counts={**cfg["_stats"], "unrelated": unrelated})
    fams = sorted({p["family"] for p in profs})
    out = {"records": records,
           "counts": {**cfg["_stats"], "unrelated": unrelated},
           "reason": reason, "truncated": reason == "max_output_bytes",
           "captured_bytes": out_bytes,
           "installed": len(rep["installed"]), "pending": rep["pending"],
           "states": rep["states"], "deferred": rep["deferred"],
           "auto_installed": auto_installed, "unconfirmed": unconfirmed,
           "errors": errors, "cleanup_errors": cleanup_errors,
           "run_id": run_id,
           "transactions": _transactions(cfg),
           "correlations": _correlation_summary(records),
           "lookup_summary": _lookup_summary(cfg),
           "coverage_notes": {f: COVERAGE_NOTES.get(f) for f in fams
                              if f in COVERAGE_NOTES}}
    return out


# ------------------------------------------------------------ offline query
def query_events(project, run_id: str | None = None,
                 family: str | None = None, profile: str | None = None,
                 role: str | None = None, limit: int = 50,
                 offset: int = 0) -> dict:
    """Paginated offline query over persisted framework-watch records
    (events of kind "framework_event"). Filters: run_id, profile family,
    source profile, and role (request|lifecycle|staged|submit|lookup).
    Follows the `runs list` pagination shape (issue #33/#36)."""
    where, params = ["e.kind='framework_event'"], []
    if run_id:
        where.append("e.run_id=?")
        params.append(run_id)
    if family:
        where.append("e.payload LIKE ?")
        params.append(f'%"family":"{family}"%')
    if profile:
        where.append("e.payload LIKE ?")
        params.append(f'%"profile":"{profile}"%')
    if role:
        where.append("e.payload LIKE ?")
        params.append(f'%"role":"{role}"%')
    cond = " AND ".join(where)
    with project.db() as db:
        rows = db.query(
            "SELECT e.event_id, e.run_id, e.class_sig, e.method_name, "
            "e.method_sig, e.payload FROM events e JOIN runs r ON "
            "r.run_id=e.run_id WHERE " + cond +
            " ORDER BY e.rowid LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = db.one(
            "SELECT COUNT(*) AS n FROM events e JOIN runs r ON "
            "r.run_id=e.run_id WHERE " + cond, tuple(params))["n"]
    records = []
    for row in rows:
        payload = json.loads(row.pop("payload") or "{}")
        row["family"] = payload.get("family")
        row["profile"] = payload.get("profile")
        row["role"] = payload.get("role")
        row["op"] = payload.get("op")
        row["service"] = payload.get("service")
        row["attribution"] = payload.get("attribution")
        row["status"] = payload.get("status", "ok")
        records.append(row)
    return {"records": records, "count": len(records), "total": total,
            "limit": limit, "offset": offset,
            "truncated": offset + len(records) < total}

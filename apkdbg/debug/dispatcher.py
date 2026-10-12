"""Session-owned event dispatcher — one routing, lease, and cleanup layer
shared by crypto hooks, breakpoints, conditions, coverage, and watchers.

Ownership and epochs
--------------------
Every JDWP event request is registered (EventDispatcher.register) with an
explicit owner, event kind, and epoch stamp. Request ids and type ids are
per-connection: DebugSession._attach calls bump_epoch(), which kills every
live handle — subscriptions from an older epoch go inactive and lookups of
stale-stamped entries fail, so two connection epochs (or two sessions) may
reuse numeric request ids without cross-contamination. Symbolic hook and
source-breakpoint definitions are retained across epochs (symbolic_hooks,
define_source) as the input of DebugSession.restore_requests(); live
request ids are not, and an explicit clear of a definition's last live
entry drops the definition so restore never resurrects it. Remote
cleanup of a dead epoch is UNCONFIRMED by definition: never send a clear or
claim a resume succeeded without transport confirmation.

Routing
-------
dispatch() routes each composite ONCE. Every event is matched to a live
registry entry by request id AND event kind, then delivered to the active
subscription(s) of the entry's owner. Events with no live entry, a kind
mismatch, or no interested subscription are UNCLAIMED: they are returned to
the caller of next_routed()/wait_events(). Background loops (crypto watch,
coverage, conditions) stash() unclaimed composites, preserving them for the
public debugger interface (wait_events drains the stash first). Resume
responsibility for unclaimed suspensions transfers to whoever eventually
consumes them — a watch loop never resumes threads from events it does not
own, and an unclaimed stop stays suspended until its consumer resumes it
(standard debugger semantics for a user-visible stop).

Suspension lease
----------------
All threads suspended by the claimed events of one composite form a shared
SuspensionLease. Subscriber callbacks run first; only then does the lease
release each suspension exactly once per thread — never twice, never before
every owning consumer finished. A subscriber may retain() a thread to
preserve a user-owned stop (e.g. a matched conditional breakpoint stays
suspended for inspection). SP_NONE composites never trigger a resume.
SP_ALL is released per event-thread (status quo; a full VM resume would
also drop unrelated user stops).

Deferred install
----------------
defer_hook() registers a CLASS_PREPARE watch; when a matching class
prepares, the dispatcher runs the install callback exactly once per type_id
(each classloader instance prepares its own type_id, so multi-loader
dedupe falls out of type_id identity; the loader id is recorded in the
registry entry when the VM answers ReferenceType.ClassLoader).
"""

from __future__ import annotations

from ..device.jdwp import (
    EVK_BREAKPOINT, EVK_CLASS_PREPARE, SP_ALL, SP_EVENT_THREAD, SP_NONE,
)
from ..protocol import log_progress


def _symbolic_key(meta: dict | None) -> tuple | None:
    """Symbolic-definition key of a registry entry: hooks by (owner, hook
    name), source breakpoints by ("user", spec), deferred CLASS_PREPARE
    watches by (owner, deferred key). Entries without a symbolic def
    (one-shot step requests) return None."""
    if not meta:
        return None
    if meta.get("hook_def") is not None:
        return (meta.get("owner"), meta.get("hook"))
    if meta.get("entry") == "source" and meta.get("spec"):
        return ("user", meta["spec"])
    if meta.get("entry") == "deferred":
        return (meta.get("owner"), meta.get("deferred"))
    return None


class SuspensionLease:
    """Shared suspension set of one routed composite. Released exactly once
    per thread after every owning consumer finished; retained threads
    (user-owned stops) are never force-resumed."""

    def __init__(self, session, threads: set[int]):
        self._session = session
        self.threads = frozenset(threads)
        self._retained: set[int] = set()
        self.released = False
        self.errors: list[str] = []

    def retain(self, thread: int) -> None:
        """Keep `thread` suspended: ownership of the stop transfers to the
        retaining consumer (it must resume explicitly, or document that the
        stop is left for the user)."""
        self._retained.add(thread)

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        for t in sorted(set(self.threads) - self._retained):
            try:
                self._session.client.thread_resume(t)
            except Exception as e:
                self.errors.append(f"resume {t}: {str(e)[:80]}")


class Subscription:
    """One consumer's claim on events owned by `owner` (optionally narrowed
    to a set of request ids). Bound to the creation epoch: a reconnect
    inactivates it, so a stale subscription can never claim events from a
    reused request id of a later epoch."""

    def __init__(self, dispatcher: EventDispatcher, owner: str,
                 callback, request_ids: set[int] | None = None):
        self._d = dispatcher
        self.owner = owner
        self.callback = callback
        self.request_ids = set(request_ids) if request_ids is not None else None
        self.epoch = dispatcher.epoch
        self.closed = False

    @property
    def active(self) -> bool:
        return not self.closed and self.epoch == self._d.epoch

    def matches(self, request_id: int) -> bool:
        return self.request_ids is None or request_id in self.request_ids

    def close(self) -> None:
        self.closed = True
        try:
            self._d._subs.remove(self)
        except ValueError:
            pass


class RoutedResult(dict):
    """Composite-shaped dict ({"suspend_policy", "events"}) whose "events"
    hold only the UNCLAIMED events. Claimed events and the lease are
    attributes, keeping the dict itself JSON-native for cmd_events."""

    def __init__(self, composite: dict, unclaimed: list[dict],
                 claimed: list[dict], lease: SuspensionLease):
        super().__init__(
            suspend_policy=composite.get("suspend_policy", SP_NONE),
            events=unclaimed)
        self.composite = composite
        self.claimed = claimed
        self.lease = lease


class EventDispatcher:
    """Per-session registry (epoch + request id -> meta), event router,
    suspension-lease manager, and deferred-install coordinator."""

    def __init__(self, session):
        self.session = session
        self.epoch = 0
        self._subs: list[Subscription] = []
        self._deferred: dict[int, dict] = {}   # CLASS_PREPARE rid -> handler
        self._pending: list[dict] = []         # stashed unclaimed composites
        self._symbolic: dict[tuple, dict] = {}  # survives epoch bumps

    # ------------------------------------------------------------- registry
    def register(self, request_id: int, meta: dict) -> dict:
        meta["_epoch"] = self.epoch
        self.session.bp_registry[request_id] = meta
        if meta.get("hook_def") is not None:
            self._symbolic[(meta.get("owner"), meta.get("hook"))] = {
                "owner": meta.get("owner"), "hook": meta.get("hook"),
                "hook_def": meta["hook_def"],
                "capture_returns": not meta.get("can_invoke", True)}
        return meta

    def define_source(self, spec: str, resolved: dict,
                      suspend_all: bool) -> None:
        """Record the symbolic definition of a source breakpoint (the
        resolved translation is connection-independent: class signature,
        dalvik line, method descriptors). It survives epoch bumps and is
        the input of restore_requests(); live request ids never do."""
        self._symbolic[("user", spec)] = {
            "owner": "user", "entry": "source", "spec": spec,
            "resolved": resolved,
            "suspend_policy": SP_ALL if suspend_all else SP_EVENT_THREAD}

    def unregister(self, request_id: int) -> dict | None:
        self._deferred.pop(request_id, None)
        meta = self.session.bp_registry.pop(request_id, None)
        key = _symbolic_key(meta)
        if key is not None and not any(
                _symbolic_key(m) == key
                for m in self.session.bp_registry.values()):
            # the last live entry of the definition was explicitly
            # cleared: restore must not resurrect it
            self._symbolic.pop(key, None)
        return meta

    def is_live(self, meta: dict | None) -> bool:
        return meta is not None and meta.get("_epoch") in (None, self.epoch)

    def lookup(self, request_id: int | None,
               kind: int | None = None) -> dict | None:
        """Live registry entry for `request_id`, optionally requiring the
        event kind it was registered under (kind mismatches route nowhere)."""
        if request_id is None:
            return None
        meta = self.session.bp_registry.get(request_id)
        if not self.is_live(meta):
            return None
        if kind is not None and meta.get("kind", EVK_BREAKPOINT) != kind:
            return None
        return meta

    def bump_epoch(self) -> None:
        """New connection epoch: request/type ids from the old connection
        are dead. Subscriptions carry their creation epoch and go inactive
        lazily; deferred installs and stashed events reference dead ids and
        are dropped. Symbolic hook definitions survive for re-install."""
        self.epoch += 1
        self._deferred.clear()
        self._pending.clear()

    def symbolic_hooks(self) -> list[dict]:
        """Symbolic hook definitions seen in any epoch (owner, hook name,
        hook_def, capture_returns) — the input of the re-install path."""
        return list(self._symbolic.values())

    # -------------------------------------------------------- subscriptions
    def subscribe(self, owner: str, callback,
                  request_ids: set[int] | None = None) -> Subscription:
        sub = Subscription(self, owner, callback, request_ids)
        self._subs.append(sub)
        return sub

    # ------------------------------------------------------ deferred hooks
    def defer_hook(self, owner: str, key: str, pattern: str,
                   on_prepare, symbolic: dict | None = None) -> int:
        """Register (or reuse) a CLASS_PREPARE watch for `pattern`. When a
        matching class prepares, on_prepare(event, handler) runs exactly
        once per type_id; handler["installed_rids"]/["errors"] accumulate
        the outcome."""
        for rid, h in self._deferred.items():
            if (h["owner"] == owner and h["key"] == key
                    and self.lookup(rid, EVK_CLASS_PREPARE) is not None):
                return rid
        c = self.session.client
        rid = c.set_event(EVK_CLASS_PREPARE, SP_EVENT_THREAD,
                          [c.mod_class_match(pattern)])
        self.register(rid, {"owner": owner, "kind": EVK_CLASS_PREPARE,
                            "entry": "deferred", "deferred": key,
                            "pattern": pattern})
        self._deferred[rid] = {"owner": owner, "key": key,
                               "on_prepare": on_prepare, "seen": set(),
                               "installed_rids": [], "errors": []}
        if symbolic is not None:
            self._symbolic[(owner, key)] = symbolic
        return rid

    def deferred_handlers(self, owner: str) -> list[dict]:
        return [h for h in self._deferred.values() if h["owner"] == owner]

    def _run_deferred(self, handler: dict, ev: dict) -> None:
        type_id = ev.get("type_id")
        if type_id is None or type_id in handler["seen"]:
            return
        handler["seen"].add(type_id)  # exactly one attempt per class instance
        try:
            handler["on_prepare"](ev, handler)
        except Exception as e:
            handler["errors"].append(str(e)[:120])
            log_progress(f"deferred install {handler['key']}: {e}")

    # -------------------------------------------------------------- routing
    def dispatch(self, composite: dict) -> RoutedResult:
        sp = composite.get("suspend_policy", SP_NONE)
        deliveries: list[tuple[Subscription, dict]] = []
        claimed: list[dict] = []
        unclaimed: list[dict] = []
        for ev in composite.get("events", []):
            self.session._enrich_event(ev)
            rid = ev.get("request_id")
            entry = self.lookup(rid, ev.get("kind_id"))
            if entry is not None and rid in self._deferred:
                self._run_deferred(self._deferred[rid], ev)
                claimed.append(ev)
                continue
            subs = [s for s in self._subs
                    if entry is not None and s.active
                    and s.owner == entry.get("owner") and s.matches(rid)]
            if subs:
                claimed.append(ev)
                for s in subs:
                    deliveries.append((s, ev))
            else:
                unclaimed.append(ev)
        threads = set()
        if sp != SP_NONE:  # SP_NONE events never trigger a resume
            for ev in claimed:
                t = ev.get("thread")
                if t is not None:
                    threads.add(t)
        lease = SuspensionLease(self.session, threads)
        for s, ev in deliveries:
            try:
                s.callback(ev, lease)
            except Exception as e:
                lease.errors.append(f"{s.owner}: {str(e)[:120]}")
        lease.release()
        return RoutedResult(composite, unclaimed, claimed, lease)

    def next_routed(self, timeout: float | None = None) -> RoutedResult:
        """Fetch one composite from the transport and route it. Never drains
        the stash — that is the public wait_events path. Read-only and
        handle-free: after a scoped reconnect it may re-block on the new
        connection's event stream (issue #32 op class "read", re-resolve)."""
        comp = self.session._op(lambda c: c.next_event(timeout),
                                _class="read", _name="wait_events",
                                _reresolve=True)
        return self.dispatch(comp)

    # ---------------------------------------------------------------- stash
    def stash(self, routed: dict) -> None:
        """Preserve unclaimed events for the public debugger interface.
        Their suspensions (if any) stay in place; resume responsibility
        transfers to the eventual consumer."""
        events = routed.get("events") or []
        if events:
            self._pending.append({
                "suspend_policy": routed.get("suspend_policy", SP_NONE),
                "events": list(events)})

    def drain(self) -> dict | None:
        if not self._pending:
            return None
        events, sp = [], SP_NONE
        for comp in self._pending:
            sp = comp["suspend_policy"]
            events.extend(comp["events"])
        self._pending.clear()
        return {"suspend_policy": sp, "events": events, "stashed": True}

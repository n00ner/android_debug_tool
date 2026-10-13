"""Branch coverage tracking over JDWP, with overhead controls.

Two modes, cheapest first:

  method  — METHOD_ENTRY events with ClassMatch modifiers (e.g. "com.foo.*")
            and suspend policy NONE: the VM never stops, events stream into
            the composite queue. Overhead is a hash-bump per entered method;
            safe to run for minutes on real apps. Answers "which methods ran".

  line    — SINGLE_STEP events (STEP_LINE/STEP_INTO) restricted with
            ThreadOnly + ClassMatch modifiers, suspend EVENT_THREAD, hard
            event budget and wall-clock cap. This is expensive (~100-1000x
            slowdown of the stepped thread) so it is opt-in, thread-scoped,
            package-scoped, and time-boxed. Answers "which lines ran" and,
            via the smali branch_sites table, "which branch directions ran".

Method identity (issue #37): hits are keyed by the full identity
class signature + method name + method descriptor everywhere — in memory,
in the persisted coverage_hits rows, and in branch-site lookups — so
overloads never merge. Distinct JDWP type ids seen for one class signature
(distinguishable classloader copies) are tracked per-copy in memory and
reported in the persisted report; type ids are per-connection, so only
descriptors are persisted as row identity.

Line mapping: a location's line is the one attached to the nearest
preceding bytecode index of the runtime LineNumberTable (correct for
non-monotonic tables). The observed (bytecode index -> line) evidence is
kept per method and reported alongside the per-line hit counts. A missing
or uncovering table is recorded as an explicit `missing_table` unknown,
never silently dropped.

Branch resolution (line mode): remember the previous observed location per
thread; when the previous line holds branch sites of the previous method,
the current location decides the outcome — but an edge (taken/fall-through)
is claimed only when the static site mapping plus the runtime locations
support exactly one reading:

  - if-site, single site on the line: current line == target line means
    TAKEN (same-line targets included); current line == the table's next
    line means FALL-THROUGH.
  - several sites on one line: TAKEN only when the current line matches
    exactly one site's target; anything else is `ambiguous_line`.
  - goto: the site observation is recorded as a site hit; the jump edge is
    identified only when the current line is the resolved target.
  - switch: a site observation is NOT a case edge (no case table is stored
    statically); the outcome stays `unresolved_target`.

Everything else keeps an unknown with a reason: `method_transition`
(calls/returns/recursion across methods), `exceptional_flow` (same-method
jump that is neither target nor fall-through — e.g. a catch block),
`trace_gap` (capture ended or evidence truncated right after a site line),
`missing_table`, `step_granularity` (line-level stepping re-stopped on the
same line without resolving the branch), `ambiguous_line`.

report() is idempotent: finalization (dangling trace gaps + the
coverage_hits/coverage_branch_sites flush) happens exactly once, so
repeated report calls never change persisted data. Branch outcomes are
persisted with taken/fallthrough/unknown (with reasons) in separate
columns, keyed by the descriptor-level site key
(class->name(desc):dalvik_line:smali_line) — the local integer
branch_sites.id is not portable between rebuilt indexes and is never
persisted (issue #29).

Event consumption goes through the session dispatcher: the tracker
registers its request under a per-run owner and receives only its own
events via a subscription. Line-mode thread resumes are released by the
composite's shared lease (once per thread, after every consumer of the
composite finished); SP_NONE method-mode events never resume. Events owned
by others (user breakpoints, crypto hooks) are never consumed or resumed —
they are stashed back for the public wait_events interface, whose caller
owns resume responsibility.

Every run is also persisted as a versioned run manifest (issue #36, see
core/manifests.py) when the session has a project: the run_id the
coverage_hits rows already carry becomes the manifest's durable identity,
with capture config, environment, epoch, and completion reason recorded,
and the final report stored as a run artifact. Line/method captures are
time- or budget-boxed samples, so the artifact's truncation block marks
them incomplete with the stop reason and dropped-event count.
"""

from __future__ import annotations

import json
import time
import uuid

from ..device.jdwp import (
    EVK_METHOD_ENTRY, EVK_SINGLE_STEP, SP_EVENT_THREAD, SP_NONE,
    STEP_INTO, STEP_LINE, JdwpClient,
)
from ..core.manifests import RunStore, capture_environment
from ..errors import SessionError

DEFAULT_BUDGET = 20000
DEFAULT_SECONDS = 60


class CoverageTracker:
    def __init__(self, session, packages: list[str], *,
                 mode: str = "method", thread: int | None = None,
                 budget: int = DEFAULT_BUDGET, seconds: int = DEFAULT_SECONDS,
                 scenario: str | None = None):
        if mode not in ("method", "line"):
            raise SessionError(f"bad coverage mode {mode!r}",
                               hint="method | line")
        if mode == "line" and thread is None:
            raise SessionError("line coverage needs a target thread",
                               hint="suspend at a breakpoint first, or pass "
                                    "thread id from an event")
        self.session = session
        self.packages = packages
        self.mode, self.thread = mode, thread
        self.budget, self.seconds = budget, seconds
        self.scenario = scenario
        self.run_id = uuid.uuid4().hex[:8]
        self.method_hits: dict[str, int] = {}
        self.line_hits: dict[str, dict[int, int]] = {}
        self.offset_hits: dict[str, dict[int, dict]] = {}
        self.branch_outcomes: dict[str, dict] = {}
        self.unknowns: dict[tuple, dict] = {}
        # cls_sig -> {type_id: loader_id}: distinguishable classloader
        # copies of one class (JDWP type ids are per-connection, so this
        # is in-memory evidence only; descriptors are what persists)
        self._copies: dict[str, dict[int, int | None]] = {}
        self._last: dict[int, dict] = {}  # thread -> location record
        self._method_cache: dict[tuple[int, int], tuple[str, str]] = {}
        self._lt_cache: dict[tuple[int, int], list | None] = {}
        self._events = 0
        self._dropped = 0
        self._finalized = False

    # ------------------------------------------------------------------ run
    def run(self, cancel=None) -> dict:
        """cancel: cooperative cancellation (issue #34) — any object with
        is_set(); while passed, event waits are sliced so a cancel is
        observed within ~1s, and the stop reason is "cancelled"."""
        c = self.session.client
        d = self.session.events
        # durable run manifest (issue #36): same run_id the coverage_hits
        # rows already carry, now with full capture conditions; skipped for
        # project-less sessions
        store = RunStore.for_session(self.session)
        if store is not None:
            store.begin_run(
                "coverage", run_id=self.run_id, scenario=self.scenario,
                capture_config={"mode": self.mode, "packages": self.packages,
                                "budget": self.budget, "seconds": self.seconds,
                                "thread": self.thread},
                epoch=d.epoch,
                environment=capture_environment(self.session))
        mods = [c.mod_class_match(f"{p}.*") for p in self.packages]
        if self.mode == "method":
            kind, policy = EVK_METHOD_ENTRY, SP_NONE
        else:
            mods.append(c.mod_thread_only(self.thread))
            # SINGLE_STEP requests require the Step modifier (size+depth);
            # without it ART accepts the request but never fires it
            mods.append(c.mod_step(self.thread, STEP_LINE, STEP_INTO))
            kind, policy = EVK_SINGLE_STEP, SP_EVENT_THREAD
        rid = c.set_event(kind, policy, mods)
        owner = f"coverage:{self.run_id}"
        d.register(rid, {"owner": owner, "kind": kind, "entry": "coverage",
                         "run_id": self.run_id, "mode": self.mode})
        if self.mode == "line":
            c.thread_resume(self.thread)

        sub = d.subscribe(owner, self._on_event, request_ids={rid})
        deadline = time.time() + self.seconds
        cancelled = False
        try:
            while self._events < self.budget and time.time() < deadline:
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break
                wait = max(1.0, deadline - time.time())
                if cancel is not None:
                    wait = min(wait, 1.0)  # sliced: cancel visible ~1s
                try:
                    r = d.next_routed(timeout=wait)
                except Exception as e:
                    if cancel is not None \
                            and getattr(e, "code", None) == "E_JDWP_TIMEOUT" \
                            and time.time() < deadline:
                        continue  # sliced wait expired; the window has not
                    break
                if r["events"]:
                    d.stash(r)  # not ours: preserve for wait_events
        finally:
            sub.close()
            self.session.clear_request(rid)  # kind-correct, epoch-checked
        rep = self.report()
        # both stop conditions mean the capture is a bounded sample, not an
        # exhaustive trace: it stays explicitly incomplete (issue #37)
        if cancelled:
            reason = "cancelled"
        else:
            reason = "budget" if self._events >= self.budget else "duration"
        rep["stop_reason"] = reason
        rep["complete"] = False
        rep["dropped_events"] = self._dropped
        if store is not None:
            store.end_run(self.run_id, reason,
                          counts={"events": self._events,
                                  "dropped_events": self._dropped,
                                  "methods": len(self.method_hits),
                                  "lines": sum(len(v) for v in
                                               self.line_hits.values()),
                                  "unknowns": sum(u["count"] for u in
                                                  self.unknowns.values())})
            store.add_artifact(self.run_id, "coverage_report", rep,
                               epoch=d.epoch,
                               truncation={"complete": False,
                                           "stop_reason": reason,
                                           "dropped_events": self._dropped})
            rep["recorded"] = True
        return rep

    def _on_event(self, e: dict, lease) -> None:
        if "location" not in e:
            self._dropped += 1
            return
        self._events += 1
        self._record(e)
        # line mode: the lease releases the thread's suspension after all
        # consumers of this composite finished (once per thread)

    # ---------------------------------------------------------------- record
    def _record(self, e: dict) -> None:
        c: JdwpClient = self.session.client
        loc = e["location"]
        cls_sig = self.session._sig_of(loc["class"])
        mname, msig = self._method_info(c, loc["class"], loc["method"])
        self._note_copy(c, cls_sig, loc["class"])
        line = self._line_of(c, loc)
        key = f"{cls_sig}->{mname}{msig}"

        if self.mode == "method":
            self.method_hits[key] = self.method_hits.get(key, 0) + 1
            return

        if line is None:
            self._note_unknown("missing_table", key, None)
        else:
            lines = self.line_hits.setdefault(key, {})
            lines[line] = lines.get(line, 0) + 1
        offsets = self.offset_hits.setdefault(key, {})
        off = offsets.setdefault(loc["index"], {"line": line, "hits": 0})
        off["hits"] += 1

        # branch transition from the previously observed line in this thread
        cur = {"cls": cls_sig, "name": mname, "sig": msig, "line": line,
               "index": loc["index"], "type_id": loc["class"],
               "method_id": loc["method"], "key": key}
        tid = e.get("thread", 0)
        prev = self._last.get(tid)
        if prev:
            self._resolve_branch(prev, cur)
        self._last[tid] = cur

    # ------------------------------------------------------------- branches
    def _resolve_branch(self, prev: dict, cur: dict) -> None:
        sites = self._sites_at(prev)
        same_method = (prev["cls"], prev["name"], prev["sig"]) == \
                      (cur["cls"], cur["name"], cur["sig"])
        if not same_method:
            # call/return/recursion/exception across methods: the line-level
            # trace carries no evidence about the branch outcome
            if sites:
                for s in sites:
                    rec = self._site_rec(prev, s)
                    self._bump_unknown(rec, "method_transition")
            else:
                self._note_unknown("method_transition", prev["key"],
                                   prev["line"])
            return
        if not sites:
            return
        if prev["line"] is None or cur["line"] is None:
            for s in sites:
                self._bump_unknown(self._site_rec(prev, s), "missing_table")
            return
        if len(sites) > 1:
            # several instructions share one source line: claim an edge
            # only when the current line matches exactly one site's target
            matches = [s for s in sites
                       if s["kind"] != "switch"
                       and s["target_dalvik_line"] is not None
                       and s["target_dalvik_line"] == cur["line"]]
            if len(matches) == 1 and not (
                    matches[0]["kind"] == "if"
                    and self._is_next_line(prev, cur)):
                rec = self._site_rec(prev, matches[0])
                rec["site_hits"] += 1
                rec["taken"] += 1
            else:
                for s in sites:
                    rec = self._site_rec(prev, s)
                    rec["site_hits"] += 1
                    self._bump_unknown(rec, "ambiguous_line")
            return
        site = sites[0]
        rec = self._site_rec(prev, site)
        rec["site_hits"] += 1
        tgt = site["target_dalvik_line"]
        if site["kind"] == "switch":
            # a switch site observation is not an observed case edge: the
            # static index stores no case->target table
            self._bump_unknown(rec, "unresolved_target")
        elif tgt is None:
            self._bump_unknown(rec, "unresolved_target")
        elif cur["line"] == tgt:
            if site["kind"] == "if" and self._is_next_line(prev, cur):
                # target line == fall-through line: line granularity
                # cannot distinguish the two edges
                self._bump_unknown(rec, "ambiguous_line")
            else:
                # taken edge; same-line targets covered by the equality
                rec["taken"] += 1
        elif site["kind"] == "goto":
            # a goto always jumps; landing anywhere else means the evidence
            # is missing (exception/truncation between site and target)
            self._bump_unknown(rec, "exceptional_flow")
        elif self._is_next_line(prev, cur):
            rec["fallthrough"] += 1
        elif cur["line"] == prev["line"]:
            # re-stopped on the same line without resolving the branch:
            # STEP_LINE granularity omitted the deciding instruction
            self._bump_unknown(rec, "step_granularity")
        else:
            # same-method jump that is neither target nor fall-through
            # (catch block, loop exit through another path, ...)
            self._bump_unknown(rec, "exceptional_flow")

    def _sites_at(self, loc: dict) -> list[dict]:
        """All branch sites of loc's line in loc's exact method (class sig +
        name + descriptor join), in instruction order — never a LIMIT 1
        pick: several sites can share one dalvik line."""
        if self.session.project is None or loc["line"] is None:
            return []
        with self.session.project.db() as db:
            return db.query(
                "SELECT bs.* FROM branch_sites bs JOIN methods m ON "
                "m.id=bs.method_id JOIN classes c ON c.id=m.class_id "
                "WHERE c.sig=? AND m.name=? AND m.sig=? AND "
                "bs.dalvik_line=? ORDER BY bs.smali_line",
                (loc["cls"], loc["name"], loc["sig"], loc["line"]))

    def _site_rec(self, prev: dict, site: dict) -> dict:
        # site identity: full method identity + dalvik line + the site's
        # instruction identity within the method (its smali file line)
        key = f"{prev['key']}:{site['dalvik_line']}:{site['smali_line']}"
        return self.branch_outcomes.setdefault(
            key, {"site_id": site["id"], "class": prev["cls"],
                  "method": prev["name"], "sig": prev["sig"],
                  "line": site["dalvik_line"],
                  "smali_line": site["smali_line"], "op": site["opcode"],
                  "kind": site["kind"], "site_hits": 0, "taken": 0,
                  "fallthrough": 0, "unknown": {}})

    @staticmethod
    def _bump_unknown(rec: dict, reason: str) -> None:
        rec["unknown"][reason] = rec["unknown"].get(reason, 0) + 1

    def _is_next_line(self, prev: dict, cur: dict) -> bool:
        """Fall-through evidence: cur's line is the one the runtime line
        table attaches to the first bytecode region after prev's index."""
        table = self._line_table(self.session.client, prev["type_id"],
                                 prev["method_id"])
        if not table:
            return False
        for e in table:
            if e["index"] > prev["index"]:
                return e["line"] == cur["line"]
        return False

    def _note_unknown(self, reason: str, key: str,
                      line: int | None) -> None:
        k = (reason, key, line)
        if k in self.unknowns:
            self.unknowns[k]["count"] += 1
        else:
            self.unknowns[k] = {"reason": reason, "method": key,
                                "line": line, "count": 1}

    # ------------------------------------------------------------ identity
    def _method_info(self, c: JdwpClient, type_id: int,
                     method_id: int) -> tuple[str, str]:
        k = (type_id, method_id)
        if k not in self._method_cache:
            m = next((m for m in c.rt_methods(type_id)
                      if m["id"] == method_id), None)
            self._method_cache[k] = (m["name"], m["sig"]) if m else ("?", "")
        return self._method_cache[k]

    def _note_copy(self, c: JdwpClient, cls_sig: str, type_id: int) -> None:
        copies = self._copies.setdefault(cls_sig, {})
        if type_id not in copies:
            try:
                copies[type_id] = c.rt_class_loader(type_id)
            except Exception:
                copies[type_id] = None

    # ------------------------------------------------------------ line map
    def _line_table(self, c: JdwpClient, type_id: int,
                    method_id: int) -> list | None:
        k = (type_id, method_id)
        if k not in self._lt_cache:
            try:
                self._lt_cache[k] = \
                    c.method_line_table(type_id, method_id)["lines"]
            except Exception:
                self._lt_cache[k] = None
        return self._lt_cache[k]

    def _line_of(self, c: JdwpClient, loc: dict) -> int | None:
        """Line attached to the nearest preceding bytecode index — correct
        for non-monotonic tables (e.g. (index=0,line=100),(index=4,line=10)
        maps index 4 to 10, not to max(100,10)). None when the table is
        missing or has no entry covering the index; callers record that as
        an explicit missing_table unknown."""
        table = self._line_table(c, loc["class"], loc["method"])
        if not table:
            return None
        best = None
        for e in table:
            if e["index"] <= loc["index"]:
                best = e["line"]
            else:
                break
        return best

    # ---------------------------------------------------------------- report
    def report(self) -> dict:
        self._finalize()
        out = {"run_id": self.run_id, "mode": self.mode,
               "events": self._events, "packages": self.packages}
        copies = {sig: {"type_ids": sorted(ids),
                        "loaders": sorted({l for l in ids.values()
                                           if l is not None})}
                  for sig, ids in self._copies.items() if len(ids) > 1}
        if copies:
            out["loaded_copies"] = copies
        if self.unknowns:
            out["unknowns"] = sorted(
                self.unknowns.values(),
                key=lambda u: (u["reason"], u["method"],
                               u["line"] if u["line"] is not None else -1))
        if self.mode == "method":
            out["methods"] = dict(sorted(self.method_hits.items(),
                                         key=lambda kv: -kv[1]))
        else:
            out["lines"] = {k: dict(sorted(v.items())) for k, v in
                            self.line_hits.items()}
            out["offsets"] = {
                k: {str(i): e for i, e in sorted(v.items())}
                for k, v in self.offset_hits.items()}
            out["branches"] = {
                "sites_hit": sum(1 for r in self.branch_outcomes.values()
                                 if r["site_hits"]),
                "edges_identified": sum(
                    r["taken"] + r["fallthrough"]
                    for r in self.branch_outcomes.values()),
                "unknown_transitions": sum(
                    sum(r["unknown"].values())
                    for r in self.branch_outcomes.values()),
                "detail": self.branch_outcomes}
        return out

    def _finalize(self) -> None:
        """Runs exactly once: dangling per-thread locations get a trace_gap
        unknown for every site on their line, then line hits are flushed.
        Keeps report() idempotent — repeated calls change nothing."""
        if self._finalized:
            return
        self._finalized = True
        if self.mode == "line":
            for loc in self._last.values():
                for s in self._sites_at(loc):
                    self._bump_unknown(self._site_rec(loc, s), "trace_gap")
            self._flush_db()

    def _flush_db(self) -> None:
        if self.session.project is None:
            return
        with self.session.project.db() as db:
            for key, lines in self.line_hits.items():
                cls, m = key.split("->", 1)
                i = m.find("(")
                mname, msig = (m[:i], m[i:]) if i >= 0 else (m, "")
                for line, hits in lines.items():
                    db.execute(
                        "INSERT INTO coverage_hits(run_id,class_sig,"
                        "method_name,method_sig,dalvik_line,hits) "
                        "VALUES(?,?,?,?,?,?)",
                        (self.run_id, cls, mname, msig, line, hits))
            for site_key, rec in self.branch_outcomes.items():
                db.execute(
                    "INSERT INTO coverage_branch_sites(run_id,site_key,"
                    "class_sig,method_name,method_sig,dalvik_line,"
                    "smali_line,opcode,kind,site_hits,taken,fallthrough,"
                    "unknowns) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (self.run_id, site_key, rec["class"], rec["method"],
                     rec["sig"], rec["line"], rec["smali_line"], rec["op"],
                     rec["kind"], rec["site_hits"], rec["taken"],
                     rec["fallthrough"],
                     json.dumps(rec["unknown"], separators=(",", ":"))
                     if rec["unknown"] else None))

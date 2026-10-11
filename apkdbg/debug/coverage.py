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

Branch resolution (line mode): remember the previous observed line per
thread; when the previous line is an if-* site, the current line decides the
outcome — equal to the recorded target line means TAKEN, anything else means
FALL-THROUGH. goto/switch sites are marked hit when executed.
"""

from __future__ import annotations

import time
import uuid

from ..device.jdwp import (
    EVK_METHOD_ENTRY, EVK_SINGLE_STEP, SP_EVENT_THREAD, SP_NONE,
    STEP_INTO, STEP_LINE, JdwpClient,
)
from ..errors import SessionError

DEFAULT_BUDGET = 20000
DEFAULT_SECONDS = 60


class CoverageTracker:
    def __init__(self, session, packages: list[str], *,
                 mode: str = "method", thread: int | None = None,
                 budget: int = DEFAULT_BUDGET, seconds: int = DEFAULT_SECONDS):
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
        self.run_id = uuid.uuid4().hex[:8]
        self.method_hits: dict[str, int] = {}
        self.line_hits: dict[str, dict[int, int]] = {}
        self.branch_outcomes: dict[str, dict] = {}
        self._last: dict[int, tuple[str, str, int]] = {}  # thread -> (cls,m,line)
        self._method_cache: dict[tuple[int, int], str] = {}
        self._events = 0

    # ------------------------------------------------------------------ run
    def run(self) -> dict:
        c = self.session.client
        mods = [c.mod_class_match(f"{p}.*") for p in self.packages]
        if self.mode == "method":
            rid = c.set_event(EVK_METHOD_ENTRY, SP_NONE, mods)
            kind = EVK_METHOD_ENTRY
        else:
            mods.append(c.mod_thread_only(self.thread))
            # SINGLE_STEP requests require the Step modifier (size+depth);
            # without it ART accepts the request but never fires it
            mods.append(c.mod_step(self.thread, STEP_LINE, STEP_INTO))
            rid = c.set_event(EVK_SINGLE_STEP, SP_EVENT_THREAD, mods)
            kind = EVK_SINGLE_STEP
            c.thread_resume(self.thread)

        deadline = time.time() + self.seconds
        try:
            while self._events < self.budget and time.time() < deadline:
                try:
                    ev = self.session.wait_events(
                        timeout=max(1.0, deadline - time.time()))
                except Exception:
                    break
                for e in ev.get("events", []):
                    if e.get("kind_id") != kind or "location" not in e:
                        continue
                    self._events += 1
                    self._record(e)
                    if self.mode == "line" and "thread" in e:
                        c.thread_resume(e["thread"])
        finally:
            c.clear_event(kind, rid)
        return self.report()

    # ---------------------------------------------------------------- record
    def _record(self, e: dict) -> None:
        c: JdwpClient = self.session.client
        loc = e["location"]
        cls_sig = self.session._sig_of(loc["class"])
        mname = self._method_name(c, loc["class"], loc["method"])
        line = self._line_of(c, loc)
        key = f"{cls_sig}->{mname}"

        if self.mode == "method":
            self.method_hits[key] = self.method_hits.get(key, 0) + 1
            return

        self.line_hits.setdefault(key, {})
        if line is not None:
            self.line_hits[key][line] = self.line_hits[key].get(line, 0) + 1

        # branch transition from the previously observed line in this thread
        tid = e.get("thread", 0)
        prev = self._last.get(tid)
        if prev and line is not None:
            self._resolve_branch(prev, (cls_sig, mname, line))
        self._last[tid] = (cls_sig, mname, line)

    def _resolve_branch(self, prev, cur) -> None:
        pcls, pm, pline = prev
        ccls, cm, cline = cur
        with self.session.project.db() as db:
            site = db.one(
                "SELECT bs.* FROM branch_sites bs JOIN methods m ON "
                "m.id=bs.method_id JOIN classes c ON c.id=m.class_id "
                "WHERE c.sig=? AND m.name=? AND bs.dalvik_line=? LIMIT 1",
                (pcls, pm, pline))
        if not site:
            return
        sid = site["id"]
        rec = self.branch_outcomes.setdefault(
            str(sid), {"class": pcls, "method": pm, "line": pline,
                       "op": site["opcode"], "taken": 0, "fallthrough": 0})
        same_method = pcls == ccls and pm == cm
        if site["kind"] in ("goto", "switch"):
            rec["taken"] += 1
        elif same_method and site["target_dalvik_line"] == cline:
            rec["taken"] += 1
        else:
            rec["fallthrough"] += 1

    def _method_name(self, c: JdwpClient, type_id: int, method_id: int) -> str:
        k = (type_id, method_id)
        if k not in self._method_cache:
            name = next((m["name"] for m in c.rt_methods(type_id)
                         if m["id"] == method_id), "?")
            self._method_cache[k] = name
        return self._method_cache[k]

    @staticmethod
    def _line_of(c: JdwpClient, loc: dict) -> int | None:
        try:
            lt = c.method_line_table(loc["class"], loc["method"])
            best = None
            for e in lt["lines"]:
                if e["index"] <= loc["index"]:
                    best = e["line"] if best is None else max(best, e["line"])
                else:
                    break
            return best
        except Exception:
            return None

    # ---------------------------------------------------------------- report
    def report(self) -> dict:
        out = {"run_id": self.run_id, "mode": self.mode,
               "events": self._events, "packages": self.packages}
        if self.mode == "method":
            out["methods"] = dict(sorted(self.method_hits.items(),
                                         key=lambda kv: -kv[1]))
        else:
            out["lines"] = {k: dict(sorted(v.items())) for k, v in
                            self.line_hits.items()}
            taken = sum(1 for r in self.branch_outcomes.values() if r["taken"])
            out["branches"] = {"sites_hit": len(self.branch_outcomes),
                               "with_taken_edge": taken,
                               "detail": self.branch_outcomes}
            self._flush_db()
        return out

    def _flush_db(self) -> None:
        with self.session.project.db() as db:
            for key, lines in self.line_hits.items():
                cls, mname = key.split("->", 1)
                for line, hits in lines.items():
                    db.execute(
                        "INSERT INTO coverage_hits(run_id,class_sig,"
                        "method_name,dalvik_line,hits) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(run_id,class_sig,method_name,dalvik_line)"
                        " DO UPDATE SET hits=hits+excluded.hits",
                        (self.run_id, cls, mname, line, hits))

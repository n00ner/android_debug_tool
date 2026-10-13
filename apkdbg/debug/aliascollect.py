"""Opt-in, budgeted string-observation collector (issue #25).

The collector consumes string values ALREADY captured by breakpoints
(conditional-capture), snapshots, and crypto-style watchers, and turns
them into reviewable alias candidates via the versioned heuristics of
core/aliases. It never invents reads on its own: by default it performs
ZERO additional JDWP requests and only analyzes capture output.

Optional EXTRA frame/heap reads (extra_reads=True) — reading string
fields of objects already referenced by a capture — are separately and
explicitly budgeted: depth, object count, byte count, JDWP request
count, and elapsed time. There is no zero-overhead assumption: every
collector run reports the JDWP requests it actually issued (jdwp_reads)
and the wall-clock pause time it added while the thread stayed suspended
(pause_s); no universal latency guarantee is made.

Suspension ownership stays with the dispatcher: the collector runs inside
a subscription callback and never resumes threads itself — the composite
SuspensionLease releases each suspension once, after every consumer
finished, including when the collector hit a budget or a read failed.
Budget exhaustion and read failures produce PARTIAL results with explicit
reasons and leave the session usable.

Attribution: strings inside a captured object node are attributed to that
object's runtime class; top-level strings to the capture context (frame
or hook class). Classloader identity is carried through from the capture
context when known, so identically named classes from distinct loaders
stay distinguishable (core/aliases never merges them).
"""

from __future__ import annotations

import time

from ..core import aliases
from ..device.jdwp import TAG_STRING

# record keys whose string values are structural, not app-data signals
_SKIP_KEYS = {"hook", "phase", "type", "capture_error", "meta_error",
              "error", "hex", "b64", "trunc"}


class CollectBudgets:
    """Budgets for one collector. The already-captured path is bounded by
    max_strings/max_str; EXTRA reads (extra_reads=True only) have their
    own depth/object/byte/request/elapsed limits."""

    def __init__(self, max_strings: int = 200, max_str: int = 256, *,
                 extra_reads: bool = False, max_extra_depth: int = 1,
                 max_extra_objects: int = 16, max_extra_bytes: int = 8192,
                 max_extra_requests: int = 64,
                 max_extra_seconds: float = 2.0):
        self.max_strings, self.max_str = max_strings, max_str
        self.extra_reads = extra_reads
        self.max_extra_depth = max_extra_depth
        self.max_extra_objects = max_extra_objects
        self.max_extra_bytes = max_extra_bytes
        self.max_extra_requests = max_extra_requests
        self.max_extra_seconds = max_extra_seconds

    def as_dict(self) -> dict:
        return {"max_strings": self.max_strings, "max_str": self.max_str,
                "extra_reads": self.extra_reads,
                "max_extra_depth": self.max_extra_depth,
                "max_extra_objects": self.max_extra_objects,
                "max_extra_bytes": self.max_extra_bytes,
                "max_extra_requests": self.max_extra_requests,
                "max_extra_seconds": self.max_extra_seconds}


class _BudgetExhausted(Exception):
    pass


class AliasCollector:
    """Feeds captured strings through the heuristic rules into an
    AliasStore. `store` may be None (project-less session): findings are
    still measured and reported, just not persisted."""

    def __init__(self, session=None, store: aliases.AliasStore | None = None,
                 budgets: CollectBudgets | None = None):
        self.session = session
        self.store = store
        self.b = budgets or CollectBudgets()
        self.reads = 0          # measured JDWP requests issued by the collector
        self.pause_s = 0.0      # measured pause time added (threads suspended)
        self.observations = 0
        self.suggestions = 0
        self.context_findings = 0
        self.partial = False
        self.reasons: list[str] = []

    # ------------------------------------------------------------- entry API
    def collect_from_record(self, record: dict, context: dict, *,
                            run_id: str | None = None,
                            event_id: str | None = None,
                            client=None) -> dict:
        """Consume a crypto-watch-style capture record (already-captured
        args/meta/return values). With budgets.extra_reads and a live
        client, string fields of captured objects are read under the
        extra-read budgets (the calling thread is still suspended — that
        time is measured and reported)."""
        t0 = time.monotonic()
        try:
            strings, objects = [], []
            self._walk_record(record, None, strings, objects)
            rep = self._observe(strings, context,
                                run_id=run_id, event_id=event_id)
            if objects and self.b.extra_reads and client is not None:
                rep["extra"] = self._extra_reads(
                    client, objects, context, run_id=run_id,
                    event_id=event_id)
            return rep
        except Exception as e:  # never break the owning watch loop
            self._flag(f"record collection failed: {str(e)[:100]}")
            return {"observations": 0, "suggestions": [],
                    "behavioral_context": [], "partial": True,
                    "reasons": [str(e)[:100]]}
        finally:
            self.pause_s += time.monotonic() - t0

    def collect_from_snapshot(self, node: dict, context: dict, *,
                              run_id: str | None = None,
                              artifact_id: str | None = None) -> dict:
        """Consume an already-captured snapshot/dump tree. Strings nested
        inside an object node are attributed to that object's class."""
        t0 = time.monotonic()
        try:
            by_class: dict[str | None, list] = {}
            self._walk_snapshot(node, context.get("class_sig"), None,
                                by_class)
            rep = {"observations": 0, "suggestions": [],
                   "behavioral_context": [], "partial": False,
                   "reasons": []}
            ev = {"kind": "snapshot"}
            if artifact_id:
                ev["artifact_id"] = artifact_id
            if run_id:
                ev["run_id"] = run_id
            for cls, strings in by_class.items():
                ctx = dict(context, class_sig=cls or context.get("class_sig"))
                sub = self._observe(strings, ctx, run_id=run_id,
                                    extra_evidence=[ev])
                for k in ("observations",):
                    rep[k] += sub[k]
                rep["suggestions"] += sub["suggestions"]
                rep["behavioral_context"] += sub["behavioral_context"]
                rep["partial"] = rep["partial"] or sub["partial"]
                rep["reasons"] += sub["reasons"]
            return rep
        except Exception as e:
            self._flag(f"snapshot collection failed: {str(e)[:100]}")
            return {"observations": 0, "suggestions": [],
                    "behavioral_context": [], "partial": True,
                    "reasons": [str(e)[:100]]}
        finally:
            self.pause_s += time.monotonic() - t0

    def report(self) -> dict:
        """Cumulative collector metrics for the owning capture run. Reads
        and pause are MEASURED on this session — no universal latency
        guarantee is implied."""
        return {"enabled": True, "persisted": self.store is not None,
                "observations": self.observations,
                "suggestions": self.suggestions,
                "behavioral_context": self.context_findings,
                "partial": self.partial, "reasons": self.reasons[:20],
                "jdwp_reads": self.reads,
                "pause_ms": round(self.pause_s * 1000, 3),
                "budgets": self.b.as_dict(),
                "note": "jdwp_reads/pause_ms are measured on this session; "
                        "no universal latency guarantee"}

    # --------------------------------------------------------------- observe
    def _observe(self, strings: list, context: dict, *,
                 run_id: str | None = None, event_id: str | None = None,
                 extra_evidence: list | None = None) -> dict:
        rep: dict = {"observations": 0, "suggestions": [],
                     "behavioral_context": [], "partial": False,
                     "reasons": []}
        if not context.get("class_sig"):
            return rep
        for text, label in strings[: self.b.max_strings]:
            rep["observations"] += 1
            self.observations += 1
            for f in aliases.analyze(text):
                if f["kind"] == "context":
                    rep["behavioral_context"].append(
                        {"rule": f["rule"], "label": label,
                         "text": text[:80]})
                    self.context_findings += 1
                    continue
                if f["score"] < aliases.SUGGEST_MIN_SCORE:
                    continue
                ev = [{"kind": "capture", "label": label,
                       **(extra_evidence[0] if extra_evidence else {}),
                       **({"event_id": event_id} if event_id else {}),
                       **({"run_id": run_id} if run_id else {})}]
                item = {"candidate": f["text"], "rule": f["rule"],
                        "score": f["score"], "label": label}
                if self.store is not None:
                    cid, action = self.store.observe(
                        class_sig=context["class_sig"], candidate=f["text"],
                        score=f["score"], rule=f["rule"],
                        method_name=context.get("method_name"),
                        method_sig=context.get("method_sig"),
                        classloader_id=context.get("classloader_id"),
                        epoch=context.get("epoch"),
                        run_id=run_id, event_id=event_id, evidence=ev)
                    item.update(candidate_id=cid, action=action)
                else:
                    item.update(candidate_id=None, action="not_persisted")
                rep["suggestions"].append(item)
                self.suggestions += 1
        if len(strings) > self.b.max_strings:
            msg = (f"string budget exhausted ({len(strings)} > "
                   f"{self.b.max_strings})")
            rep["partial"] = True
            rep["reasons"].append(msg)
            self._flag(msg)
        return rep

    # ------------------------------------------------------------ extra reads
    def _extra_reads(self, client, objects: list, context: dict, *,
                     run_id: str | None = None,
                     event_id: str | None = None) -> dict:
        """Opt-in reads beyond the capture: string fields of objects the
        capture already referenced. Depth 1 = fields of the captured object
        only; object-valued fields are never recursed into. Every budget
        (depth/objects/bytes/requests/elapsed) is enforced separately and
        every issued JDWP request is counted."""
        res = {"objects": 0, "strings": 0, "requests": 0, "bytes": 0,
               "partial": False, "reasons": []}
        if self.b.max_extra_depth < 1:
            res["partial"] = True
            res["reasons"].append("extra-read depth budget is 0")
            self._flag("extra-read depth budget is 0")
            return res
        start = time.monotonic()
        for oid in objects:
            if res["objects"] >= self.b.max_extra_objects:
                self._exhausted(res, "extra-read object budget exhausted")
                break
            if time.monotonic() - start > self.b.max_extra_seconds:
                self._exhausted(res, "extra-read time budget exhausted")
                break
            try:
                _, type_id = self._req(client, res,
                                       client.object_reftype, oid)
                fields = self._req(client, res, client.rt_fields, type_id)
                sfields = [f for f in fields
                           if f.get("sig") == "Ljava/lang/String;"][:8]
                if not sfields:
                    res["objects"] += 1
                    continue
                vals = self._req(client, res, client.object_get_values,
                                 oid, [f["id"] for f in sfields])
                got = []
                for f, v in zip(sfields, vals):
                    if v.get("tag") != TAG_STRING or not v.get("v"):
                        continue
                    s = self._req(client, res, client.string_value,
                                  v["v"], self.b.max_str + 1)
                    res["bytes"] += len(s)
                    if res["bytes"] > self.b.max_extra_bytes:
                        raise _BudgetExhausted(
                            "extra-read byte budget exhausted")
                    got.append((s[: self.b.max_str], f"field:{f['name']}"))
                if got:
                    res["strings"] += len(got)
                    self._observe(got, context, run_id=run_id,
                                  event_id=event_id)
            except _BudgetExhausted as e:
                self._exhausted(res, str(e))
                break
            except Exception as e:  # dead object, VM race, ...
                res["partial"] = True
                res["reasons"].append(f"object {oid}: {str(e)[:80]}")
                self._flag(f"extra read failed: {str(e)[:80]}")
            res["objects"] += 1
        return res

    def _req(self, client, res: dict, fn, *args):
        """One measured JDWP request under the request-count budget."""
        if res["requests"] >= self.b.max_extra_requests:
            raise _BudgetExhausted("extra-read request budget exhausted")
        res["requests"] += 1
        self.reads += 1
        return fn(*args)

    def _exhausted(self, res: dict, msg: str) -> None:
        res["partial"] = True
        res["reasons"].append(msg)
        self._flag(msg)

    def _flag(self, msg: str) -> None:
        self.partial = True
        if len(self.reasons) < 20:
            self.reasons.append(msg)

    # --------------------------------------------------------------- walkers
    def _walk_record(self, node, label, strings: list, objects: list,
                     depth: int = 0) -> None:
        if len(strings) > self.b.max_strings or depth > 8:
            return
        if isinstance(node, dict):
            if node.get("type") == "string" and isinstance(node.get("v"), str):
                strings.append((node["v"], label or "value"))
                return
            if node.get("type") == "object" and node.get("id"):
                objects.append(node["id"])
            for k, v in node.items():
                if k in _SKIP_KEYS:
                    continue
                self._walk_record(v, k, strings, objects, depth + 1)
        elif isinstance(node, list):
            for item in node:
                self._walk_record(item, label, strings, objects, depth + 1)
        elif isinstance(node, str) and node:
            strings.append((node, label or "value"))
        elif isinstance(node, list):
            for item in node:
                self._walk_record(item, label, strings, objects, depth + 1)

    def _walk_snapshot(self, node, cls, label, by_class: dict,
                       depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(node, dict):
            cur = node.get("cls", cls)
            s = node.get("s")
            if isinstance(s, str):  # string node {"s": text, "trunc"?}
                by_class.setdefault(cls, []).append((s, label or "value"))
                return
            for k, v in node.items():
                self._walk_snapshot(v, cur, k, by_class, depth + 1)
        elif isinstance(node, list):
            for item in node:
                self._walk_snapshot(item, cls, label, by_class, depth + 1)

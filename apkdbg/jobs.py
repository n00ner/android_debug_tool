"""Cancellable background jobs with bounded event and result output
(issue #34).

Threading model
---------------
The stdio server's main thread keeps reading request lines; a job runs its
collector on ONE daemon worker thread. The JDWP socket has exactly one
event-stream reader at a time: JobRegistry admits a single active job, and
the server rejects session-owning commands (including `connect`/`events`)
with E_JOB_CONFLICT while a job is active. Workers receive events only
through the collectors' own dispatcher subscriptions (owner + request id
routing, #31) — two workers never coexist, so none can read the socket or
steal events. Control requests (job_status/job_read/job_cancel/job_list)
never touch the socket and are answered in O(1) from registry state, so
their latency does not depend on the worker's state.

Terminal states and reasons
---------------------------
States: queued -> running (-> cancelling) -> completed | cancelled |
failed. The terminal record is immutable (written once, under the job
lock; repeated cancel/status observe it unchanged). Completion reasons:
completed (clean finish), deadline (time window), event_budget
(max_events/max_reads/queue_pressure/coverage budget), output_budget
(max_bytes/max_output_bytes/capped export), cancellation (cooperative
cancel), target_exit (process died), disconnect (transport lost / stale
epoch), capture_failure (anything else). Budget-stopped captures are
incomplete=true — a bounded capture is never reported silently complete.

Bounded record buffer and read cursors
--------------------------------------
Each job retains at most max_records records / max_record_bytes of JSON in
a drop-oldest ring; received/retained/dropped(never retained)/expired
(evicted) counts are exact and appear in every status/read reply. A read
cursor is the opaque token "r<absolute index>": pages resume without
duplicates or omissions among retained records; a cursor below the ring
base (evicted) fails with E_CURSOR_EXPIRED carrying the valid base. While
a job can still produce records a read always returns a continuation
cursor, even when caught up; null marks only a terminal, exhausted stream.

Shutdown
--------
JobRegistry.shutdown (Ctx.close, i.e. EOF/server exit) cancels every
active job, joins workers for a bounded window, and stamps a
deterministic failed/disconnect record on any job whose cleanup did not
finish in time.
"""

from __future__ import annotations

import json
import threading
import time
import uuid

from .device.jdwp import JdwpConnError
from .errors import (
    ApkDbgError, CursorExpiredError, ExportIncompleteError,
    InvalidParamsError, JobConflictError, JobNotFoundError,
    ProcessDiedError, StaleHandleError,
)
from .protocol import log_progress

STATES = ("queued", "running", "cancelling", "completed", "cancelled",
          "failed")
TERMINAL = ("completed", "cancelled", "failed")
REASONS = ("completed", "deadline", "event_budget", "output_budget",
           "cancellation", "target_exit", "disconnect", "capture_failure")

# collector stop reason -> (terminal state, completion reason, incomplete)
_COMPLETIONS = {
    "duration": ("completed", "deadline", False),
    "max_events": ("completed", "event_budget", True),
    "max_reads": ("completed", "event_budget", True),
    "queue_pressure": ("completed", "event_budget", True),
    "budget": ("completed", "event_budget", True),
    "max_bytes": ("completed", "output_budget", True),
    "max_output_bytes": ("completed", "output_budget", True),
    "cancelled": ("cancelled", "cancellation", True),
    "error": ("failed", "capture_failure", True),
}

DEFAULT_MAX_RECORDS = 1000
MAX_RECORDS_CAP = 10000
DEFAULT_MAX_RECORD_BYTES = 1 << 20
MAX_RECORD_BYTES_CAP = 16 << 20
DEFAULT_MAX_COMPLETED = 8      # retained terminal jobs (FIFO eviction)
MAX_PAGE = 500                 # hard upper bound for a job_read page
SHUTDOWN_TIMEOUT_S = 5.0       # bounded cleanup window on server exit


class Job:
    """One background operation: identity, lifecycle, cancel event, and
    the bounded record buffer its collector streams into. All mutable
    state is guarded by _lock; the terminal record is written once."""

    def __init__(self, command: str, params: dict, max_records: int,
                 max_record_bytes: int):
        self.operation_id = "op-" + uuid.uuid4().hex[:12]
        self.command = command
        self.params = params
        self.max_records = max_records
        self.max_record_bytes = max_record_bytes
        self.state = "queued"
        self.created_at = time.time()
        self.started_at: float | None = None
        self.ended_at: float | None = None
        self.cancel_event = threading.Event()
        self.thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._records: list = []
        self._sizes: list[int] = []
        self._base = 0           # absolute index of _records[0]
        self._received = 0       # records offered by the collector
        self._dropped = 0        # offered but never retained (byte bound)
        self._expired = 0        # retained once, evicted (record bound)
        self._bytes = 0
        self.outcome: dict | None = None
        self.result: dict | None = None
        self.error: dict | None = None

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    # ------------------------------------------------------------ emission
    def emit(self, rec) -> None:
        """Bounded sink fed by the collector's on_record tap. Never raises:
        a full buffer counts the record dropped/expired instead of
        disturbing the capture."""
        try:
            size = len(json.dumps(rec, default=str))
        except Exception:
            size = 0
        with self._lock:
            self._received += 1
            if self._bytes + size > self.max_record_bytes:
                self._dropped += 1
                return
            while len(self._records) >= self.max_records:
                self._bytes -= self._sizes.pop(0)
                self._records.pop(0)
                self._base += 1
                self._expired += 1
            self._records.append(rec)
            self._sizes.append(size)
            self._bytes += size

    # ------------------------------------------------------------ lifecycle
    def mark_running(self) -> None:
        with self._lock:
            if self.state == "queued":
                self.state = "running"
                self.started_at = time.time()

    def request_cancel(self) -> None:
        """Cooperative cancel: set the event the collector polls and move
        to cancelling. Idempotent — a terminal job is left untouched."""
        with self._lock:
            if self.terminal:
                return
            self.cancel_event.set()
            if self.state in ("queued", "running"):
                self.state = "cancelling"

    def set_terminal(self, state: str, reason: str, incomplete: bool,
                     result: dict | None = None,
                     error: dict | None = None) -> None:
        with self._lock:
            if self.terminal:
                return
            self.state = state
            self.ended_at = time.time()
            self.outcome = {"state": state, "reason": reason,
                            "incomplete": incomplete}
            self.result = result
            self.error = error

    # -------------------------------------------------------------- views
    def status(self) -> dict:
        with self._lock:
            out = {"operation_id": self.operation_id,
                   "command": self.command,
                   "state": self.state,
                   "terminal": self.terminal,
                   "created_at": self.created_at,
                   "elapsed_s": round((self.ended_at or time.time())
                                      - self.created_at, 3),
                   "params": self.params,
                   "limits": {"max_records": self.max_records,
                              "max_record_bytes": self.max_record_bytes},
                   "progress": {"received": self._received,
                                "retained": len(self._records),
                                "dropped": self._dropped,
                                "expired": self._expired,
                                "buffer_base": self._base,
                                "buffer_bytes": self._bytes}}
            for k in ("started_at", "ended_at", "outcome", "result",
                      "error"):
                v = getattr(self, k)
                if v is not None:
                    out[k] = v
            return out

    def brief(self) -> dict:
        with self._lock:
            out = {"operation_id": self.operation_id,
                   "command": self.command,
                   "state": self.state,
                   "terminal": self.terminal,
                   "created_at": self.created_at}
            if self.outcome is not None:
                out["reason"] = self.outcome["reason"]
            return out

    def read(self, cursor: str | None, limit: int) -> dict:
        """One bounded page. Pages resume without duplicates or omissions
        among retained records; a cursor below the buffer base names
        records the ring already evicted -> E_CURSOR_EXPIRED."""
        with self._lock:
            end = self._base + len(self._records)
            if cursor is None:
                start = self._base
            else:
                start = _parse_cursor(cursor)
                if start < self._base:
                    raise CursorExpiredError(
                        f"cursor {cursor!r} is below the retained window "
                        f"(base r{self._base}); those records were evicted "
                        f"by the bounded buffer",
                        hint="re-read without a cursor (or from the "
                             "reported base); expired/dropped counts are "
                             "exact",
                        cursor=cursor, base=f"r{self._base}",
                        expired=self._expired, dropped=self._dropped)
            start = min(start, end)
            page = self._records[start - self._base:
                                 start - self._base + limit]
            nxt = start + len(page)
            out = {"operation_id": self.operation_id,
                   "state": self.state,
                   "records": list(page),
                   "count": len(page),
                   "cursor": f"r{nxt}" if nxt < end or not self.terminal
                   else None,
                   "received": self._received,
                   "retained": len(self._records),
                   "dropped": self._dropped,
                   "expired": self._expired,
                   "buffer_base": self._base,
                   "truncated": bool(self._dropped or self._expired)}
            if self.outcome is not None:
                out["outcome"] = self.outcome
            return out


def _parse_cursor(cursor) -> int:
    if not isinstance(cursor, str) or not cursor.startswith("r") \
            or not cursor[1:].isdigit():
        raise InvalidParamsError(
            f"malformed cursor {cursor!r}",
            hint="cursors are the opaque tokens returned by job_read "
                 "(e.g. \"r42\"); omit cursor for the oldest retained page")
    return int(cursor[1:])


class JobRegistry:
    """Thread-safe job table with a single-active-job rule (one JDWP
    event-stream reader per session) and bounded completed-job retention."""

    def __init__(self, max_completed: int = DEFAULT_MAX_COMPLETED):
        self.max_completed = max_completed
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}

    def active(self) -> Job | None:
        with self._lock:
            return next((j for j in self._jobs.values() if not j.terminal),
                        None)

    def start(self, ctx, command: str, params: dict, runner,
              max_records: int = DEFAULT_MAX_RECORDS,
              max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES) -> dict:
        max_records = max(1, min(int(max_records), MAX_RECORDS_CAP))
        max_record_bytes = max(1, min(int(max_record_bytes),
                                      MAX_RECORD_BYTES_CAP))
        with self._lock:
            cur = next((j for j in self._jobs.values() if not j.terminal),
                       None)
            if cur is not None:
                raise JobConflictError(
                    f"job {cur.operation_id} ({cur.command}) is still "
                    f"{cur.state}; one JDWP session supports one "
                    "background job",
                    hint="poll job_status, or job_cancel it first",
                    operation_id=cur.operation_id, command=cur.command,
                    state=cur.state)
            job = Job(command, params, max_records, max_record_bytes)
            self._jobs[job.operation_id] = job
        t = threading.Thread(target=self._worker, args=(job, ctx, runner),
                             name=f"apkdbg-{job.operation_id}", daemon=True)
        job.thread = t
        t.start()
        return job.status()

    def get(self, operation_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(operation_id)
        if job is None:
            raise JobNotFoundError(
                f"no job {operation_id!r} in this session",
                hint="job_list shows retained jobs; completed jobs are "
                     "evicted oldest-first beyond the retention bound",
                operation_id=operation_id)
        return job

    def cancel(self, operation_id: str) -> dict:
        job = self.get(operation_id)
        job.request_cancel()
        return job.status()

    def list(self, limit: int, offset: int) -> dict:
        with self._lock:
            jobs = list(self._jobs.values())
        rows = [j.brief() for j in jobs]
        page = rows[offset:offset + limit]
        return {"jobs": page, "count": len(page), "total": len(rows),
                "limit": limit, "offset": offset,
                "truncated": offset + len(page) < len(rows)}

    def shutdown(self, timeout_s: float = SHUTDOWN_TIMEOUT_S) -> None:
        """Server exit: cancel every active job, allow a bounded cleanup
        window, then stamp a deterministic terminal record on anything
        still unfinished."""
        with self._lock:
            jobs = [j for j in self._jobs.values() if not j.terminal]
        for j in jobs:
            j.request_cancel()
        deadline = time.monotonic() + timeout_s
        for j in jobs:
            if j.thread is not None:
                j.thread.join(max(0.0, deadline - time.monotonic()))
        for j in jobs:
            if not j.terminal:
                j.set_terminal(
                    "failed", "disconnect", True, error={
                        "code": "E_SESSION",
                        "message": "server shut down before the job "
                                   "finished cleanup",
                        "retryable": False, "outcome": "partial"})

    # -------------------------------------------------------------- worker
    def _worker(self, job: Job, ctx, runner) -> None:
        job.mark_running()
        try:
            result = runner(ctx, job)
        except Exception as e:
            self._finish_error(job, e)
            return
        self._finish_result(job, result)

    def _finish_result(self, job: Job, result: dict) -> None:
        summary = dict(result or {})
        recs = summary.pop("records", None)
        if recs is not None:
            # records stream through the bounded buffer, not the summary
            summary["record_count"] = len(recs)
            summary["records_via"] = "job_read"
        if job.command == "export_buffer":
            state, reason, incomplete = ("completed", "completed", False) \
                if (result or {}).get("complete") \
                else ("completed", "output_budget", True)
        else:
            stop = (result or {}).get("reason") \
                or (result or {}).get("stop_reason")
            state, reason, incomplete = _COMPLETIONS.get(
                stop, ("completed", "completed", False))
        if job.cancel_event.is_set() and state != "failed":
            # cancel landed before the terminal write: cooperative cancel
            # wins; the partial result is preserved either way
            state, reason = "cancelled", "cancellation"
        job.set_terminal(state, reason, incomplete, result=summary)
        self._evict()

    def _finish_error(self, job: Job, e: Exception) -> None:
        err = e.to_dict() if isinstance(e, ApkDbgError) else {
            "code": "E_INTERNAL", "message": str(e),
            "retryable": False, "outcome": "failed"}
        if job.cancel_event.is_set():
            state, reason = "cancelled", "cancellation"
        elif isinstance(e, ProcessDiedError):
            state, reason = "failed", "target_exit"
        elif isinstance(e, ExportIncompleteError):
            why = str(e.context.get("reason") or "")
            if why.startswith("cancelled"):
                state, reason = "cancelled", "cancellation"
            elif why.startswith("deadline"):
                state, reason = "failed", "deadline"
            else:
                state, reason = "failed", "capture_failure"
        elif isinstance(e, (JdwpConnError, StaleHandleError)):
            state, reason = "failed", "disconnect"
        else:
            state, reason = "failed", "capture_failure"
        job.set_terminal(state, reason, True, error=err)
        self._evict()
        log_progress(f"job {job.operation_id} ({job.command}) "
                     f"{state}/{reason}: {err['message'][:120]}")

    def _evict(self) -> None:
        """Bounded completed-job retention: oldest terminal jobs beyond
        max_completed are dropped; their ids then fail with
        E_JOB_NOT_FOUND."""
        with self._lock:
            done = [j for j in self._jobs.values() if j.terminal]
            for j in done[:max(0, len(done) - self.max_completed)]:
                del self._jobs[j.operation_id]

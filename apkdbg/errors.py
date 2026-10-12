"""Structured error hierarchy. Every error carries a stable machine-readable
code so LLM agents can branch on `code` instead of parsing messages.

`to_dict()` shape is the stable error-data contract (also embedded in
JSON-RPC 2.0 error.data, see server.py): `code`, `message`, `retryable`,
and `outcome` are always present; `hint` and `context` appear only when
set (absent means none, never null)."""


class ApkDbgError(Exception):
    code = "E_INTERNAL"
    hint: str | None = None
    retryable = False          # safe to retry the same call as-is
    outcome = "failed"         # failed = no effect; partial = some effects

    def __init__(self, message: str, *, hint: str | None = None, **context):
        super().__init__(message)
        self.message = message
        if hint:
            self.hint = hint
        self.context = context

    def to_dict(self) -> dict:
        d = {"code": self.code, "message": self.message,
             "retryable": self.retryable, "outcome": self.outcome}
        if self.hint:
            d["hint"] = self.hint
        if self.context:
            d["context"] = self.context
        return d


class ToolNotFoundError(ApkDbgError):
    code = "E_TOOL_NOT_FOUND"


class ToolRunError(ApkDbgError):
    code = "E_TOOL_RUN"


class DecompileError(ApkDbgError):
    code = "E_DECOMPILE"


class MappingError(ApkDbgError):
    code = "E_MAPPING"


class AdbError(ApkDbgError):
    code = "E_ADB"
    retryable = True  # adb transport failures are transient (recovery ladder)


class JdwpError(ApkDbgError):
    code = "E_JDWP"
    retryable = True  # connection drops are reconnectable


class JdwpReplyError(JdwpError):
    code = "E_JDWP_REPLY"

    # official JDWP spec error constants (note: INVALID_* ids are NOT
    # sequential with INVALID_LENGTH; 5xx range covers tag/index/length)
    JDWP_ERRORS = {
        10: "INVALID_THREAD", 11: "INVALID_THREAD_GROUP",
        12: "INVALID_PRIORITY", 13: "THREAD_NOT_SUSPENDED",
        14: "THREAD_SUSPENDED", 15: "THREAD_NOT_ALIVE",
        20: "INVALID_OBJECT", 21: "INVALID_CLASS", 22: "CLASS_NOT_PREPARED",
        23: "INVALID_METHODID", 24: "INVALID_LOCATION", 25: "INVALID_FIELDID",
        30: "INVALID_FRAMEID", 31: "NO_MORE_FRAMES", 32: "OPAQUE_FRAME",
        33: "NOT_CURRENT_FRAME", 34: "TYPE_MISMATCH", 35: "INVALID_SLOT",
        40: "DUPLICATE", 41: "NOT_FOUND", 42: "INVALID_MODULE",
        50: "INVALID_MONITOR", 51: "NOT_MONITOR_OWNER", 52: "INTERRUPT",
        99: "NOT_IMPLEMENTED", 100: "NULL_POINTER", 101: "ABSENT_INFORMATION",
        102: "INVALID_EVENT_TYPE", 103: "ILLEGAL_ARGUMENT",
        110: "OUT_OF_MEMORY", 111: "ACCESS_DENIED", 112: "VM_DEAD",
        113: "INTERNAL", 115: "UNATTACHED_THREAD", 500: "INVALID_TAG",
        502: "ALREADY_INVOKING", 503: "INVALID_INDEX", 504: "INVALID_LENGTH",
        506: "INVALID_STRING", 507: "INVALID_CLASS_LOADER",
        508: "INVALID_ARRAY", 509: "TRANSPORT_LOAD", 510: "TRANSPORT_INIT",
        511: "NATIVE_METHOD", 512: "INVALID_COUNT",
    }

    def __init__(self, error_no: int, cmdset: int, cmd: int):
        name = self.JDWP_ERRORS.get(error_no, f"ERR_{error_no}")
        super().__init__(
            f"JDWP {name} for cmdset={cmdset} cmd={cmd}",
            error_no=error_no, cmdset=cmdset, cmd=cmd,
        )


class SessionError(ApkDbgError):
    code = "E_SESSION"


# -------------------------------------------------- recovery (issue #32)
class OutcomeUnknownError(JdwpError):
    """A state-changing request was (fully or partially) transmitted before
    the connection dropped: the VM may already have executed it. Execution
    is UNKNOWN — not failed — so the op is never transparently replayed.
    Context carries op, phase (transmit/post-send), epoch/epoch_new, and
    the recovery state of the session."""
    code = "E_OUTCOME_UNKNOWN"
    retryable = False          # blind retry could execute app code twice
    outcome = "unknown"

    def __init__(self, op: str, *, phase: str, epoch: int,
                 epoch_new: int | None, recovery: str,
                 hint: str | None = None):
        when = {"transmit": "during transmission of the request",
                "post-send": "after the request reached the VM but before "
                             "its reply arrived"}.get(phase, phase)
        super().__init__(
            f"{op}: connection lost {when}; whether the VM executed it is "
            "UNKNOWN (this is not a failure confirmation)",
            hint=hint or "verify target state out-of-band (fresh events, a "
                         "read of the mutated state) before deciding to "
                         "re-issue the operation by hand",
            op=op, phase=phase, epoch=epoch, epoch_new=epoch_new,
            recovery=recovery)


class ProcessDiedError(SessionError):
    """The target process restarted (pid change) or exited — distinct from
    a recoverable transport failure. Every handle, request, and frame is
    gone; recovery requires a full re-attach plus symbolic restore."""
    code = "E_PROCESS_DIED"

    def __init__(self, message: str, **context):
        super().__init__(message,
                         hint="re-run connect, then 'restore' to re-install "
                              "breakpoints/hooks from their symbolic "
                              "definitions", **context)


class StaleHandleError(SessionError):
    """A numeric handle (thread/frame/object/type id) was used after the
    connection epoch that issued it died. The new connection may reuse the
    same numeric id for an unrelated object, so the op is refused instead
    of silently reading the wrong target."""
    code = "E_STALE_HANDLE"

    def __init__(self, op: str, *, epoch: int, hint: str | None = None):
        super().__init__(
            f"{op}: thread/frame/object ids are per-connection and died "
            f"with connection epoch {epoch}",
            hint=hint or "re-acquire fresh ids from new events/frames "
                         "(wait_events, step), then retry the operation",
            op=op, epoch=epoch)


class ResolveError(ApkDbgError):
    code = "E_RESOLVE"


class ExportIncompleteError(ApkDbgError):
    """A bounded buffer export (issue #38) stopped before the requested
    range was fully written: deadline/cancel, disconnect, or a host write
    failure (e.g. disk full). The partial temp file was removed unless the
    caller explicitly opted into retaining incomplete artifacts
    (keep_partial); context carries the reason, byte counts, the retained
    partial path (if any), and elapsed time. An incomplete capture is
    never reported as complete."""
    code = "E_EXPORT_INCOMPLETE"
    retryable = True           # re-issue against fresh handles/epoch
    outcome = "partial"


class CapabilityError(ApkDbgError):
    code = "E_CAPABILITY"


# -------------------------------------------------- background jobs (issue #34)
class JobConflictError(ApkDbgError):
    """A JDWP-owning operation was requested while a background job holds
    the session: one JDWP socket supports exactly one event-stream reader,
    so concurrent session operations are rejected early instead of
    interleaving on the wire. Context carries the running operation id."""
    code = "E_JOB_CONFLICT"
    retryable = True           # safe to retry once the running job ends


class JobNotFoundError(ApkDbgError):
    """Unknown operation id — never existed, or evicted by the bounded
    completed-job retention (job_list shows what is still retained)."""
    code = "E_JOB_NOT_FOUND"


class CursorExpiredError(ApkDbgError):
    """A job_read cursor points below the retained window: the bounded
    record buffer already evicted those records (exact expired/dropped
    counts are in every job_read reply). Re-read from the reported base."""
    code = "E_CURSOR_EXPIRED"


# ------------------------------------------------------- protocol (issue #33)
class ProtocolError(ApkDbgError):
    """Malformed or unsatisfiable request envelope — deterministic, raised
    before any project/session context is obtained."""
    code = "E_PROTOCOL"


class InvalidRequestError(ProtocolError):
    code = "E_INVALID_REQUEST"


class MethodNotFoundError(ProtocolError):
    code = "E_METHOD_NOT_FOUND"


class InvalidParamsError(ProtocolError):
    code = "E_INVALID_PARAMS"

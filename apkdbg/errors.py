"""Structured error hierarchy. Every error carries a stable machine-readable
code so LLM agents can branch on `code` instead of parsing messages."""


class ApkDbgError(Exception):
    code = "E_INTERNAL"
    hint: str | None = None

    def __init__(self, message: str, *, hint: str | None = None, **context):
        super().__init__(message)
        self.message = message
        if hint:
            self.hint = hint
        self.context = context

    def to_dict(self) -> dict:
        d = {"code": self.code, "message": self.message}
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


class JdwpError(ApkDbgError):
    code = "E_JDWP"


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


class ResolveError(ApkDbgError):
    code = "E_RESOLVE"

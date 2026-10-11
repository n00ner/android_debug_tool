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

    JDWP_ERRORS = {
        10: "INVALID_LENGTH", 20: "INVALID_THREAD", 21: "INVALID_OBJECT",
        22: "INVALID_CLASS", 23: "INVALID_METHODID", 24: "INVALID_LOCATION",
        25: "INVALID_EVENT_KIND", 30: "INVALID_FIELDID", 31: "INVALID_FRAMEID",
        32: "INVALID_STRING", 35: "INVALID_SLOT", 40: "TYPE_MISMATCH",
        41: "INVALID_TAG", 51: "NOT_IMPLEMENTED", 99: "VM_DEAD",
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

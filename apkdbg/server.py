"""JSON-RPC over stdio — the integration surface for LLM agents.

One JSON value per line, both directions. The server keeps a persistent Ctx,
so JDWP sessions survive across calls (essential: disconnecting a JDWP
socket typically resumes/kills the debug session). All bodies are minified;
anything human-readable goes to stderr.

Protocol versions (issue #33)
-----------------------------
The wire version is selected PER REQUEST by the presence of a top-level
``jsonrpc`` member:

* ``"2.0"`` — JSON-RPC 2.0 (https://www.jsonrpc.org/specification is the
  contract reference). The member must equal ``"2.0"``. Replies carry
  ``"jsonrpc": "2.0"``; protocol failures use the standard numeric codes
  (-32700 parse, -32600 invalid request, -32601 method not found, -32602
  invalid params, -32603 internal) while domain errors keep their stable
  ``E_*`` code in structured ``error.data``
  (code/message/retryable/outcome, plus hint/context when set).
  Notifications (requests without ``id``) are executed but never replied
  to — not even on error (logged to stderr instead). A JSON array on one
  line is a batch: one reply array, notification responses omitted, an
  all-notification batch produces no output line at all. ``params`` may be
  an object (by name) or an array (by position, in catalog order).
* ``"1.0"`` — legacy compatibility envelope, and the DEFAULT: a request
  without a ``jsonrpc`` member is treated as
  ``{"id": ..., "method": ..., "params": {...}}`` and answered with
  ``{"id": ..., "result": ...}`` or ``{"id": ..., "error": {...}}`` where
  the error body is the same structured error data (E_PARSE,
  E_INVALID_REQUEST, E_METHOD_NOT_FOUND, E_INVALID_PARAMS, or a domain
  code). Legacy clients from before #33 keep working unchanged.

Requests whose version cannot be determined (non-object roots) and parse
failures are answered in the legacy envelope with ``id: null`` — a parse
error NEVER borrows the id of a previous request. Batch elements are
version-detected individually, so a batch may mix both envelopes.

Every request is validated (root type, method, params against the command
catalog in core/apicatalog.py) BEFORE any project/session context is
obtained. Two protocol methods work without an initialized project or a
device, in both versions:

  describe       the versioned command catalog (params: optional "command")
  capabilities   per-command capability states: supported /
                 unavailable_in_this_session / unverified_runtime
"""

from __future__ import annotations

import json
import sys

from .commands import COMMANDS, Ctx
from .core import apicatalog
from .errors import (
    ApkDbgError, InvalidParamsError, InvalidRequestError, MethodNotFoundError,
)
from .protocol import dumps, log_progress

LEGACY_VERSION = "1.0"
JSONRPC_VERSION = "2.0"

# standard JSON-RPC 2.0 protocol error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

_PROTOCOL_METHODS = tuple(apicatalog._PROTOCOL_ENTRIES)


def _error_payload(e: Exception) -> dict:
    if isinstance(e, ApkDbgError):
        return e.to_dict()
    return {"code": "E_INTERNAL", "message": str(e),
            "retryable": False, "outcome": "failed"}


def _valid_id(v) -> bool:
    return v is None or (isinstance(v, (str, int, float))
                         and not isinstance(v, bool))


class RpcServer:
    """Stateful line-oriented request handler (one per stdio session).
    Unit-testable without stdio via handle_line(); request-local state
    lives only in locals, so lines can never corrupt each other."""

    def __init__(self, project_root: str, serial: str | None = None):
        self.project_root = project_root
        self.serial = serial
        self._ctx: Ctx | None = None

    def close(self) -> None:
        # EOF or crash: release the JDWP session AND its adb forward listener
        if self._ctx is not None:
            self._ctx.close()
            self._ctx = None

    def _get_ctx(self) -> Ctx:
        if self._ctx is None:
            self._ctx = Ctx(self.project_root, serial=self.serial)
        return self._ctx

    def _session_live(self) -> bool:
        s = self._ctx._session if self._ctx is not None else None
        return s is not None and s.client is not None

    # ------------------------------------------------------------ transport
    def handle_line(self, line: str) -> list[dict]:
        """One input line -> zero or more reply objects (zero only for
        notifications / all-notification batches)."""
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            return [self._legacy_error(None, {
                "code": "E_PARSE",
                "message": f"invalid JSON: {e}",
                "hint": "one minified JSON object per line",
                "retryable": False, "outcome": "failed"})]
        if isinstance(req, list):
            return self._handle_batch(req)
        reply = self._handle_one(req)
        return [] if reply is None else [reply]

    def _handle_one(self, req) -> dict | None:
        if not isinstance(req, dict):
            # version undeterminable -> legacy compatibility envelope
            return self._legacy_error(None, _error_payload(
                InvalidRequestError(
                    "request must be a JSON object, got "
                    + type(req).__name__)))
        if "jsonrpc" in req:
            return self._handle_v2(req)
        return self._handle_legacy(req)

    def _handle_batch(self, items: list) -> list[dict]:
        if not items:
            return [self._v2_error(None, INVALID_REQUEST,
                                   "batch must not be empty")]
        replies = []
        for item in items:
            if isinstance(item, dict):
                reply = self._handle_one(item)
            else:
                reply = self._v2_error(None, INVALID_REQUEST,
                                       "batch elements must be JSON objects")
            if reply is not None:
                replies.append(reply)
        return replies

    # ---------------------------------------------------------- legacy v1
    def _handle_legacy(self, req: dict) -> dict:
        rid = req.get("id")  # request-local; reset for every line
        try:
            method = req.get("method")
            if not isinstance(method, str):
                raise InvalidRequestError("missing or non-string 'method'")
            params = req.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise InvalidParamsError(
                    "params must be a JSON object, got "
                    + type(params).__name__)
            return {"id": rid, "result": self._dispatch(method, params)}
        except Exception as e:
            return self._legacy_error(rid, _error_payload(e))

    @staticmethod
    def _legacy_error(rid, payload: dict) -> dict:
        return {"id": rid, "error": payload}

    # ----------------------------------------------------------- JSON-RPC v2
    def _handle_v2(self, req: dict) -> dict | None:
        notify = "id" not in req
        rid = req.get("id")
        try:
            if req.get("jsonrpc") != JSONRPC_VERSION:
                raise InvalidRequestError("'jsonrpc' must be \"2.0\"")
            if not notify and not _valid_id(rid):
                raise InvalidRequestError(
                    "'id' must be a string, number, or null")
            method = req.get("method")
            if not isinstance(method, str):
                raise InvalidRequestError("missing or non-string 'method'")
            params = self._v2_params(method, req.get("params"))
            result = self._dispatch(method, params)
            if notify:
                return None
            return {"jsonrpc": JSONRPC_VERSION, "id": rid, "result": result}
        except Exception as e:
            if notify:
                log_progress(f"notification {req.get('method')!r} failed: {e}")
                return None
            return self._v2_exc(rid if _valid_id(rid) else None, e)

    @staticmethod
    def _v2_params(method: str, raw) -> dict:
        """Normalize v2 params: absent -> {}, object -> by name, array ->
        by position in catalog parameter order."""
        if raw is None:
            return {}
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, list):
            entry = apicatalog.entry_for(method)
            if entry is None:
                raise MethodNotFoundError(f"unknown method {method!r}")
            names = [p["name"] for p in entry["params"]]
            if len(raw) > len(names):
                raise InvalidParamsError(
                    f"{method} takes at most {len(names)} positional "
                    f"params, got {len(raw)}")
            return dict(zip(names, raw))
        raise InvalidParamsError(
            "params must be an object or array, got " + type(raw).__name__)

    def _v2_exc(self, rid, e: Exception) -> dict:
        if isinstance(e, InvalidRequestError):
            return self._v2_error(rid, INVALID_REQUEST, e.message,
                                  e.to_dict())
        if isinstance(e, MethodNotFoundError):
            return self._v2_error(rid, METHOD_NOT_FOUND, e.message,
                                  e.to_dict())
        if isinstance(e, InvalidParamsError):
            return self._v2_error(rid, INVALID_PARAMS, e.message,
                                  e.to_dict())
        if isinstance(e, ApkDbgError):
            # domain error: numeric internal code, E_* contract in data
            return self._v2_error(rid, INTERNAL_ERROR, e.message,
                                  e.to_dict())
        return self._v2_error(rid, INTERNAL_ERROR, str(e),
                              _error_payload(e))

    @staticmethod
    def _v2_error(rid, code: int, message: str, data=None) -> dict:
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": rid, "error": err}

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, method: str, params: dict):
        """Validate against the catalog BEFORE obtaining any project or
        session context, then call the command."""
        entry = apicatalog.entry_for(method)
        if entry is None:
            raise MethodNotFoundError(
                f"unknown method {method!r}",
                hint="methods: "
                     + ", ".join(list(COMMANDS) + list(_PROTOCOL_METHODS)))
        kwargs = apicatalog.validate_params(entry, params)
        if method == "describe":
            return apicatalog.describe(**kwargs)
        if method == "capabilities":
            return apicatalog.capabilities(self._session_live())
        ctx = self._get_ctx() if entry["requires"]["project"] else None
        return COMMANDS[method](ctx, **kwargs)


def serve_stdio(project_root: str, serial: str | None = None) -> None:
    server = RpcServer(project_root, serial=serial)
    log_progress(f"apkdbg serving stdio, project={project_root}")
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            for reply in server.handle_line(line):
                sys.stdout.write(dumps(reply) + "\n")
            sys.stdout.flush()
    finally:
        server.close()

"""JSON-RPC 2.0 over stdio — the integration surface for LLM agents.

One JSON object per line, both directions. The server keeps a persistent Ctx,
so JDWP sessions survive across calls (essential: disconnecting a JDWP
socket typically resumes/kills the debug session).

Request:  {"id": 1, "method": "bp", "params": {"spec": "a.b.C.run:42"}}
Reply:    {"id": 1, "result": {...}}          or
          {"id": 1, "error": {"code": "E_RESOLVE", "message": "..."}}

All bodies are minified. Anything human-readable goes to stderr.
"""

from __future__ import annotations

import json
import sys

from .commands import COMMANDS, Ctx
from .errors import ApkDbgError
from .protocol import dumps, log_progress


def serve_stdio(project_root: str, serial: str | None = None) -> None:
    ctx_holder: dict = {"ctx": None}

    def get_ctx() -> Ctx:
        if ctx_holder["ctx"] is None:
            ctx_holder["ctx"] = Ctx(project_root, serial=serial)
        return ctx_holder["ctx"]

    log_progress(f"apkdbg serving stdio, project={project_root}")
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                rid, method = req.get("id"), req.get("method")
                params = req.get("params") or {}
                if method == "init":  # init needs no open project
                    result = COMMANDS["init"](None, **params)
                else:
                    fn = COMMANDS.get(method)
                    if fn is None:
                        raise ApkDbgError(f"unknown method {method!r}",
                                          hint="methods: " + ", ".join(COMMANDS))
                    result = fn(get_ctx(), **params)
                reply = {"id": rid, "result": result}
            except Exception as e:
                if isinstance(e, ApkDbgError):
                    payload = e.to_dict()
                else:
                    payload = {"code": "E_INTERNAL", "message": str(e)}
                reply = {"id": locals().get("rid"), "error": payload}
            sys.stdout.write(dumps(reply) + "\n")
            sys.stdout.flush()
    finally:
        # EOF or crash: release the JDWP session AND its adb forward listener
        if ctx_holder["ctx"] is not None:
            ctx_holder["ctx"].close()

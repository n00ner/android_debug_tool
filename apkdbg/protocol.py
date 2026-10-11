"""Compact JSON envelope helpers.

Design rule: every command prints exactly ONE line of JSON to stdout.
No banners, no progress text on stdout (progress goes to stderr). This
keeps the tool safe for stdio-based JSON-RPC transport and minimizes
token burn for LLM consumers.
"""

from __future__ import annotations

import json
import sys

from .errors import ApkDbgError


def ok(data: dict | list | None = None, **kw) -> dict:
    payload = data if data is not None else kw
    return {"status": "ok", "data": payload if payload is not None else {}}


def err(exc: Exception) -> dict:
    if isinstance(exc, ApkDbgError):
        return {"status": "error", "error": exc.to_dict()}
    return {"status": "error", "error": {"code": "E_INTERNAL", "message": str(exc)}}


def dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


def emit(obj) -> None:
    sys.stdout.write(dumps(obj) + "\n")
    sys.stdout.flush()


def log_progress(msg: str) -> None:
    sys.stderr.write(f"[apkdbg] {msg}\n")
    sys.stderr.flush()

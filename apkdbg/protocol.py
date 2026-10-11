"""Compact JSON envelope helpers.

Design rule: every command prints exactly ONE line of JSON to stdout.
No banners, no progress text on stdout (progress goes to stderr). This
keeps the tool safe for stdio-based JSON-RPC transport and minimizes
token burn for LLM consumers.
"""

from __future__ import annotations

import json
import math
import sys

from .errors import ApkDbgError


def ok(data: dict | list | None = None, **kw) -> dict:
    payload = data if data is not None else kw
    return {"status": "ok", "data": payload if payload is not None else {}}


def err(exc: Exception) -> dict:
    if isinstance(exc, ApkDbgError):
        return {"status": "error", "error": exc.to_dict()}
    return {"status": "error", "error": {"code": "E_INTERNAL", "message": str(exc)}}


def _sanitize(o):
    """Replace non-finite floats (legal JDWP float/double values) with an
    explicit string marker: bare NaN/Infinity are not valid JSON (RFC 8259)
    and strict clients reject the whole response."""
    if isinstance(o, float):
        if math.isfinite(o):
            return o
        if math.isnan(o):
            return "NaN"
        return "Infinity" if o > 0 else "-Infinity"
    if isinstance(o, dict):
        return {k: _sanitize(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_sanitize(v) for v in o]
    return o


def dumps(obj) -> str:
    return json.dumps(_sanitize(obj), separators=(",", ":"),
                      ensure_ascii=False, default=str, allow_nan=False)


def emit(obj) -> None:
    sys.stdout.write(dumps(obj) + "\n")
    sys.stdout.flush()


def log_progress(msg: str) -> None:
    sys.stderr.write(f"[apkdbg] {msg}\n")
    sys.stderr.flush()

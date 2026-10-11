"""Subprocess helpers shared by all external-tool wrappers."""

from __future__ import annotations

import shutil
import subprocess

from .errors import ToolNotFoundError, ToolRunError
from .protocol import log_progress


def find_binary(name: str, env_var: str | None = None, extra: list[str] | None = None) -> str:
    import os
    candidates = []
    if env_var and os.environ.get(env_var):
        candidates.append(os.environ[env_var])
    candidates.append(name)
    for c in candidates:
        found = shutil.which(c)
        if found:
            return found
    for c in extra or []:
        if shutil.which(c):
            return shutil.which(c)
    raise ToolNotFoundError(
        f"required tool not found: {name}",
        hint=f"install it or set {env_var}" if env_var else "add it to PATH",
        tool=name,
    )


def run(cmd: list[str], *, timeout: int = 600, tool: str | None = None,
        check: bool = True) -> subprocess.CompletedProcess:
    log_progress("$ " + " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="replace",
        )
    except FileNotFoundError:
        raise ToolNotFoundError(f"required tool not found: {cmd[0]}", tool=cmd[0])
    except subprocess.TimeoutExpired:
        raise ToolRunError(f"tool timed out after {timeout}s: {cmd[0]}",
                           tool=tool or cmd[0])
    if check and proc.returncode != 0:
        raise ToolRunError(
            f"{cmd[0]} exited with code {proc.returncode}",
            hint=(proc.stderr or proc.stdout or "").strip()[-2000:] or None,
            tool=tool or cmd[0], rc=proc.returncode,
        )
    return proc

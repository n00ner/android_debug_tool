"""apktool / jadx CLI wrappers. Both are optional at import time; the init
pipeline checks availability and reports structured errors."""

from __future__ import annotations

from pathlib import Path

from ..errors import DecompileError
from ..protocol import log_progress
from ..util import find_binary, run

# jadx flag sets tried in order: newer jadx emits a JSON mapping alongside
# sources; older builds reject unknown flags, so we degrade gracefully.
JADX_FLAG_SETS = [
    ["--mappings-json", "--deobf"],
    ["--deobf"],
    [],
]


def tool_version(tool: str, *, env_var: str | None = None) -> str | None:
    """Best-effort `<tool> --version` first line, for index provenance
    (issue #35). Never fails: version capture must not break an init."""
    try:
        bin_ = find_binary(tool, env_var=env_var)
        proc = run([bin_, "--version"], timeout=15, tool=tool, check=False)
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else None
    except Exception:
        return None


def apktool_decode(apk: str | Path, out_dir: str | Path,
                   timeout: int = 900) -> dict:
    bin_ = find_binary("apktool", env_var="APKDBG_APKTOOL")
    out = Path(out_dir)
    run([bin_, "d", "-f", "-o", str(out), str(apk)], timeout=timeout,
        tool="apktool")
    if not (out / "AndroidManifest.xml").exists():
        raise DecompileError("apktool produced no AndroidManifest.xml",
                             hint="is the input a valid APK?")
    return {"tool": "apktool", "out": str(out)}


def jadx_decompile(apk: str | Path, out_dir: str | Path,
                   timeout: int = 1200) -> dict:
    bin_ = find_binary("jadx", env_var="APKDBG_JADX")
    out = Path(out_dir)
    last_err = None
    for flags in JADX_FLAG_SETS:
        proc = run([bin_, "-d", str(out), *flags, str(apk)],
                   timeout=timeout, tool="jadx", check=False)
        # jadx exits non-zero when some methods fail to decompile — normal on
        # real apps. Judge success by produced sources, not the exit code.
        n_sources = len(list(out.rglob("*.java"))) if out.exists() else 0
        if n_sources > 0:
            mapping = _find_mapping_file(out)
            return {"tool": "jadx", "out": str(out), "flags": flags,
                    "java_files": n_sources,
                    "decompile_errors": proc.returncode != 0,
                    "mapping_file": str(mapping) if mapping else None}
        last_err = (proc.stderr or proc.stdout or "")[-500:]
    raise DecompileError("jadx produced no sources with any flag set",
                         hint=last_err)


def _find_mapping_file(jadx_out: Path) -> Path | None:
    for name in ("mappings.json", "mapping.json", "deobf.json",
                 "resources/mapping.json"):
        p = jadx_out / name
        if p.exists():
            return p
    return None

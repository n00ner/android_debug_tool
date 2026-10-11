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
        if proc.returncode == 0:
            mapping = _find_mapping_file(out)
            if flags and "--mappings-json" in flags and not mapping:
                log_progress("jadx accepted --mappings-json but no mapping "
                             "file was found; continuing without it")
            return {"tool": "jadx", "out": str(out), "flags": flags,
                    "mapping_file": str(mapping) if mapping else None}
        last_err = (proc.stderr or proc.stdout or "")[-500:]
    raise DecompileError("jadx failed with all known flag sets",
                         hint=last_err)


def _find_mapping_file(jadx_out: Path) -> Path | None:
    for name in ("mappings.json", "mapping.json", "deobf.json",
                 "resources/mapping.json"):
        p = jadx_out / name
        if p.exists():
            return p
    return None

"""Live validation for issue #21 on a real device.

Runs crypto_hooks.run_watch(capture_returns=True) against the fixture app
while a trigger thread fires com.apkdbg.cryptofixture.RUN broadcasts.
Compares every captured vector against vectors.json and prints a JSON
verdict. Usage: python _validate.py [serial] [triggers] [duration_s]
"""
import json, subprocess, sys, threading, time

sys.path.insert(0, r"J:\reverse\debug_tool")
from apkdbg.core.project import Project
from apkdbg.debug.session import DebugSession
from apkdbg.debug.hooks import crypto

HERE = r"J:\reverse\debug_tool\tests/fixtures/crypto"
SERIAL = sys.argv[1] if len(sys.argv) > 1 else "4b79a217"
TRIGGERS = int(sys.argv[2]) if len(sys.argv) > 2 else 60
DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 120.0
PKG = "com.apkdbg.cryptofixture"

V = json.load(open(f"{HERE}/vectors.json"))


def adb(*args):
    return subprocess.run(["adb", "-s", SERIAL, *args],
                          capture_output=True, text=True)


def trigger_loop(stop):
    for _ in range(TRIGGERS):
        if stop.is_set():
            break
        adb("shell", "am", "broadcast", "-a",
            "com.apkdbg.cryptofixture.RUN", "-p", PKG)
        time.sleep(1.0)


def check(records):
    v = {"aes_key": False, "iv": False, "cipher_input": False,
         "cipher_return": False, "mac_input": False, "mac_return": False,
         "digest_input": False, "digest_return": False,
         "phase_labels": True, "opmode_1": False}
    for r in records:
        if "phase" not in r:
            v["phase_labels"] = False
        h, a = r["hook"], r.get("args", {})
        if h.startswith("SecretKeySpec") and r.get("phase") == "entry":
            if a.get("key", {}).get("hex") == V["aes_key_hex"]:
                v["aes_key"] = True
        if h.startswith("IvParameterSpec") and r.get("phase") == "entry":
            if a.get("iv", {}).get("hex") == V["iv_hex"]:
                v["iv"] = True
        if h.startswith("Cipher.init") and r.get("phase") == "entry":
            if a.get("opmode", {}).get("v") == 1:
                v["opmode_1"] = True
        if h == "Cipher.doFinal(byte[])":
            if r.get("phase") == "entry" and \
                    a.get("input", {}).get("hex") == V["plaintext_hex"]:
                v["cipher_input"] = True
            if r.get("phase") == "return" and r.get("return", {}).get(
                    "hex") == V["aes_128_cbc_pkcs5_ciphertext_hex"]:
                v["cipher_return"] = True
        if h == "Mac.doFinal(byte[])":
            if r.get("phase") == "entry" and \
                    a.get("input", {}).get("hex") == V["plaintext_hex"]:
                v["mac_input"] = True
            if r.get("phase") == "return" and \
                    r.get("return", {}).get("hex") == V["hmac_sha256_hex"]:
                v["mac_return"] = True
        if h == "MessageDigest.digest(byte[])":
            if r.get("phase") == "entry" and \
                    a.get("input", {}).get("hex") == V["plaintext_hex"]:
                v["digest_input"] = True
            if r.get("phase") == "return" and \
                    r.get("return", {}).get("hex") == V["sha256_hex"]:
                v["digest_return"] = True
    return v


def main():
    props = {}
    for k in ("ro.product.model", "ro.build.version.release",
              "ro.build.version.sdk"):
        props[k] = adb("shell", "getprop", k).stdout.strip()
    proj = Project(f"{HERE}/proj")
    s = DebugSession(proj, serial=SERIAL)
    info = s.connect(PKG)
    print(json.dumps({"connect": info, "props": props}))
    stop = threading.Event()
    t = threading.Thread(target=trigger_loop, args=(stop,), daemon=True)
    t.start()
    t0 = time.time()
    try:
        rep = crypto.run_watch(s, duration_s=DURATION,
                               capture_returns=True)
    finally:
        stop.set()
        t.join(timeout=5)
    rep.pop("records", None) if False else None
    records = rep["records"]
    verdict = check(records)
    summary = {
        "duration_actual_s": round(time.time() - t0, 1),
        "triggers_sent": TRIGGERS,
        "hits": rep["hits"],
        "installed": rep["installed"], "pending": rep["pending"],
        "reason": rep["reason"], "truncated": rep["truncated"],
        "unrelated": rep["unrelated"], "errors": rep["errors"],
        "cleanup_errors": rep["cleanup_errors"],
        "registry_after": len(s.bp_registry),
        "verdict": verdict,
        "verdict_pass": all(verdict.values()),
    }
    # error-rate stats on entry captures
    entry = [r for r in records if r.get("phase") == "entry"]
    bad = [r for r in entry if any(isinstance(x, dict) and "error" in x
                                   for x in r.get("args", {}).values())]
    summary["entry_records"] = len(entry)
    summary["entry_with_arg_errors"] = len(bad)
    meta_err = [r for r in records if "meta_error" in r or any(
        isinstance(x, dict) and "error" in x
        for x in r.get("meta", {}).values())]
    summary["records_with_meta_errors"] = len(meta_err)
    # app still responsive + no leaked suspension: trigger once more
    adb("shell", "am", "broadcast", "-a", "com.apkdbg.cryptofixture.RUN",
        "-p", PKG)
    time.sleep(2)
    out = adb("shell", "logcat", "-d", "-s", "CryptoFixture:I")
    lines = (out.stdout or "").strip().splitlines()
    summary["app_responsive_after"] = bool(
        lines) and "RUN ok" in lines[-1]
    with open(f"{HERE}/_validate_out.json", "w") as f:
        json.dump({"summary": summary, "records": records}, f, indent=1)
    print(json.dumps(summary, indent=1))
    s.close()


if __name__ == "__main__":
    main()

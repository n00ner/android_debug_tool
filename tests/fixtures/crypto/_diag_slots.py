"""Diagnose ART frame slot layout at framework-method breakpoints (#21).

Attaches to the crypto fixture app, breaks at SecretKeySpec.<init>(byte[],String)
and Cipher.init(int,Key), then dumps frames/var-table/raw slot probes.
"""
import json, subprocess, sys, time

sys.path.insert(0, r"J:\reverse\debug_tool")
from apkdbg.core.project import Project
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import SP_EVENT_THREAD

PKG = "com.apkdbg.cryptofixture"
PROJ = r"J:\reverse\debug_tool\tests/fixtures/crypto\proj"
SERIAL = "4b79a217"


def trigger():
    subprocess.run(["adb", "-s", SERIAL, "shell", "am", "broadcast",
                    "-a", "com.apkdbg.cryptofixture.RUN", "-p", PKG],
                   capture_output=True)


def probe(c, thread, frame_id, nslots=6):
    out = {}
    for slot in range(nslots):
        for tag, tname in ((91, "array"), (76, "obj"), (73, "int"),
                           (115, "str")):
            try:
                v = c.frame_get_values(thread, frame_id, [(slot, tag)])[0]
                out.setdefault(slot, []).append((tname, v["tag"], v["v"]))
            except Exception as e:
                out.setdefault(slot, []).append((tname, "ERR",
                                                 str(e).split("\n")[0][:60]))
    return out


def main():
    proj = Project(PROJ)
    s = DebugSession(proj, serial=SERIAL)
    print(json.dumps(s.connect(PKG)))
    c = s.client
    targets = [("Ljavax/crypto/spec/SecretKeySpec;", "<init>",
                "([BLjava/lang/String;)V"),
               ("Ljavax/crypto/Cipher;", "init",
                "(ILjava/security/Key;)V")]
    rids = []
    for sig, name, msig in targets:
        for cls in c.classes_by_signature(sig):
            m = next((m for m in c.rt_methods(cls["type_id"])
                      if m["name"] == name and m["sig"] == msig), None)
            if not m:
                print("no method", sig); continue
            try:
                lt = c.method_line_table(cls["type_id"], m["id"])
                idx = lt["lines"][0]["index"] if lt["lines"] else 0
                print(f"{sig}{name}: idx={idx} lines={lt['lines'][:3]}")
            except Exception as e:
                idx = 0
                print(f"{sig}{name}: no line table ({e}); idx=0")
            try:
                vt = c.method_var_table(cls["type_id"], m["id"])
                print("  vartable:", json.dumps(vt)[:400])
            except Exception as e:
                print("  no vartable:", str(e)[:80])
            rids.append(c.set_breakpoint(cls["type_id"], m["id"], idx,
                                         SP_EVENT_THREAD))
    print("rids:", rids)
    trigger()
    deadline = time.time() + 30
    seen = 0
    while time.time() < deadline and seen < 2:
        try:
            ev = c.next_event(timeout=20)
        except Exception as e:
            print("event wait:", e); trigger(); continue
        for e in ev.get("events", []):
            if e.get("request_id") not in rids or "thread" not in e:
                continue
            seen += 1
            t = e["thread"]
            print("== EVENT rid", e["request_id"], "loc", e.get("location"))
            fr = c.thread_frames(t, 1)[0]
            print("  frame0:", fr)
            try:
                this = c.frame_this_object(t, fr["frame_id"])
                print("  this:", this)
            except Exception as ex:
                print("  this ERR:", ex)
            print("  slots:", json.dumps(probe(c, t, fr["frame_id"]),
                                       default=str))
            c.thread_resume(t)
    for rid in rids:
        c.clear_event(2, rid)
    s.close()


if __name__ == "__main__":
    main()

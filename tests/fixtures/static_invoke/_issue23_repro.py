"""Issue #23 reproduction: ClassType.InvokeMethod (static) on Android 15
and a desktop JVM control.

Matrix per runtime: static invoke on an EVENT-suspended thread with
options INVOKE_SINGLE_THREADED(1) and 0; plus a negative control on a
thread suspended only by ThreadReference.Suspend. Records negotiated ID
sizes, method identity, thread status/suspend count (ThreadReference
11/4 and 11/12 raw), reply/error, and socket health after each call.

Usage: python _issue23_repro.py [serial]
Writes _issue23_out.json next to this script.
"""
import json, subprocess, sys, time

sys.path.insert(0, r"J:\reverse\debug_tool")
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, SP_EVENT_THREAD, TAG_STRING, JdwpClient,
)
from apkdbg.core.project import Project
from apkdbg.debug.session import DebugSession
from apkdbg.errors import ApkDbgError

HERE = r"J:\reverse\debug_tool\tests\fixtures\static_invoke"
SERIAL = sys.argv[1] if len(sys.argv) > 1 else "4b79a217"
PKG = "com.apkdbg.cryptofixture"
PROJ = r"J:\reverse\debug_tool\tests\fixtures\crypto\proj"
JAVA = r"C:\Program Files\Zulu\zulu-21\bin\java"
rep = {"android": {}, "desktop": {}}


def adb(*a):
    return subprocess.run(["adb", "-s", SERIAL, *a],
                          capture_output=True, text=True)


def thread_state(c, thread):
    """ThreadReference.Status (11/4) + SuspendCount (11/12), raw."""
    w = c._writer() if hasattr(c, "_writer") else None
    from apkdbg.device.jdwp import Writer
    w = Writer(c.sizes)
    w.object_id(thread)
    st = c.request(11, 4, bytes(w.buf))
    status, susp = st.u32(), st.u32()
    w = Writer(c.sizes)
    w.object_id(thread)
    cnt = c.request(11, 12, bytes(w.buf))
    return {"thread_status": status, "suspend_status": susp,
            "suspend_count": cnt.u32()}


def health(c, probe_sig, probe_id):
    try:
        return c.rt_signature(probe_id) == probe_sig
    except Exception:
        return False


def find_static(c, cls_sig, name, sig):
    classes = c.classes_by_signature(cls_sig)
    assert classes, f"{cls_sig} not loaded"
    tid = classes[0]["type_id"]
    m = next(m for m in c.rt_methods(tid)
             if m["name"] == name and m["sig"] == sig)
    return tid, m


def break_on_entry(c, cls_sig, name, sig):
    classes = c.classes_by_signature(cls_sig)
    tid = classes[0]["type_id"]
    m = next(m for m in c.rt_methods(tid)
             if m["name"] == name and m["sig"] == sig)
    try:
        lt = c.method_line_table(tid, m["id"])
        idx = lt["lines"][0]["index"] if lt["lines"] else 0
    except Exception:
        idx = 0
    rid = c.set_breakpoint(tid, m["id"], idx, SP_EVENT_THREAD)
    return tid, m, rid


def invoke_matrix(c, tid, m, arg_str, label, thread, probe):
    out = []
    for options in (1, 0):
        state = thread_state(c, thread)
        arg = c.create_string(arg_str)
        entry = {"options": options, "state_before": state,
                 "method": m["name"] + m["sig"]}
        try:
            r = c.ct_invoke_method(tid, thread, m["id"],
                                   [(TAG_STRING, arg)], options=options)
            entry["reply"] = {"tag": r["value"]["tag"],
                              "v": r["value"]["v"],
                              "exception": r["exception"]}
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {str(e)[:120]}"
        entry["healthy_after"] = health(c, *probe)
        out.append(entry)
    return out


def run_desktop():
    d = {"runtime": "desktop JVM (Zulu 21)", "steps": []}
    proc = subprocess.Popen(
        [JAVA, "-agentlib:jdwp=transport=dt_socket,server=y,"
               "suspend=y,address=7799", "StaticControl"],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        c = JdwpClient("127.0.0.1", 7799, timeout=10)
        for _ in range(50):
            try:
                c.connect()
                break
            except Exception:
                time.sleep(0.3)
        d["id_sizes"] = vars(c.sizes)
        c.vm_resume()  # release the suspend=y start so main class loads
        for _ in range(50):
            if c.classes_by_signature("LStaticControl;"):
                break
            time.sleep(0.2)
        tid, m0 = None, None
        classes = c.classes_by_signature("LStaticControl;")
        tid = classes[0]["type_id"]
        m = next(m for m in c.rt_methods(tid)
                 if m["name"] == "busyLoop" and m["sig"] == "()V")
        lt = c.method_line_table(tid, m["id"])
        # index-0 line (`int i = 0;`) ran before the bp was set; break on
        # every later line (loop body) so a running loop hits one
        idxs = [l["index"] for l in lt["lines"][1:]] or [0]
        rids = [c.set_breakpoint(tid, m["id"], i, SP_EVENT_THREAD)
                for i in idxs]
        probe = ("LStaticControl;", tid)
        stid, sm = find_static(c, "LStaticControl;", "answer",
                               "(Ljava/lang/String;)I")
        ev, deadline = None, time.time() + 20
        while ev is None and time.time() < deadline:
            comp = c.next_event(timeout=10)
            for e in comp["events"]:
                if e.get("request_id") in rids:
                    ev = e
                elif "thread" in e:
                    c.thread_resume(e["thread"])
        assert ev, "busyLoop breakpoint never fired"
        thread = ev["thread"]
        d["steps"].append({"event_suspended_thread":
                           invoke_matrix(c, stid, sm, "41", "answer",
                                         thread, probe)})
        # negative control: plain ThreadReference.Suspend thread
        c.thread_suspend(thread)
        state = thread_state(c, thread)
        entry = {"thread_suspend_only": True, "state_before": state}
        try:
            arg = c.create_string("41")
            r = c.ct_invoke_method(stid, thread, sm["id"],
                                   [(TAG_STRING, arg)], options=1)
            entry["reply"] = {"tag": r["value"]["tag"],
                              "v": r["value"]["v"],
                              "exception": r["exception"]}
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {str(e)[:120]}"
        entry["healthy_after"] = health(c, *probe)
        d["steps"].append({"negative_control": entry})
        try:
            c.thread_resume(thread)
            c.thread_resume(thread)
            [c.clear_event(EVK_BREAKPOINT, r) for r in rids]
        except Exception:
            pass
        c.close()
    finally:
        proc.kill()
    return d


def run_android():
    a = {"steps": []}
    for k in ("ro.product.model", "ro.build.version.release",
              "ro.build.version.sdk"):
        a[k] = adb("shell", "getprop", k).stdout.strip()
    adb("shell", "am", "broadcast", "-a", "com.apkdbg.cryptofixture.RUN",
        "-p", PKG)
    time.sleep(1)
    s = DebugSession(Project(PROJ), serial=SERIAL)
    a["connect"] = s.connect(PKG)
    c = s.client
    a["id_sizes"] = vars(c.sizes)
    recv = "Lcom/apkdbg/cryptofixture/RunReceiver;"
    tid, m, rid = break_on_entry(c, recv, "onReceive",
                                 "(Landroid/content/Context;"
                                 "Landroid/content/Intent;)V")
    probe = (recv, tid)
    adb("shell", "am", "broadcast", "-a", "com.apkdbg.cryptofixture.RUN",
        "-p", PKG)
    comp = c.next_event(timeout=15)
    ev = next(e for e in comp["events"] if e.get("request_id") == rid)
    thread = ev["thread"]
    # app-local static: RunReceiver.hex(String)[B
    stid, sm = find_static(c, recv, "hex", "(Ljava/lang/String;)[B")
    a["steps"].append({"app_local_static_hex": invoke_matrix(
        c, stid, sm, "0aff", "hex", thread, probe)})
    # platform static: Integer.parseInt(String)I
    pid, pm = find_static(c, "Ljava/lang/Integer;", "parseInt",
                          "(Ljava/lang/String;)I")
    a["steps"].append({"platform_parseInt": invoke_matrix(
        c, pid, pm, "42", "parseInt", thread, probe)})
    # negative control
    c.thread_suspend(thread)
    entry = {"thread_suspend_only": True,
             "state_before": thread_state(c, thread)}
    try:
        arg = c.create_string("42")
        r = c.ct_invoke_method(pid, thread, pm["id"],
                               [(TAG_STRING, arg)], options=1)
        entry["reply"] = {"tag": r["value"]["tag"], "v": r["value"]["v"],
                          "exception": r["exception"]}
    except Exception as e:
        entry["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    entry["healthy_after"] = health(c, *probe)
    a["steps"].append({"negative_control": entry})
    try:
        c.thread_resume(thread)
        c.thread_resume(thread)
        [c.clear_event(EVK_BREAKPOINT, r) for r in rids]
    except Exception:
        pass
    s.close()
    return a


def main():
    rep["desktop"] = run_desktop()
    rep["android"] = run_android()
    with open(HERE + r"\_issue23_out.json", "w") as f:
        json.dump(rep, f, indent=1, default=str)
    print(json.dumps(rep, indent=1, default=str))


if __name__ == "__main__":
    main()

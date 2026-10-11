"""Device validation for issue #22 — checked instance invoke + NewInstance.

Against com.wolfs.myapplication (debuggable) on the connected device:
 1. launch suspended (-D), CLASS_PREPARE watch -> breakpoint at
    MainActivity.onCreate entry -> receiver object
 2. checked resolve+invoke of INHERITED Activity.getIntent() (the pairing
    that disconnected Android 15 when sent as subclass type id +
    superclass method id) -> must succeed, socket stays healthy
 3. ct_new_instance rejects a non-<init> / wrong-class method id LOCALLY
    (no request sent, connection untouched)
 4. valid checked construction: new StringBuilder() then checked invoke
    of toString()
Writes a JSON report to _issue22_out.json next to this script.
"""
import json, subprocess, sys, time

sys.path.insert(0, r"J:\reverse\debug_tool")
from apkdbg.core.project import Project
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_CLASS_PREPARE, SP_EVENT_THREAD,
)
from apkdbg.errors import ApkDbgError

SERIAL = sys.argv[1] if len(sys.argv) > 1 else "4b79a217"
PKG = "com.wolfs.myapplication"
MA = "Lcom/wolfs/myapplication/MainActivity;"
PROJ = r"J:\reverse\debug_tool\test_scope\proj_wolfs"
OUT = r"J:\reverse\debug_tool\tests\fixtures\_issue22_out.json"
rep = {"device": {}, "steps": []}


def adb(*a):
    return subprocess.run(["adb", "-s", SERIAL, *a],
                          capture_output=True, text=True)


def step(name, **kw):
    rep["steps"].append({"step": name, **kw})
    print(json.dumps({"step": name, **kw}))


def main():
    for k in ("ro.product.model", "ro.build.version.release",
              "ro.build.version.sdk"):
        rep["device"][k] = adb("shell", "getprop", k).stdout.strip()
    proj = Project(PROJ)
    s = DebugSession(proj, serial=SERIAL)
    info = s.connect(PKG, launch=True)   # force-stop + am start -D
    rep["vm"] = info
    c = s.client
    step("connected", pid=info["pid"], vm=info["vm"])

    # 1. CLASS_PREPARE watch for MainActivity, then onCreate breakpoint
    prep = c.set_event(EVK_CLASS_PREPARE, SP_EVENT_THREAD,
                       [c.mod_class_match(
                           "com.wolfs.myapplication.MainActivity")])
    c.vm_resume()
    cls = None
    deadline = time.time() + 45
    while time.time() < deadline and cls is None:
        comp = c.next_event(timeout=10)
        for e in comp["events"]:
            if e.get("request_id") == prep and e.get("signature") == MA:
                cls = {"type_id": e["type_id"]}
            if "thread" in e:
                c.thread_resume(e["thread"])
    c.clear_event(EVK_CLASS_PREPARE, prep)
    assert cls, "MainActivity never prepared"
    m = next(m for m in c.rt_methods(cls["type_id"])
             if m["name"] == "onCreate"
             and m["sig"] == "(Landroid/os/Bundle;)V")
    lt = c.method_line_table(cls["type_id"], m["id"])
    idx = lt["lines"][0]["index"] if lt["lines"] else 0
    rid = c.set_breakpoint(cls["type_id"], m["id"], idx, SP_EVENT_THREAD)
    ev, deadline = None, time.time() + 45
    while time.time() < deadline and ev is None:
        comp = c.next_event(timeout=10)
        for e in comp["events"]:
            if e.get("request_id") == rid:
                ev = e
            elif "thread" in e:
                c.thread_resume(e["thread"])
    c.clear_event(EVK_BREAKPOINT, rid)
    assert ev, "onCreate breakpoint never fired"
    thread = ev["thread"]
    fr = c.thread_frames(thread, 1)[0]
    this = c.frame_this_object(thread, fr["frame_id"])["v"]
    _, rt = c.object_reftype(this)
    step("receiver", obj=this, runtime_type_id=rt,
         requested_type_id=cls["type_id"])

    # 2. checked resolve + invoke of inherited getIntent
    def_cls, mid = c.resolve_instance_method(
        rt, "getIntent", "()Landroid/content/Intent;")
    step("resolved", declaring_class_id=def_cls, method_id=mid,
         inherited=def_cls != rt)
    r = c.invoke_object_method(this, thread, def_cls, mid, [])
    step("invoke_getIntent", options=1,
         value_tag=r["value"]["tag"], value=r["value"]["v"],
         exception=r["exception"])
    healthy = c.rt_signature(rt) == MA
    step("health_after_invoke", ok=healthy,
         resolved_sig=c.rt_signature(def_cls))

    # 3. constructor validation rejects locally (no request sent)
    sb = c.classes_by_signature("Ljava/lang/StringBuilder;")[0]["type_id"]
    tostring = next(m for m in c.rt_methods(sb) if m["name"] == "toString")
    rejected = None
    try:
        c.ct_new_instance(sb, thread, tostring["id"], [])
    except ApkDbgError as e:
        rejected = {"code": getattr(e, "code", None), "msg": str(e)[:100]}
    step("new_instance_rejected_locally", rejected=rejected,
         healthy=c.rt_signature(sb).endswith("StringBuilder;"))

    # 4. valid checked construction + checked invoke on the new object
    init = next(m for m in c.rt_methods(sb)
                if m["name"] == "<init>" and m["sig"] == "()V")
    r = c.ct_new_instance(sb, thread, init["id"], [])
    new_obj = r["value"]["v"]
    step("new_instance_ok", obj=new_obj, exception=r["exception"])
    dc2, mid2 = c.resolve_instance_method(sb, "toString",
                                          "()Ljava/lang/String;")
    r = c.invoke_object_method(new_obj, thread, dc2, mid2, [])
    step("invoke_toString", value_tag=r["value"]["tag"],
         string=c.string_value(r["value"]["v"]) if r["value"]["v"] else None,
         exception=r["exception"])
    c.thread_resume(thread)
    healthy = c.rt_signature(rt) == MA
    rep["healthy_end"] = healthy
    steps = {s_["step"]: s_ for s_ in rep["steps"]}
    rep["pass"] = all([
        steps["resolved"]["inherited"],
        steps["invoke_getIntent"]["value"] not in (None, 0),
        steps["invoke_getIntent"]["exception"] in (None, 0),
        steps["health_after_invoke"]["ok"],
        steps["new_instance_rejected_locally"]["rejected"],
        steps["new_instance_rejected_locally"]["healthy"],
        steps["new_instance_ok"]["obj"],
        steps["invoke_toString"]["exception"] in (None, 0),
        healthy,
    ])
    with open(OUT, "w") as f:
        json.dump(rep, f, indent=1)
    print(json.dumps({"pass": rep["pass"]}))
    s.close()


if __name__ == "__main__":
    main()

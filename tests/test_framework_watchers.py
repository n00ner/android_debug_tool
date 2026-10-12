"""Offline regression tests for issue #27 — opt-in framework watcher
profiles (navigation / storage / services). Duck-typed FakeJdwpClient
drives a real DebugSession (no device)."""

from __future__ import annotations

import tempfile
import threading
import unittest
from unittest.mock import patch

from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug.hooks import framework
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_CLASS_PREPARE, EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, SP_NONE,
    TAG_OBJECT, TAG_STRING, JdwpError,
)
from apkdbg.errors import SessionError

ACT = "Landroid/app/Activity;"
CTXW = "Landroid/content/ContextWrapper;"
CTX = "Landroid/content/Context;"
CIMPL = "Landroid/app/ContextImpl;"
INTENT = "Landroid/content/Intent;"
EDITOR = "Landroid/content/SharedPreferences$Editor;"
EDIMPL = "Landroid/app/SharedPreferencesImpl$EditorImpl;"
CUSTOM_ED = "Lcom/foo/CustomEditor;"

PUTSTRING_SIG = ("(Ljava/lang/String;Ljava/lang/String;)"
                 "Landroid/content/SharedPreferences$Editor;")
SVC_NAME_SIG = "(Ljava/lang/String;)Ljava/lang/Object;"


def _timeout_error():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeJdwpClient:
    def __init__(self):
        self.next_rid = 1
        self.classes = {}        # sig -> [{"type_id": int}]
        self.methods = {}        # type_id -> [{"name","sig","id","mod_bits"}]
        self.sigs = {}           # type_id -> signature
        self.fields = {}         # type_id -> [{"name","id"}]
        self.supers = {}         # type_id -> superclass id (0 = none)
        self.obj_types = {}      # oid -> type_id
        self.obj_values = {}     # (oid, field_id) -> tagged value
        self.frames = {}         # thread -> [frame dicts]
        self.this_objects = {}   # frame_id -> oid
        self.slot_values = {}    # (frame_id, slot) -> value
        self.strings = {}        # oid -> str
        self.dead_strings = set()
        self.invocations = []    # (oid, class_id, method_id)
        self.invoke_results = {}  # (class_id, method_id) -> {"value":...}
        self.invoke_throws = set()  # (class_id, method_id) -> raises
        self.event_queue = []
        self.cleared = []
        self.resumed = []
        self.set_calls = []

    def close(self):
        pass

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    def classes_by_signature(self, sig):
        return self.classes.get(sig, [])

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def rt_signature(self, type_id):
        return self.sigs.get(type_id, f"Lfake/{type_id};")

    def rt_class_loader(self, type_id):
        return 9000

    def rt_fields(self, type_id):
        return self.fields.get(type_id, [])

    def ct_superclass(self, class_id):
        return self.supers.get(class_id, 0)

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_event(self, kind, suspend, mods):
        self.set_calls.append((kind, suspend, list(mods)))
        return self._rid()

    def mod_class_only(self, type_id):
        return ("class_only", type_id)

    def mod_class_match(self, pattern):
        return ("class_match", pattern)

    def mod_thread_only(self, thread):
        return ("thread_only", thread)

    def mod_count(self, n):
        return ("count", n)

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout_error()

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def vm_resume(self):
        pass

    def thread_frames(self, thread, count=32):
        return self.frames.get(thread, [])[:count]

    def frame_get_values(self, thread, frame_id, slots):
        return [{"tag": tag, "v": self.slot_values.get((frame_id, slot))}
                for slot, tag in slots]

    def frame_this_object(self, thread, frame_id):
        return {"tag": TAG_OBJECT, "v": self.this_objects.get(frame_id)}

    def object_reftype(self, obj):
        if obj not in self.obj_types:
            raise JdwpError("INVALID_OBJECT")
        return TAG_OBJECT, self.obj_types[obj]

    def object_get_values(self, obj, field_ids):
        if obj not in self.obj_types:
            raise JdwpError("INVALID_OBJECT")
        return [self.obj_values.get((obj, f), {"tag": 86, "v": None})
                for f in field_ids]

    def string_value(self, oid, max_len=4096):
        if oid in self.dead_strings:
            raise JdwpError("INVALID_OBJECT")
        return self.strings.get(oid, "")[:max_len]

    def resolve_instance_method(self, type_id, name, sig=None):
        cid = type_id
        while cid:
            for m in self.methods.get(cid, []):
                if m["name"] == name and (sig is None or m["sig"] == sig):
                    return cid, m["id"]
            cid = self.supers.get(cid, 0)
        raise JdwpError(f"method {name} not found")

    def invoke_object_method(self, obj, thread, class_id, method_id, args,
                             options=1, *, validated=True):
        self.invocations.append((obj, class_id, method_id))
        if (class_id, method_id) in self.invoke_throws:
            raise JdwpError("reply timeout")
        r = self.invoke_results.get((class_id, method_id))
        if r is None:
            raise JdwpError("no such method")
        return r


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def nav_client() -> FakeJdwpClient:
    """Fake VM: Activity + ContextWrapper + ContextImpl loaded with the
    startActivity overloads and lifecycle methods; intent type 6000."""
    c = FakeJdwpClient()
    c.classes[ACT] = [{"type_id": 1000}]
    c.classes[CTXW] = [{"type_id": 2000}]
    c.classes[CIMPL] = [{"type_id": 3000}]
    c.sigs.update({1000: ACT, 2000: CTXW, 3000: CIMPL, 6000: INTENT})
    c.methods[1000] = [
        {"name": "startActivity", "sig": "(Landroid/content/Intent;)V",
         "id": 1100, "mod_bits": 0x0001},
        {"name": "startActivity",
         "sig": "(Landroid/content/Intent;Landroid/os/Bundle;)V",
         "id": 1101, "mod_bits": 0x0001},
        {"name": "onCreate", "sig": "(Landroid/os/Bundle;)V", "id": 1102,
         "mod_bits": 0x0004},
        {"name": "onNewIntent", "sig": "(Landroid/content/Intent;)V",
         "id": 1103, "mod_bits": 0x0004},
    ]
    c.methods[2000] = [
        {"name": "startActivity", "sig": "(Landroid/content/Intent;)V",
         "id": 2100, "mod_bits": 0x0001},
        {"name": "startActivity",
         "sig": "(Landroid/content/Intent;Landroid/os/Bundle;)V",
         "id": 2101, "mod_bits": 0x0001},
    ]
    c.methods[3000] = [
        {"name": "startActivity", "sig": "(Landroid/content/Intent;)V",
         "id": 3100, "mod_bits": 0x0001},
        {"name": "startActivity",
         "sig": "(Landroid/content/Intent;Landroid/os/Bundle;)V",
         "id": 3101, "mod_bits": 0x0001},
    ]
    # Intent fields for bounded capture
    c.fields[6000] = [{"name": "mAction", "id": 61},
                      {"name": "mFlags", "id": 62}]
    return c


def store_client() -> FakeJdwpClient:
    """Fake VM: the Editor interface (abstract) + AOSP impl (concrete)."""
    c = FakeJdwpClient()
    c.classes[EDITOR] = [{"type_id": 4000}]
    c.classes[EDIMPL] = [{"type_id": 4001}]
    c.sigs.update({4000: EDITOR, 4001: EDIMPL})
    abstr = [
        {"name": "putString", "sig": PUTSTRING_SIG, "id": 4050,
         "mod_bits": 0x0401},
        {"name": "apply", "sig": "()V", "id": 4051, "mod_bits": 0x0401},
        {"name": "commit", "sig": "()Z", "id": 4052, "mod_bits": 0x0401},
    ]
    c.methods[4000] = abstr
    c.methods[4001] = [
        {"name": "putString", "sig": PUTSTRING_SIG, "id": 4100,
         "mod_bits": 0x0001},
        {"name": "putInt",
         "sig": "(Ljava/lang/String;I)"
                "Landroid/content/SharedPreferences$Editor;",
         "id": 4101, "mod_bits": 0x0001},
        {"name": "remove",
         "sig": "(Ljava/lang/String;)"
                "Landroid/content/SharedPreferences$Editor;",
         "id": 4102, "mod_bits": 0x0001},
        {"name": "clear",
         "sig": "()Landroid/content/SharedPreferences$Editor;",
         "id": 4103, "mod_bits": 0x0001},
        {"name": "apply", "sig": "()V", "id": 4104, "mod_bits": 0x0001},
        {"name": "commit", "sig": "()Z", "id": 4105, "mod_bits": 0x0001},
    ]
    return c


def svc_client() -> FakeJdwpClient:
    """Fake VM: abstract Context declarations + concrete ContextImpl."""
    c = FakeJdwpClient()
    c.classes[CTX] = [{"type_id": 5000}]
    c.classes[CIMPL] = [{"type_id": 3000}]
    c.sigs.update({5000: CTX, 3000: CIMPL, 6001: "Landroid/app/ActivityManager;"})
    c.methods[5000] = [
        {"name": "getSystemService", "sig": SVC_NAME_SIG, "id": 5100,
         "mod_bits": 0x0401},
        {"name": "getSystemService",
         "sig": "(Ljava/lang/Class;)Ljava/lang/Object;", "id": 5101,
         "mod_bits": 0x0401},
    ]
    c.methods[3000] = [
        {"name": "getSystemService", "sig": SVC_NAME_SIG, "id": 5105,
         "mod_bits": 0x0001},
        {"name": "getSystemService",
         "sig": "(Ljava/lang/Class;)Ljava/lang/Object;", "id": 5106,
         "mod_bits": 0x0001},
    ]
    return c


def exit_event(rid, thread=11, cls=1000, method=1100, ret=None):
    return {"kind": "method_exit_return", "kind_id": EVK_METHOD_EXIT_RET,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 3},
            "return_value": ret if ret is not None else {"tag": 86,
                                                         "v": None}}


def composite(*events, sp=SP_EVENT_THREAD):
    return {"suspend_policy": sp, "events": list(events)}


def make_cfg(**over):
    cfg = {"mode": "attributed", "scope": None, "exclude": [],
           "invoke_getters": False, "corr_window_ms": 250,
           "max_stack": 8, "max_str": 512,
           "_stats": framework._new_stats(), "_stop": None,
           "_editors": {}, "_svc_counts": {},
           "_corr_open": {}, "_corr_seq": 0}
    cfg.update(over)
    return cfg


def _frame(fid, cls, method, index=0):
    return {"frame_id": fid,
            "location": {"class": cls, "method": method, "index": index}}


# ------------------------------------------------------------------ profiles
class ProfileTests(unittest.TestCase):
    def test_family_expansion(self):
        profs = framework.resolve_profiles(["navigation"])
        names = {p["name"] for p in profs}
        self.assertIn("nav.activity.start", names)
        self.assertIn("nav.contextimpl.start.opts", names)
        self.assertIn("nav.lifecycle.oncreate", names)
        self.assertTrue(all(p["family"] == "navigation" for p in profs))
        store = framework.resolve_profiles(["storage"])
        self.assertIn("store.commit", {p["name"] for p in store})
        svc = framework.resolve_profiles(["services"])
        self.assertEqual({p["name"] for p in svc},
                         {"svc.name", "svc.class"})

    def test_unknown_selector_rejected(self):
        with self.assertRaises(SessionError):
            framework.resolve_profiles(["nav.x"])
        with self.assertRaises(SessionError):
            framework.resolve_profile("storage.extra")

    def test_builtin_shapes(self):
        commit = framework.resolve_profile("store.commit")
        self.assertEqual(commit["ret"], "boolean")
        self.assertEqual(commit["role"], "submit")
        self.assertIn(EDIMPL.split(";")[0] + ";", commit["cls_alts"])
        req = framework.resolve_profile("nav.activity.start")
        self.assertEqual(req["args"], [("intent", "object")])
        svc = framework.resolve_profile("svc.name")
        self.assertEqual(svc["args"], [("name", "string")])
        self.assertEqual(svc["ret"], "object")

    def test_custom_profile_validation_and_auto_args(self):
        p = framework.resolve_profile(
            {"cls": CUSTOM_ED, "method": "commit", "sig": "()Z",
             "family": "storage", "role": "submit", "ret": "boolean"})
        self.assertEqual(p["name"], "custom:commit()Z")
        self.assertEqual(p["args"], [])
        p = framework.resolve_profile(
            {"cls": "LX;", "method": "m",
             "sig": "(Ljava/lang/String;IJ)V"})
        self.assertEqual(p["args"], [("arg0", "string"), ("arg1", "int"),
                                     ("arg2", "long")])
        with self.assertRaises(SessionError):
            framework.resolve_profile({"cls": "LX;"})
        with self.assertRaises(SessionError):
            framework.resolve_profile({"cls": "LX;", "method": "m",
                                       "sig": "()V", "ret": "weird"})


# -------------------------------------------------------------------- install
class InstallTests(unittest.TestCase):
    def test_interface_skipped_concrete_impl_hooked(self):
        c = store_client()
        s = make_session(c)
        rep = framework.install(s, framework.resolve_profiles(["storage"]))
        # the abstract interface contributes no requests; every concrete
        # storage method installs exactly one
        self.assertEqual(rep["states"]["store.putstring"], "installed")
        rids = [i["request_ids"] for i in rep["installed"]
                if i["profile"] == "store.putstring"][0]
        self.assertEqual(len(rids), 1)
        self.assertEqual(s.bp_registry[rids[0]]["type_id"], 4001)
        # commit's boolean return is captured via the exit event
        reg = s.bp_registry[[i["request_ids"][0] for i in rep["installed"]
                             if i["profile"] == "store.commit"][0]]
        self.assertEqual(reg["profile"]["ret"], "boolean")

    def test_interface_only_is_unsupported(self):
        c = store_client()
        c.classes[EDIMPL] = []  # no concrete implementation loaded
        s = make_session(c)
        rep = framework.install(s, [framework.resolve_profile(
            "store.putstring")])
        self.assertEqual(rep["states"], {"store.putstring": "unsupported"})

    def test_overload_matched_by_exact_sig(self):
        c = nav_client()
        s = make_session(c)
        rep = framework.install(s, [framework.resolve_profile(
            "nav.activity.start")])
        rid = rep["installed"][0]["request_ids"][0]
        self.assertEqual(s.bp_registry[rid]["method_id"], 1100)  # not 1101
        self.assertEqual(s.bp_registry[rid]["capture_spec"],
                         [{"slot": 1, "type": "object", "label": "intent"}])

    def test_pending_not_found_native(self):
        s = make_session(FakeJdwpClient())
        rep = framework.install(s, [framework.resolve_profile(
            "nav.activity.start")])
        self.assertEqual(rep["states"], {"nav.activity.start": "pending"})

        c = nav_client()
        del c.methods[1000][0]  # only the Bundle overload remains
        s = make_session(c)
        rep = framework.install(s, [framework.resolve_profile(
            "nav.activity.start")])
        self.assertEqual(rep["states"], {"nav.activity.start": "not-found"})

        c = nav_client()
        c.methods[1000][0]["mod_bits"] = 0x0101  # native
        s = make_session(c)
        rep = framework.install(s, [framework.resolve_profile(
            "nav.activity.start")])
        self.assertEqual(rep["states"],
                         {"nav.activity.start": "unsupported"})
        self.assertIn("native", rep["pending"][0]["reason"])

    def test_services_abstract_ctx_skipped_impl_hooked(self):
        c = svc_client()
        s = make_session(c)
        rep = framework.install(s, framework.resolve_profiles(["services"]))
        self.assertEqual(rep["states"]["svc.name"], "installed")
        rid = [i["request_ids"] for i in rep["installed"]
               if i["profile"] == "svc.name"][0][0]
        self.assertEqual(s.bp_registry[rid]["type_id"], 3000)

    def test_install_idempotent_per_class(self):
        c = store_client()
        s = make_session(c)
        rep1 = framework.install(s, [framework.resolve_profile(
            "store.commit")])
        rep2 = framework.install(s, [framework.resolve_profile(
            "store.commit")])
        self.assertEqual(rep1["installed"][0]["request_ids"],
                         rep2["installed"][0]["request_ids"])
        self.assertEqual(len(c.set_calls), 1)


class DeferTests(unittest.TestCase):
    def test_late_loaded_custom_editor_via_defer(self):
        c = FakeJdwpClient()  # custom editor not loaded at install time
        s = make_session(c)
        loaded = {"yes": False}

        def cbs(sig):
            if sig == CUSTOM_ED and loaded["yes"]:
                return [{"type_id": 4500}]
            return []
        c.classes_by_signature = cbs
        orig_next = c.next_event

        def next_then_load(timeout=None):
            comp = orig_next(timeout)
            loaded["yes"] = True
            return comp
        c.next_event = next_then_load
        c.sigs[4500] = CUSTOM_ED
        c.methods[4500] = [{"name": "commit", "sig": "()Z", "id": 4501,
                            "mod_bits": 0x0001}]
        prof = {"cls": CUSTOM_ED, "method": "commit", "sig": "()Z",
                "family": "storage", "role": "submit", "ret": "boolean"}
        c.frames[11] = [_frame(5, 4500, 4501)]
        c.this_objects[5] = 9600
        c.event_queue.append(
            composite({"kind": "class_prepare",
                       "kind_id": EVK_CLASS_PREPARE, "request_id": 1,
                       "thread": 11, "type_id": 4500,
                       "signature": CUSTOM_ED, "status": 0}))
        c.event_queue.append(composite(
            exit_event(2, cls=4500, method=4501, ret={"tag": 90, "v": 1})))

        res = framework.run_watch(s, profiles=[prof], duration_s=5,
                                  defer=True)
        self.assertEqual(res["states"], {"custom:commit()Z": "pending"})
        self.assertEqual(res["auto_installed"], [2])
        rec = res["records"][0]
        self.assertEqual(rec["role"], "submit")
        self.assertIs(rec["result"], True)
        self.assertEqual(res["transactions"][0]["commit_result"], True)
        self.assertEqual(set(c.cleared), {(EVK_CLASS_PREPARE, 1),
                                          (EVK_METHOD_EXIT_RET, 2)})


# -------------------------------------------------------------------- extract
class StorageExtractTests(unittest.TestCase):
    def setUp(self):
        self.c = store_client()
        self.s = make_session(self.c)
        rep = framework.install(
            self.s, framework.resolve_profiles(["storage"]))
        self.rids = {i["profile"]: i["request_ids"][0]
                     for i in rep["installed"]}
        self.c.frames[11] = [_frame(5, 4001, 4100)]
        self.c.this_objects[5] = 9001
        self.c.slot_values[(5, 1)] = 8001
        self.c.slot_values[(5, 2)] = 8002
        self.c.strings[8001] = "greeting"
        self.c.strings[8002] = "hello-framework"

    def _put(self, rid_key="store.putstring", oid=9001, thread=11):
        self.c.this_objects[5] = oid
        return extract(framework, self.s,
                       exit_event(self.rids[rid_key], thread=thread,
                                  cls=4001, method=4100,
                                  ret={"tag": TAG_OBJECT, "v": oid}),
                       self.cfg)

    def test_staged_vs_submit_vs_commit_result(self):
        self.cfg = make_cfg()
        rec = self._put()
        self.assertEqual(rec["role"], "staged")
        self.assertEqual(rec["op"], {"op": "putString", "key": "greeting",
                                     "value": "hello-framework"})
        self.assertEqual(rec["editor"], "E1")
        # apply = submission of the same editor
        self.c.frames[11] = [_frame(6, 4001, 4104)]
        self.c.this_objects[6] = 9001
        rec = extract(framework, self.s,
                      exit_event(self.rids["store.apply"], cls=4001,
                                 method=4104), self.cfg)
        self.assertEqual(rec["role"], "submit")
        self.assertEqual(rec["op"], {"op": "apply"})
        # commit on a second editor captures the boolean result
        self.c.frames[11] = [_frame(7, 4001, 4105)]
        self.c.this_objects[7] = 9002
        rec = extract(framework, self.s,
                      exit_event(self.rids["store.commit"], cls=4001,
                                 method=4105, ret={"tag": 90, "v": 1}),
                      self.cfg)
        self.assertEqual(rec["op"], {"op": "commit", "result": True})
        tx = {t["editor"]: t for t in framework._transactions(self.cfg)}
        self.assertEqual(tx["E1"]["submitted"], "apply")
        self.assertFalse(tx["E1"]["discarded"])
        self.assertEqual(tx["E2"]["submitted"], "commit")
        self.assertIs(tx["E2"]["commit_result"], True)

    def test_discarded_editor_distinguishable(self):
        self.cfg = make_cfg()
        self._put(oid=9003)  # staged, never submitted
        tx = framework._transactions(self.cfg)
        self.assertEqual(len(tx), 1)
        self.assertTrue(tx[0]["discarded"])
        self.assertEqual(tx[0]["staged_count"], 1)
        self.assertIsNone(tx[0]["submitted"])

    def test_concurrent_editors_not_conflated(self):
        self.cfg = make_cfg()
        self._put(oid=9001)
        self._put(oid=9002)
        self._put(oid=9001)
        eds = self.cfg["_editors"]
        self.assertEqual(len(eds), 2)
        self.assertEqual(eds[9001]["alias"], "E1")
        self.assertEqual(eds[9002]["alias"], "E2")
        self.assertEqual(len(eds[9001]["staged"]), 2)
        self.assertEqual(len(eds[9002]["staged"]), 1)
        # each editor's ops share that editor's correlation id
        tx_ops = framework._transactions(self.cfg)
        self.assertNotEqual(tx_ops[0]["oid"], tx_ops[1]["oid"])

    def test_editor_without_this_is_explicit(self):
        self.cfg = make_cfg()
        self.c.this_objects.clear()  # this read yields no object
        rec = extract(framework, self.s,
                      exit_event(self.rids["store.putstring"], cls=4001,
                                 method=4100,
                                 ret={"tag": TAG_OBJECT, "v": 9001}),
                      self.cfg)
        self.assertIn("editor", rec["capture_errors"])
        self.assertNotIn("editor_oid", rec)


class NavExtractTests(unittest.TestCase):
    def setUp(self):
        self.c = nav_client()
        self.s = make_session(self.c)
        rep = framework.install(
            self.s, framework.resolve_profiles(["navigation"]))
        self.rids = {i["profile"]: i["request_ids"][0]
                     for i in rep["installed"]}
        # intent object 7001 with bounded field values
        self.c.obj_types[7001] = 6000
        self.c.obj_values[(7001, 61)] = {"tag": TAG_STRING, "v": 8005}
        self.c.obj_values[(7001, 62)] = {"tag": 73, "v": 16}
        self.c.strings[8005] = "com.apkdbg.FW_NAV"
        self.c.frames[11] = [_frame(5, 1000, 1100)]
        self.c.slot_values[(5, 1)] = 7001

    def test_request_record_with_bounded_intent_capture(self):
        cfg = make_cfg()
        rec = extract(framework, self.s,
                      exit_event(self.rids["nav.activity.start"]), cfg)
        self.assertEqual(rec["role"], "request")
        self.assertEqual(rec["target"], {"intent_id": 7001, "cls": INTENT})
        self.assertEqual(rec["intent"]["fields"]["action"],
                         "com.apkdbg.FW_NAV")
        self.assertEqual(rec["intent"]["fields"]["flags"],
                         {"type": "int", "v": 16})
        # getter invocation is off by default: explicit, never silent
        self.assertEqual(rec["intent"]["meta"]["status"], "not_requested")

    def test_lifecycle_record_distinct_from_request(self):
        cfg = make_cfg()
        self.c.frames[11] = [_frame(8, 1000, 1102)]
        rec = extract(framework, self.s,
                      exit_event(self.rids["nav.lifecycle.oncreate"],
                                 cls=1000, method=1102), cfg)
        self.assertEqual(rec["role"], "lifecycle")
        self.assertNotIn("intent", rec)
        req = extract(framework, self.s,
                      exit_event(self.rids["nav.activity.start"]), cfg)
        self.assertEqual(req["role"], "request")
        self.assertNotEqual(rec["role"], req["role"])

    def test_duplicate_call_correlation(self):
        """One call traversing Activity -> ContextWrapper -> ContextImpl:
        three events, one correlation id."""
        cfg = make_cfg()
        recs = []
        for prof, cls, mid in (("nav.activity.start", 1000, 1100),
                               ("nav.contextwrapper.start", 2000, 2100),
                               ("nav.contextimpl.start", 3000, 3100)):
            self.c.frames[11] = [_frame(5, cls, mid)]
            recs.append(extract(framework, self.s,
                                exit_event(self.rids[prof], cls=cls,
                                           method=mid), cfg))
        corrs = {r["corr"] for r in recs}
        self.assertEqual(len(corrs), 1)
        groups = framework._correlation_summary(recs)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["records"], 3)
        self.assertEqual(groups[0]["profiles"],
                         ["nav.activity.start", "nav.contextwrapper.start",
                          "nav.contextimpl.start"])

    def test_individual_capture_failure_preserved_in_group(self):
        cfg = make_cfg()
        good = extract(framework, self.s,
                       exit_event(self.rids["nav.activity.start"]), cfg)
        # sibling event on the same call whose intent arg read fails
        self.c.frames[11] = [_frame(9, 2000, 2100)]
        self.c.slot_values[(9, 1)] = None
        bad = extract(framework, self.s,
                      exit_event(self.rids["nav.contextwrapper.start"],
                                 cls=2000, method=2100), cfg)
        self.assertIn("intent", bad["capture_errors"])
        self.assertNotIn("corr", bad)  # no identity -> not correlatable
        self.assertEqual(cfg["_stats"]["unavailable"], 1)
        self.assertEqual(good["status"], "ok")  # sibling unaffected

    def test_no_correlation_when_window_disabled(self):
        cfg = make_cfg(corr_window_ms=0)
        rec = extract(framework, self.s,
                      exit_event(self.rids["nav.activity.start"]), cfg)
        self.assertNotIn("corr", rec)


class InvokeGetterTests(unittest.TestCase):
    def setUp(self):
        self.c = nav_client()
        self.s = make_session(self.c)
        rep = framework.install(
            self.s, [framework.resolve_profile("nav.activity.start")])
        self.rid = rep["installed"][0]["request_ids"][0]
        self.c.obj_types[7001] = 6000
        self.c.frames[11] = [_frame(5, 1000, 1100)]
        self.c.slot_values[(5, 1)] = 7001
        # Intent.getAction / getFlags
        self.c.methods[6000] = [
            {"name": "getAction", "sig": "()Ljava/lang/String;", "id": 601,
             "mod_bits": 1},
            {"name": "getFlags", "sig": "()I", "id": 602, "mod_bits": 1},
        ]
        self.c.invoke_results[(6000, 601)] = {
            "value": {"tag": TAG_STRING, "v": 8005}, "exception": None}
        self.c.invoke_results[(6000, 602)] = {
            "value": {"tag": 73, "v": 32}, "exception": None}
        self.c.strings[8005] = "com.apkdbg.FW_NAV"

    def test_invoke_getters_explicit_option(self):
        cfg = make_cfg(invoke_getters=True)
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        meta = rec["intent"]["meta"]
        self.assertEqual(meta["action"], "com.apkdbg.FW_NAV")
        self.assertEqual(meta["flags"], {"type": "int", "v": 32})
        # resolved through the declaring class (validated #22 path)
        self.assertIn((7001, 6000, 601), self.c.invocations)

    def test_getter_failure_is_error_node_not_crash(self):
        self.c.invoke_throws.add((6000, 601))
        cfg = make_cfg(invoke_getters=True)
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        self.assertIn("error", rec["intent"]["meta"]["action"])
        self.assertEqual(rec["intent"]["meta"]["flags"],
                         {"type": "int", "v": 32})  # siblings unaffected

    def test_reentrancy_policy_blocks_armed_declaring_class(self):
        # an armed class-scoped exit request on Intent (type 6000): the
        # getter's own exit would suspend the thread mid-invoke
        c = self.c
        rid = c.set_event(EVK_METHOD_EXIT_RET, SP_EVENT_THREAD,
                          [c.mod_class_only(6000)])
        self.s.events.register(rid, {"owner": "strings", "kind":
                                     EVK_METHOD_EXIT_RET, "type_id": 6000})
        cfg = make_cfg(invoke_getters=True)
        node = framework._run_getter(
            self.s, 11, 7001, {"method": "getAction",
                               "sig": "()Ljava/lang/String;",
                               "label": "action"}, cfg,
            cfg["_stats"])
        self.assertIn("reentrancy", node["error"])
        self.assertEqual(self.c.invocations, [])  # never invoked


class ServiceExtractTests(unittest.TestCase):
    def setUp(self):
        self.c = svc_client()
        self.s = make_session(self.c)
        rep = framework.install(
            self.s, framework.resolve_profiles(["services"]))
        self.rids = {i["profile"]: i["request_ids"][0]
                     for i in rep["installed"]}
        self.c.frames[11] = [_frame(5, 3000, 5105)]
        self.c.slot_values[(5, 1)] = 8001
        self.c.strings[8001] = "activity"
        self.c.obj_types[9500] = 6001

    def test_lookup_is_capability_request_with_result_class(self):
        cfg = make_cfg()
        rec = extract(framework, self.s,
                      exit_event(self.rids["svc.name"], cls=3000,
                                 method=5105,
                                 ret={"tag": TAG_OBJECT, "v": 9500}), cfg)
        self.assertEqual(rec["role"], "lookup")
        self.assertEqual(rec["service"], {"name": "activity"})
        self.assertEqual(rec["return"]["cls"],
                         "Landroid/app/ActivityManager;")
        self.assertEqual(rec["lookup_count"], 1)

    def test_repeated_lookups_counted(self):
        cfg = make_cfg()
        for _ in range(3):
            extract(framework, self.s,
                    exit_event(self.rids["svc.name"], cls=3000,
                               method=5105, ret={"tag": TAG_OBJECT,
                                                 "v": 9500}), cfg)
        summary = framework._lookup_summary(cfg)
        self.assertEqual(summary, [{"kind": "name",
                                    "service": "activity", "lookups": 3}])

    def test_class_lookup_name_via_invoke_option(self):
        self.c.frames[11] = [_frame(5, 3000, 5106)]
        self.c.slot_values[(5, 1)] = 7002
        self.c.obj_types[7002] = 6500
        self.c.sigs[6500] = "Ljava/lang/Class;"
        self.c.methods[6500] = [{"name": "getName",
                                 "sig": "()Ljava/lang/String;", "id": 651,
                                 "mod_bits": 1}]
        self.c.invoke_results[(6500, 651)] = {
            "value": {"tag": TAG_STRING, "v": 8009}, "exception": None}
        self.c.strings[8009] = "android.app.AlarmManager"
        # default: bounded object node, no invocation
        cfg = make_cfg()
        rec = extract(framework, self.s,
                      exit_event(self.rids["svc.class"], cls=3000,
                                 method=5106), cfg)
        self.assertEqual(rec["service"]["class_id"], 7002)
        self.assertEqual(rec["service"]["class_name"]["status"],
                         "not_requested")
        self.assertEqual(self.c.invocations, [])
        # explicit opt-in resolves the class name
        cfg = make_cfg(invoke_getters=True)
        rec = extract(framework, self.s,
                      exit_event(self.rids["svc.class"], cls=3000,
                                 method=5106), cfg)
        self.assertEqual(rec["service"]["class_name"],
                         "android.app.AlarmManager")


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.c = nav_client()
        self.s = make_session(self.c)
        rep = framework.install(
            self.s, [framework.resolve_profile("nav.activity.start")])
        self.rid = rep["installed"][0]["request_ids"][0]
        self.c.obj_types[7001] = 6000
        self.c.slot_values[(5, 1)] = 7001
        self.c.sigs[7000] = "Lcom/apkdbg/FixtureActivity;"
        self.c.sigs[7002] = "Landroid/app/Instrumentation;"
        self.c.methods[7000] = [{"name": "navPaths", "sig": "()V",
                                 "id": 71}]
        self.c.frames[11] = [
            _frame(5, 1000, 1100),            # hooked method
            _frame(6, 7002, 9, index=40),     # framework wrapper
            _frame(7, 7000, 71, index=121),   # app frame
        ]

    def test_nearest_in_scope_app_frame_not_frame1(self):
        cfg = make_cfg(scope="com.apkdbg.*")
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        att = rec["attribution"]
        self.assertEqual(att["status"], "matched")
        self.assertEqual(att["caller"]["class_sig"],
                         "Lcom/apkdbg/FixtureActivity;")
        self.assertEqual(att["caller"]["method"], "navPaths")
        self.assertEqual(att["caller"]["index"], 121)

    def test_exclude_never_reports_framework_wrapper(self):
        # scope broad enough to match the wrapper; the exclude rule wins
        cfg = make_cfg(scope="com.*", exclude=["com.android.*",
                                               "android.*"])
        self.c.sigs[7002] = "Lcom/android/internal/Wrapper;"
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        att = rec["attribution"]
        self.assertEqual(att["status"], "matched")
        self.assertEqual(att["caller"]["class_sig"],
                         "Lcom/apkdbg/FixtureActivity;")

    def test_only_framework_frames_is_no_app_frame(self):
        cfg = make_cfg(scope="com.apkdbg.*")
        self.c.frames[11] = [_frame(5, 1000, 1100),
                             _frame(6, 7002, 9, index=40)]
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        self.assertEqual(rec["attribution"]["status"], "no_app_frame")
        self.assertNotIn("caller", rec["attribution"])

    def test_no_scope_and_best_effort_explicit(self):
        cfg = make_cfg()
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        self.assertEqual(rec["attribution"]["status"],
                         "no_scope_configured")
        cfg = make_cfg(mode="best_effort")
        rec = extract(framework, self.s, exit_event(self.rid), cfg)
        self.assertEqual(rec["attribution"]["status"], "not_captured")


def extract(mod, session, ev, cfg):
    return mod.extract_event(session, ev, cfg)


# ------------------------------------------------------------------ run_watch
class RunWatchTests(unittest.TestCase):
    def _queued_watch(self, c, events, **kw):
        orig_install = framework.install

        def install_then_queue(session, profiles, **ikw):
            r = orig_install(session, profiles, **ikw)
            rids = {i["profile"]: i["request_ids"][0]
                    for i in r["installed"]}
            for evs, sp in events:
                c.event_queue.append(composite(
                    *[e(rids) for e in evs], sp=sp))
            return r
        return patch.object(framework, "install", install_then_queue)

    def _store_setup(self):
        c = store_client()
        c.frames[11] = [_frame(5, 4001, 4100)]
        c.this_objects[5] = 9001
        c.slot_values[(5, 1)] = 8001
        c.slot_values[(5, 2)] = 8002
        c.strings[8001] = "k"
        c.strings[8002] = "v"
        return c

    def test_full_watch_records_and_cleanup(self):
        c = self._store_setup()
        s = make_session(c)
        events = [
            ([lambda r: exit_event(r["store.putstring"], cls=4001,
                                   method=4100,
                                   ret={"tag": TAG_OBJECT, "v": 9001}),
              lambda r: {"kind": "breakpoint", "kind_id": 2,
                         "request_id": 999, "thread": 22,
                         "location": {"class": 7000, "method": 1,
                                      "index": 0}}], SP_EVENT_THREAD),
        ]
        with self._queued_watch(c, events):
            out = framework.run_watch(s, families=["storage"],
                                      duration_s=5)
        self.assertEqual(out["counts"]["matched"], 1)
        self.assertEqual(out["counts"]["unrelated"], 1)
        self.assertEqual(c.resumed, [11])  # unrelated stop never resumed
        stashed = s.wait_events(timeout=1)
        self.assertEqual([e["request_id"] for e in stashed["events"]],
                         [999])
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(len(out["transactions"]), 1)
        self.assertTrue(out["transactions"][0]["discarded"])
        self.assertIn("storage", out["coverage_notes"])
        cleared = set(c.cleared)
        self.assertEqual({k for k, _ in cleared},
                         {EVK_METHOD_EXIT_RET})
        self.assertEqual(s.bp_registry, {})

    def test_max_events_and_max_reads_budgets(self):
        c = self._store_setup()
        c.strings.update({8003: "k2", 8004: "v2"})
        s = make_session(c)

        def put(r, key_oid=8001, val_oid=8002):
            return exit_event(r["store.putstring"], cls=4001, method=4100,
                              ret={"tag": TAG_OBJECT, "v": 9001})
        events = [([lambda r: put(r), lambda r: put(r), lambda r: put(r)],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = framework.run_watch(s, families=["storage"],
                                      duration_s=30, max_events=2)
        self.assertEqual(out["reason"], "max_events")
        self.assertEqual(out["counts"]["matched"], 2)

        c = self._store_setup()
        s = make_session(c)
        events = [([lambda r: put(r), lambda r: put(r), lambda r: put(r)],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = framework.run_watch(s, families=["storage"],
                                      duration_s=30, max_reads=3)
        self.assertEqual(out["reason"], "max_reads")
        self.assertGreaterEqual(out["counts"]["dropped"], 1)

    def test_cancellation_and_output_budget(self):
        c = self._store_setup()
        cancel = threading.Event()
        cancel.set()
        s = make_session(c)
        out = framework.run_watch(s, families=["storage"], duration_s=30,
                                  cancel=cancel)
        self.assertEqual(out["reason"], "cancelled")
        self.assertEqual({k for k, _ in c.cleared},
                         {EVK_METHOD_EXIT_RET})

        c = self._store_setup()
        s = make_session(c)
        events = [([lambda r: exit_event(r["store.putstring"], cls=4001,
                                        method=4100,
                                        ret={"tag": TAG_OBJECT,
                                             "v": 9001})],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = framework.run_watch(s, families=["storage"],
                                      duration_s=30, max_output_bytes=1)
        self.assertEqual(out["reason"], "max_output_bytes")
        self.assertTrue(out["truncated"])

    def test_disconnect_reports_unconfirmed_no_clears(self):
        c = self._store_setup()
        s = make_session(c)
        s.events.bump_epoch()
        rep = framework.install(s, framework.resolve_profiles(["storage"]))
        rid = rep["installed"][0]["request_ids"][0]

        def disconnecting(timeout=None):
            s.events.bump_epoch()  # reconnect mid-watch
            raise _timeout_error()
        c.next_event = disconnecting
        out = framework.run_watch(s, families=["storage"], duration_s=5)
        self.assertIn(rid, out["unconfirmed"])
        self.assertEqual(c.cleared, [])  # dead-epoch ids never cleared

    def test_capture_exception_non_fatal(self):
        c = self._store_setup()
        s = make_session(c)

        def boom(thread, count=32):
            raise RuntimeError("unexpected capture crash")
        c.thread_frames = boom
        events = [([lambda r: exit_event(r["store.putstring"], cls=4001,
                                        method=4100,
                                        ret={"tag": TAG_OBJECT,
                                             "v": 9001})],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = framework.run_watch(s, families=["storage"],
                                      duration_s=5)
        self.assertEqual(c.resumed, [11])
        self.assertEqual(out["cleanup_errors"], [])
        self.assertEqual(out["records"][0]["attribution"]["status"],
                         "unavailable")


# ---------------------------------------------------------------- persistence
class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = Project.create(self.tmp.name)
        with self.proj.db() as db:
            db.set_meta("sha256", "ab" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def _run_recorded_watch(self):
        c = store_client()
        c.frames[11] = [_frame(5, 4001, 4100)]
        c.this_objects[5] = 9001
        c.slot_values[(5, 1)] = 8001
        c.slot_values[(5, 2)] = 8002
        c.strings[8001] = "k"
        c.strings[8002] = "v"
        s = make_session(c, project=self.proj)
        orig_install = framework.install

        def install_then_queue(session, profiles, **ikw):
            r = orig_install(session, profiles, **ikw)
            rids = {i["profile"]: i["request_ids"][0]
                    for i in r["installed"]}
            c.event_queue.append(composite(exit_event(
                rids["store.putstring"], cls=4001, method=4100,
                ret={"tag": TAG_OBJECT, "v": 9001})))
            c.event_queue.append(composite(exit_event(
                rids["store.commit"], cls=4001, method=4105,
                ret={"tag": 90, "v": 0})))
            return r
        with patch.object(framework, "install", install_then_queue):
            return framework.run_watch(s, families=["storage"],
                                       duration_s=5, record=True,
                                       scope="com.foo.*", scenario="t27")

    def test_run_manifest_and_event_rows(self):
        out = self._run_recorded_watch()
        self.assertIsNotNone(out["run_id"])
        got = RunStore(self.proj).get_run(out["run_id"])
        run = got["run"]
        self.assertEqual(run["kind"], "framework_watch")
        self.assertEqual(run["scenario"], "t27")
        cfg = run["capture_config"]
        self.assertEqual(cfg["mode"], "attributed")
        self.assertEqual(cfg["scope"], "com.foo.*")
        self.assertIn("max_events", cfg["limits"])
        self.assertFalse(cfg["invoke_getters"])
        fams = {p["family"] for p in cfg["profiles"]}
        self.assertEqual(fams, {"storage"})
        self.assertEqual(run["counts"]["matched"], 2)
        self.assertEqual(len(got["events"]), 2)
        ev = got["events"][0]
        self.assertEqual(ev["kind"], "framework_event")
        self.assertEqual(ev["class_sig"], EDIMPL)
        self.assertEqual(ev["method_name"], "putString")
        self.assertEqual(ev["payload"]["family"], "storage")
        self.assertEqual(ev["payload"]["role"], "staged")
        self.assertIn("attribution", ev["payload"])
        commit_ev = got["events"][1]
        self.assertEqual(commit_ev["payload"]["role"], "submit")
        self.assertIs(commit_ev["payload"]["result"], False)

    def test_offline_query_pagination_and_filters(self):
        out = self._run_recorded_watch()
        q = framework.query_events(self.proj, limit=1, offset=0)
        self.assertEqual(q["total"], 2)
        self.assertEqual(q["count"], 1)
        self.assertTrue(q["truncated"])
        q2 = framework.query_events(self.proj, limit=1, offset=1)
        self.assertFalse(q2["truncated"])
        self.assertNotEqual(q["records"][0]["event_id"],
                            q2["records"][0]["event_id"])
        self.assertEqual(framework.query_events(
            self.proj, run_id=out["run_id"])["total"], 2)
        self.assertEqual(framework.query_events(
            self.proj, run_id="nope")["total"], 0)
        self.assertEqual(framework.query_events(
            self.proj, family="storage")["total"], 2)
        self.assertEqual(framework.query_events(
            self.proj, family="navigation")["total"], 0)
        self.assertEqual(framework.query_events(
            self.proj, profile="store.commit")["total"], 1)
        self.assertEqual(framework.query_events(
            self.proj, role="staged")["total"], 1)
        self.assertEqual(framework.query_events(
            self.proj, role="submit")["total"], 1)


if __name__ == "__main__":
    unittest.main()

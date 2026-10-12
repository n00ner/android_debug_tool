"""Offline regression tests for issue #26 — scoped string watchers.
Duck-typed FakeJdwpClient drives a real DebugSession (no device)."""

from __future__ import annotations

import tempfile
import threading
import unittest

from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug.hooks import strings
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_CLASS_PREPARE, EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, SP_NONE,
    TAG_STRING, JdwpError,
)
from apkdbg.errors import SessionError

DEC_CLS = "Lcom/foo/Dec;"
DEC_PROF = {"cls": DEC_CLS, "method": "decrypt",
            "sig": "([B)Ljava/lang/String;", "name": "custom:decrypt"}
SB_PROF = "stringbuilder.tostring"
SB_CLS = "Ljava/lang/StringBuilder;"
LOG_CLS = "Landroid/util/Log;"
PREFS_IFACE = "Landroid/content/SharedPreferences$Editor;"
PREFS_IMPL = "Landroid/app/SharedPreferencesImpl$Editor;"


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
        self.frames = {}         # thread -> [frame dicts]
        self.slot_values = {}    # (frame_id, slot) -> value
        self.strings = {}        # oid -> str
        self.dead_strings = set()  # oids whose string_value read fails
        self.event_queue = []
        self.cleared = []        # (kind, request_id)
        self.resumed = []
        self.set_calls = []      # (kind, sp, mods)
        self.fail_set_event = False

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

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_event(self, kind, suspend, mods):
        if self.fail_set_event:
            raise JdwpError("set_event failed")
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

    def string_value(self, oid, max_len=4096):
        if oid in self.dead_strings:
            raise JdwpError("INVALID_OBJECT")
        return self.strings.get(oid, "")[:max_len]


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def dec_client() -> FakeJdwpClient:
    """Fake VM with the custom decryptor class loaded (method id 1500)."""
    c = FakeJdwpClient()
    c.classes[DEC_CLS] = [{"type_id": 1000}]
    c.sigs[1000] = DEC_CLS
    c.methods[1000] = [
        {"name": "decrypt", "sig": "([B)Ljava/lang/String;", "id": 1500,
         "mod_bits": 0x0009},
        {"name": "decrypt", "sig": "(I)Ljava/lang/String;", "id": 1501,
         "mod_bits": 0x0009},
        {"name": "other", "sig": "()V", "id": 1502, "mod_bits": 0x0009},
    ]
    return c


def exit_event(rid, thread=11, cls=1000, method=1500, ret=None, sp=None):
    ev = {"kind": "method_exit_return", "kind_id": EVK_METHOD_EXIT_RET,
          "request_id": rid, "thread": thread,
          "location": {"class": cls, "method": method, "index": 3},
          "return_value": ret if ret is not None else {"tag": 86, "v": None}}
    return ev


def composite(*events, sp=SP_EVENT_THREAD):
    return {"suspend_policy": sp, "events": list(events)}


def str_ret(oid):
    return {"tag": TAG_STRING, "v": oid}


def make_cfg(**over):
    cfg = {"mode": "attributed", "scope": None, "max_stack": 8,
           "max_str": 512, "min_printable": 0.0, "dedupe": True,
           "capture_stack": False, "_stats": strings._new_stats(),
           "_seen": set(), "_stop": None, "_text_re": None}
    cfg.update(over)
    return cfg


# ------------------------------------------------------------------- profiles
class ProfileTests(unittest.TestCase):
    def test_builtin_by_name(self):
        p = strings.resolve_profile(SB_PROF)
        self.assertEqual(p["kind"], "return")
        self.assertEqual(p["sig"], "()Ljava/lang/String;")
        self.assertIn("does NOT capture every constructed string",
                      p["note"])

    def test_unknown_builtin_rejected(self):
        with self.assertRaises(SessionError):
            strings.resolve_profile("log.x")

    def test_custom_producer_guessed_from_return_sig(self):
        p = strings.resolve_profile(DEC_PROF)
        self.assertEqual(p["kind"], "return")
        self.assertEqual(p["name"], "custom:decrypt")

    def test_custom_consumer_and_validation(self):
        p = strings.resolve_profile(
            {"cls": LOG_CLS, "method": "i",
             "sig": "(Ljava/lang/String;Ljava/lang/String;)I",
             "kind": "args"})
        self.assertEqual(p["kind"], "args")
        with self.assertRaises(SessionError):  # no String argument
            strings.resolve_profile({"cls": "LX;", "method": "m",
                                     "sig": "(II)V", "kind": "args"})
        with self.assertRaises(SessionError):  # missing pieces
            strings.resolve_profile({"cls": "LX;"})
        with self.assertRaises(SessionError):  # bad kind
            strings.resolve_profile({**DEC_PROF, "kind": "weird"})

    def test_parse_sig(self):
        args, ret = strings.parse_sig("([BLjava/lang/String;I)V")
        self.assertEqual(args, ["[B", "Ljava/lang/String;", "I"])
        self.assertEqual(ret, "V")
        args, ret = strings.parse_sig("()Ljava/lang/String;")
        self.assertEqual(args, [])
        self.assertEqual(ret, "Ljava/lang/String;")


# -------------------------------------------------------------------- install
class InstallTests(unittest.TestCase):
    def test_request_shape_both_modes(self):
        for mode, sp in (("attributed", SP_EVENT_THREAD),
                         ("best_effort", SP_NONE)):
            c = dec_client()
            s = make_session(c)
            rep = strings.install(s, [strings.resolve_profile(DEC_PROF)],
                                  mode=mode, thread=11, mod_count=3)
            self.assertEqual(rep["states"], {"custom:decrypt": "installed"})
            kind, got_sp, mods = c.set_calls[-1]
            self.assertEqual(kind, EVK_METHOD_EXIT_RET)
            self.assertEqual(got_sp, sp)
            # class filter at request level; thread + MOD_COUNT pass-through
            self.assertIn(("class_only", 1000), mods)
            self.assertIn(("thread_only", 11), mods)
            self.assertIn(("count", 3), mods)
            rid = rep["installed"][0]["request_ids"][0]
            reg = s.bp_registry[rid]
            self.assertEqual(reg["owner"], "strings")
            self.assertEqual(reg["kind"], EVK_METHOD_EXIT_RET)
            self.assertEqual(reg["method_id"], 1500)  # exact overload
            self.assertEqual(reg["sig"], "([B)Ljava/lang/String;")

    def test_pending_not_found_unsupported(self):
        s = make_session(FakeJdwpClient())  # nothing loaded
        rep = strings.install(s, [strings.resolve_profile(DEC_PROF)])
        self.assertEqual(rep["states"], {"custom:decrypt": "pending"})

        c = dec_client()
        c.methods[1000] = [{"name": "decrypt", "sig": "(I)Ljava/lang/String;",
                            "id": 1501, "mod_bits": 0x9}]  # wrong overload
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile(DEC_PROF)])
        self.assertEqual(rep["states"], {"custom:decrypt": "not-found"})

        c = dec_client()
        c.methods[1000][0]["mod_bits"] = 0x0109  # native
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile(DEC_PROF)])
        self.assertEqual(rep["states"], {"custom:decrypt": "unsupported"})

    def test_unknown_mode_rejected(self):
        s = make_session(dec_client())
        with self.assertRaises(SessionError):
            strings.install(s, [SB_PROF and strings.resolve_profile(SB_PROF)],
                            mode="everything")

    def test_interface_skipped_impl_hooked(self):
        c = FakeJdwpClient()
        c.classes[PREFS_IFACE] = [{"type_id": 2000}]
        c.classes[PREFS_IMPL] = [{"type_id": 2001}]
        c.sigs[2000], c.sigs[2001] = PREFS_IFACE, PREFS_IMPL
        sig = ("(Ljava/lang/String;Ljava/lang/String;)"
               "Landroid/content/SharedPreferences$Editor;")
        c.methods[2000] = [{"name": "putString", "sig": sig, "id": 2500,
                            "mod_bits": 0x0401}]  # abstract interface method
        c.methods[2001] = [{"name": "putString", "sig": sig, "id": 2600,
                            "mod_bits": 0x0001}]
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile("prefs.putstring")])
        self.assertEqual(rep["states"], {"prefs.putstring": "installed"})
        rids = rep["installed"][0]["request_ids"]
        self.assertEqual(len(rids), 1)  # only the concrete impl class
        self.assertEqual(s.bp_registry[rids[0]]["type_id"], 2001)

    def test_interface_only_is_unsupported(self):
        c = FakeJdwpClient()
        c.classes[PREFS_IFACE] = [{"type_id": 2000}]
        c.sigs[2000] = PREFS_IFACE
        c.methods[2000] = [{"name": "putString",
                            "sig": "(Ljava/lang/String;Ljava/lang/String;)"
                                   "Landroid/content/SharedPreferences$Editor;",
                            "id": 2500, "mod_bits": 0x0401}]
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile("prefs.putstring")])
        self.assertEqual(rep["states"], {"prefs.putstring": "unsupported"})

    def test_partial_install_rolls_back(self):
        c = dec_client()
        c.classes[DEC_CLS].append({"type_id": 1001})
        c.sigs[1001] = DEC_CLS
        c.methods[1001] = c.methods[1000]

        orig = c.set_event
        calls = {"n": 0}

        def flaky(kind, sp, mods):
            calls["n"] += 1
            if calls["n"] > 1:
                raise JdwpError("boom")
            return orig(kind, sp, mods)
        c.set_event = flaky
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile(DEC_PROF)])
        self.assertEqual(rep["states"], {"custom:decrypt": "failed"})
        self.assertEqual(c.cleared, [(EVK_METHOD_EXIT_RET, 1)])
        self.assertEqual(s.bp_registry, {})


class DeferTests(unittest.TestCase):
    def test_late_class_loading_via_defer(self):
        c = FakeJdwpClient()  # decryptor class not loaded at install time
        s = make_session(c)
        loaded = {"yes": False}

        def cbs(sig):
            if sig == DEC_CLS and loaded["yes"]:
                return [{"type_id": 1000}]
            return []
        c.classes_by_signature = cbs
        orig_next = c.next_event

        def next_then_load(timeout=None):
            comp = orig_next(timeout)
            loaded["yes"] = True  # the CLASS_PREPARE composite "loaded" it
            return comp
        c.next_event = next_then_load
        c.sigs[1000] = DEC_CLS
        c.methods[1000] = [{"name": "decrypt", "sig": "([B)Ljava/lang/String;",
                            "id": 1500, "mod_bits": 0x9}]
        c.strings[8001] = "https://late.example/dec"
        # rid 1 = CLASS_PREPARE watch (allocated by defer); rid 2 = the
        # auto-installed exit request
        c.event_queue.append(
            composite({"kind": "class_prepare", "kind_id": EVK_CLASS_PREPARE,
                       "request_id": 1, "thread": 11, "type_id": 1000,
                       "signature": DEC_CLS, "status": 0}))
        c.event_queue.append(composite(exit_event(2, ret=str_ret(8001))))

        res = strings.run_watch(s, profiles=[DEC_PROF], duration_s=5,
                                defer=True)
        self.assertEqual(res["states"], {"custom:decrypt": "pending"})
        self.assertEqual(res["deferred"][0]["request_id"], 1)
        self.assertEqual(res["auto_installed"], [2])
        self.assertEqual(res["records"][0]["texts"],
                         ["https://late.example/dec"])
        # deferred watch + auto-installed request both cleared with their
        # actual kinds
        self.assertEqual(set(c.cleared), {(EVK_CLASS_PREPARE, 1),
                                          (EVK_METHOD_EXIT_RET, 2)})
        self.assertEqual(s.bp_registry, {})


# -------------------------------------------------------------------- extract
class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.c = dec_client()
        self.s = make_session(self.c)
        rep = strings.install(self.s, [strings.resolve_profile(DEC_PROF)])
        self.rid = rep["installed"][0]["request_ids"][0]

    def test_host_side_method_filter(self):
        cfg = make_cfg()
        other = exit_event(self.rid, method=1502)  # other(): same class
        self.assertIsNone(strings.extract_event(self.s, other, cfg))
        self.assertEqual(cfg["_stats"]["received"], 1)
        self.assertEqual(cfg["_stats"]["filtered"], 1)

    def test_return_value_decoding(self):
        self.c.strings[8001] = "https://dec.example/api"
        cfg = make_cfg()
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["texts"], ["https://dec.example/api"])
        self.assertEqual(rec["profile"], "custom:decrypt")
        self.assertEqual(cfg["_stats"]["matched"], 1)

    def test_non_string_return_counted(self):
        cfg = make_cfg()
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret={"tag": 91, "v": 1}), cfg)
        self.assertEqual(rec["status"], "non_string_return")
        self.assertEqual(cfg["_stats"]["non_string"], 1)

    def test_best_effort_object_loss_counted_not_fatal(self):
        self.c.strings[8001] = "lost"
        self.c.dead_strings.add(8001)
        cfg = make_cfg(mode="best_effort")
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["status"], "unavailable")
        self.assertIn("unavailable_reason", rec)
        self.assertEqual(cfg["_stats"]["unavailable"], 1)
        self.assertEqual(rec["attribution"]["status"], "not_captured")

    def test_attributed_nearest_app_frame(self):
        self.c.strings[8001] = "https://dec.example/api"
        self.c.sigs[3000] = "Lcom/foo/MainActivity;"
        self.c.sigs[3001] = "Landroid/os/Handler;"
        self.c.methods[3000] = [{"name": "onCreate",
                                 "sig": "(Landroid/os/Bundle;)V", "id": 42}]
        self.c.frames[11] = [
            {"frame_id": 1, "location": {"class": 1000, "method": 1500,
                                         "index": 3}},   # hooked method
            {"frame_id": 2, "location": {"class": 3001, "method": 7,
                                         "index": 9}},   # framework
            {"frame_id": 3, "location": {"class": 3000, "method": 42,
                                         "index": 121}},  # app frame
        ]
        cfg = make_cfg(scope="com.foo.*")
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        att = rec["attribution"]
        self.assertEqual(att["status"], "matched")
        self.assertEqual(att["caller"]["class_sig"], "Lcom/foo/MainActivity;")
        self.assertEqual(att["caller"]["method"], "onCreate")
        self.assertEqual(att["caller"]["method_sig"], "(Landroid/os/Bundle;)V")
        self.assertEqual(att["caller"]["index"], 121)

    def test_attributed_no_app_frame_is_explicit(self):
        self.c.strings[8001] = "x"
        self.c.frames[11] = [
            {"frame_id": 1, "location": {"class": 1000, "method": 1500,
                                         "index": 3}},
            {"frame_id": 2, "location": {"class": 3001, "method": 7,
                                         "index": 9}},
        ]
        cfg = make_cfg(scope="com.foo.*")
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["attribution"]["status"], "no_app_frame")
        self.assertNotIn("caller", rec["attribution"])

    def test_attributed_no_scope_is_explicit(self):
        self.c.strings[8001] = "x"
        cfg = make_cfg()  # no scope
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["attribution"]["status"], "no_scope_configured")

    def test_text_filters_and_dedupe(self):
        self.c.strings[8001] = "keep-me"
        self.c.strings[8002] = "drop-me"
        self.c.strings[8003] = "binary\x01\x02\x03"
        import re
        cfg = make_cfg(_text_re=re.compile("^keep"), min_printable=0.9)
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["texts"], ["keep-me"])
        # regex filter
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8002)), cfg)
        self.assertIsNone(rec)
        # printable-ratio filter
        cfg2 = make_cfg(min_printable=0.9)
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8003)), cfg2)
        self.assertIsNone(rec)
        self.assertEqual(cfg2["_stats"]["filtered"], 1)
        # value-based dedupe: same text again -> deduped, no record
        self.c.strings[8004] = "keep-me"
        cfg3 = make_cfg()
        self.assertIsNotNone(strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg3))
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8004)), cfg3)
        self.assertIsNone(rec)
        self.assertEqual(cfg3["_stats"]["deduped"], 1)

    def test_long_text_truncated_and_counted(self):
        self.c.strings[8001] = "A" * 100
        cfg = make_cfg(max_str=10)
        rec = strings.extract_event(
            self.s, exit_event(self.rid, ret=str_ret(8001)), cfg)
        self.assertEqual(rec["texts"], ["A" * 10])
        self.assertTrue(rec["truncated"])
        self.assertEqual(cfg["_stats"]["truncated"], 1)


class ArgProfileTests(unittest.TestCase):
    """Consumer profiles read String arguments at frame 0 (attributed)."""

    def _install_log(self):
        c = FakeJdwpClient()
        c.classes[LOG_CLS] = [{"type_id": 4000}]
        c.sigs[4000] = LOG_CLS
        c.methods[4000] = [
            {"name": "i", "sig": "(Ljava/lang/String;Ljava/lang/String;)I",
             "id": 4500, "mod_bits": 0x0009}]  # public static
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile("log.i")])
        return c, s, rep["installed"][0]["request_ids"][0]

    def test_static_args_at_slots_0_and_1(self):
        c, s, rid = self._install_log()
        self.assertEqual(s.bp_registry[rid]["capture_spec"],
                         [{"slot": 0, "type": "string", "label": "arg0"},
                          {"slot": 1, "type": "string", "label": "arg1"}])
        c.frames[11] = [{"frame_id": 5,
                         "location": {"class": 4000, "method": 4500,
                                      "index": 0}}]
        c.slot_values[(5, 0)] = 8001
        c.slot_values[(5, 1)] = 8002
        c.strings[8001], c.strings[8002] = "MyTag", "hello world"
        cfg = make_cfg()
        rec = strings.extract_event(
            s, exit_event(rid, cls=4000, method=4500,
                          ret={"tag": 73, "v": 1}), cfg)
        self.assertEqual(rec["texts"], ["MyTag", "hello world"])
        self.assertEqual(rec["kind"], "args")

    def test_args_unavailable_in_best_effort(self):
        c, s, rid = self._install_log()
        cfg = make_cfg(mode="best_effort")
        rec = strings.extract_event(
            s, exit_event(rid, cls=4000, method=4500,
                          ret={"tag": 73, "v": 1}), cfg)
        self.assertEqual(rec["status"], "unavailable")
        self.assertIn("attributed mode", rec["unavailable_reason"])
        self.assertEqual(cfg["_stats"]["unavailable"], 1)

    def test_instance_method_args_skip_this_slot(self):
        c = FakeJdwpClient()
        c.classes["Ljava/net/URL;"] = [{"type_id": 5000}]
        c.sigs[5000] = "Ljava/net/URL;"
        c.methods[5000] = [{"name": "<init>",
                            "sig": "(Ljava/lang/String;)V", "id": 5500,
                            "mod_bits": 0x0001}]  # instance
        s = make_session(c)
        rep = strings.install(s, [strings.resolve_profile("url.init")])
        rid = rep["installed"][0]["request_ids"][0]
        self.assertEqual(s.bp_registry[rid]["capture_spec"],
                         [{"slot": 1, "type": "string", "label": "arg0"}])


# ------------------------------------------------------------------ run_watch
class RunWatchTests(unittest.TestCase):
    def _queued_watch(self, c, events, **kw):
        """install first (rids allocated), then queue composites."""
        orig_install = strings.install

        def install_then_queue(session, profiles, **ikw):
            r = orig_install(session, profiles, **ikw)
            rid = r["installed"][0]["request_ids"][0]
            for evs, sp in events:
                c.event_queue.append(composite(
                    *[e(rid) for e in evs], sp=sp))
            return r
        from unittest.mock import patch
        return patch.object(strings, "install", install_then_queue)

    def test_owned_resumed_once_unrelated_stashed(self):
        c = dec_client()
        c.strings[8001] = "https://dec.example/a"
        s = make_session(c)
        events = [
            ([lambda rid: exit_event(rid, ret=str_ret(8001)),
              lambda rid: {"kind": "breakpoint", "kind_id": 2,
                           "request_id": 999, "thread": 22,
                           "location": {"class": 7000, "method": 1,
                                        "index": 0}}], SP_EVENT_THREAD),
        ]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=5)
        self.assertEqual(out["counts"]["matched"], 1)
        self.assertEqual(out["counts"]["unrelated"], 1)
        self.assertEqual(c.resumed, [11])  # unrelated stop never resumed
        stashed = s.wait_events(timeout=1)
        self.assertEqual([e["request_id"] for e in stashed["events"]], [999])
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(set(c.cleared), {(EVK_METHOD_EXIT_RET, 1)})

    def test_best_effort_no_resume(self):
        c = dec_client()
        c.strings[8001] = "v"
        s = make_session(c)
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001))], SP_NONE)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF],
                                    mode="best_effort", duration_s=5)
        self.assertEqual(out["counts"]["matched"], 1)
        self.assertEqual(c.resumed, [])
        self.assertEqual(out["records"][0]["attribution"]["status"],
                         "not_captured")

    def test_max_events_budget(self):
        c = dec_client()
        c.strings.update({8001: "a", 8002: "b", 8003: "c"})
        s = make_session(c)
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001)),
                    lambda rid: exit_event(rid, ret=str_ret(8002)),
                    lambda rid: exit_event(rid, ret=str_ret(8003))],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=30,
                                    max_events=2)
        self.assertEqual(out["reason"], "max_events")
        self.assertEqual(out["counts"]["matched"], 2)

    def test_mod_count_is_not_a_first_n_budget(self):
        # MOD_COUNT=N means the VM skips N-1 matches and delivers ONE event;
        # the host must not treat N as an event cap.
        c = dec_client()
        c.strings.update({8001: "a", 8002: "b"})
        s = make_session(c)
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001))],
                   SP_EVENT_THREAD),
                  ([lambda rid: exit_event(rid, ret=str_ret(8002))],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=5,
                                    mod_count=3)
        self.assertEqual(out["counts"]["matched"], 2)  # not capped at 3
        self.assertIn(("count", 3), c.set_calls[0][2])

    def test_max_reads_budget_stops_and_drops(self):
        c = dec_client()
        c.strings.update({8001: "a", 8002: "b", 8003: "c"})
        s = make_session(c)
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001)),
                    lambda rid: exit_event(rid, ret=str_ret(8002)),
                    lambda rid: exit_event(rid, ret=str_ret(8003))],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=30,
                                    max_reads=1)
        self.assertEqual(out["reason"], "max_reads")
        self.assertEqual(out["counts"]["matched"], 1)
        self.assertGreaterEqual(out["counts"]["dropped"], 1)

    def test_max_output_bytes_truncation(self):
        c = dec_client()
        c.strings[8001] = "payload"
        s = make_session(c)
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001))],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=30,
                                    max_output_bytes=1)
        self.assertEqual(out["reason"], "max_output_bytes")
        self.assertTrue(out["truncated"])

    def test_cancellation(self):
        c = dec_client()
        c.strings[8001] = "v"
        cancel = threading.Event()
        cancel.set()
        s = make_session(c)
        out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=30,
                                cancel=cancel)
        self.assertEqual(out["reason"], "cancelled")
        self.assertEqual(set(c.cleared), {(EVK_METHOD_EXIT_RET, 1)})

    def test_queue_pressure(self):
        c = dec_client()
        c.strings[8001] = "v"
        s = make_session(c)

        def unrelated(rid):
            return {"kind": "breakpoint", "kind_id": 2, "request_id": 999,
                    "thread": 22,
                    "location": {"class": 7000, "method": 1, "index": 0}}
        events = [([unrelated], SP_EVENT_THREAD) for _ in range(3)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=30,
                                    max_queue=1)
        self.assertEqual(out["reason"], "queue_pressure")
        self.assertGreaterEqual(out["counts"]["unrelated"], 2)

    def test_capture_exception_non_fatal(self):
        c = dec_client()
        s = make_session(c)

        def boom(oid, max_len=4096):
            raise RuntimeError("unexpected capture crash")
        c.string_value = boom
        events = [([lambda rid: exit_event(rid, ret=str_ret(8001))],
                   SP_EVENT_THREAD)]
        with self._queued_watch(c, events):
            out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=5)
        # string_value failure inside _read_texts is an 'unavailable'
        # record, not a crash; the thread is still resumed and cleaned up
        self.assertEqual(out["counts"]["unavailable"], 1)
        self.assertEqual(out["records"][0]["status"], "unavailable")
        self.assertEqual(c.resumed, [11])
        self.assertEqual(out["cleanup_errors"], [])

    def test_disconnect_reports_unconfirmed_no_clears(self):
        c = dec_client()
        s = make_session(c)
        s.events.bump_epoch()  # simulate reconnect after install epoch
        # install on the NEW epoch, then bump again mid-watch
        rep = strings.install(s, [strings.resolve_profile(DEC_PROF)])
        rid = rep["installed"][0]["request_ids"][0]
        orig_next = c.next_event

        def disconnecting(timeout=None):
            s.events.bump_epoch()  # reconnect mid-watch
            raise _timeout_error()
        c.next_event = disconnecting
        out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=5)
        self.assertEqual(out["unconfirmed"], [rid])
        self.assertEqual(c.cleared, [])  # dead-epoch ids never cleared

    def test_teardown_clears_with_exit_kind(self):
        c = dec_client()
        s = make_session(c)
        out = strings.run_watch(s, profiles=[DEC_PROF], duration_s=1)
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(c.cleared, [(EVK_METHOD_EXIT_RET, 1)])
        self.assertEqual(s.bp_registry, {})
        self.assertIn("coverage_note", out)
        self.assertIn("StringBuilder.toString misses", out["coverage_note"])


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
        c = dec_client()
        c.strings.update({8001: "https://dec.example/api",
                          8002: "https://dec.example/other"})
        c.frames[11] = [{"frame_id": 1,
                         "location": {"class": 1000, "method": 1500,
                                      "index": 3}}]
        s = make_session(c, project=self.proj)
        orig_install = strings.install

        def install_then_queue(session, profiles, **ikw):
            r = orig_install(session, profiles, **ikw)
            rid = r["installed"][0]["request_ids"][0]
            c.event_queue.append(composite(exit_event(rid,
                                                      ret=str_ret(8001))))
            c.event_queue.append(composite(exit_event(rid,
                                                      ret=str_ret(8002))))
            return r
        from unittest.mock import patch
        with patch.object(strings, "install", install_then_queue):
            return strings.run_watch(s, profiles=[DEC_PROF], duration_s=5,
                                     record=True, scope="com.foo.*",
                                     scenario="t")

    def test_run_manifest_and_event_rows(self):
        out = self._run_recorded_watch()
        self.assertIsNotNone(out["run_id"])
        store = RunStore(self.proj)
        got = store.get_run(out["run_id"])
        run = got["run"]
        self.assertEqual(run["kind"], "string_watch")
        self.assertEqual(run["scenario"], "t")
        cfg = run["capture_config"]
        self.assertEqual(cfg["mode"], "attributed")
        self.assertEqual(cfg["scope"], "com.foo.*")
        self.assertIn("max_events", cfg["limits"])
        self.assertEqual(cfg["profiles"][0]["name"], "custom:decrypt")
        self.assertEqual(run["counts"]["matched"], 2)
        self.assertEqual(len(got["events"]), 2)
        ev = got["events"][0]
        self.assertEqual(ev["kind"], "string_record")
        self.assertEqual(ev["class_sig"], DEC_CLS)
        self.assertEqual(ev["method_name"], "decrypt")
        self.assertEqual(ev["method_sig"], "([B)Ljava/lang/String;")
        self.assertEqual(ev["payload"]["profile"], "custom:decrypt")
        self.assertIn("attribution", ev["payload"])
        self.assertEqual(ev["payload"]["attribution"]["status"],
                         "no_app_frame")

    def test_offline_query_pagination_and_filters(self):
        out = self._run_recorded_watch()
        q = strings.query_records(self.proj, limit=1, offset=0)
        self.assertEqual(q["total"], 2)
        self.assertEqual(q["count"], 1)
        self.assertTrue(q["truncated"])
        q2 = strings.query_records(self.proj, limit=1, offset=1)
        self.assertEqual(q2["count"], 1)
        self.assertFalse(q2["truncated"])
        self.assertNotEqual(q["records"][0]["event_id"],
                            q2["records"][0]["event_id"])
        # filters: run_id / profile / mode / text substring
        self.assertEqual(strings.query_records(
            self.proj, run_id=out["run_id"])["total"], 2)
        self.assertEqual(strings.query_records(
            self.proj, run_id="nope")["total"], 0)
        self.assertEqual(strings.query_records(
            self.proj, profile="custom:decrypt")["total"], 2)
        self.assertEqual(strings.query_records(
            self.proj, profile="log.i")["total"], 0)
        self.assertEqual(strings.query_records(
            self.proj, mode="attributed")["total"], 2)
        self.assertEqual(strings.query_records(
            self.proj, mode="best_effort")["total"], 0)
        only = strings.query_records(self.proj, text="/other")
        self.assertEqual(only["total"], 1)
        self.assertEqual(only["records"][0]["texts"],
                         ["https://dec.example/other"])


if __name__ == "__main__":
    unittest.main()

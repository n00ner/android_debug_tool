"""Offline tests for issue #33 — versioned agent API and request
correlation after malformed input.

Covers: id correlation across malformed lines, envelope validation (wrong
root/params types, unknown methods, missing fields), JSON-RPC 2.0 mode
(numeric protocol errors, notifications, batches), project/ADB-free
discovery (describe/capabilities), catalog completeness for every command
in COMMANDS, bounded pagination metadata, and strict-JSON serialization
including the non-finite JDWP float/double cases from issue #9.

Server tests drive RpcServer.handle_line directly (no stdio, no device);
command tests use temp project dirs or duck-typed stub contexts."""

from __future__ import annotations

import io
import json
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock

from apkdbg import __version__, commands
from apkdbg.cli import SESSION_VERBS
from apkdbg.commands import COMMANDS, MAX_PAGE
from apkdbg.core import apicatalog
from apkdbg.core.project import Project
from apkdbg.device.jdwp import Reader
from apkdbg.errors import ApkDbgError
from apkdbg.protocol import dumps, ok
from apkdbg.server import (
    INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND,
    RpcServer, serve_stdio,
)

NOPE_PROJECT = "definitely/not/an/apkdbg/project"


def strict_loads(text: str):
    """RFC 8259-strict parse: reject NaN/Infinity constants outright."""
    def _reject(x):
        raise ValueError(f"non-finite constant {x}")
    return json.loads(text, parse_constant=_reject)


def make_project(tmp: str) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", "ab" * 32)
    return proj


def seed_classes(proj: Project, n: int) -> None:
    with proj.db() as db:
        for i in range(n):
            db.execute(
                "INSERT INTO classes(sig, fqcn) VALUES(?,?)",
                (f"Lcom/x/C{i};", f"com.x.C{i}"))


# ---------------------------------------------------------------- correlation
class CorrelationTests(unittest.TestCase):
    """Acceptance: id 7 ok -> malformed JSON -> id 8 ok; the parse error
    must carry id null, never the previous request's id."""

    def setUp(self):
        self.srv = RpcServer(NOPE_PROJECT)

    def test_parse_error_never_borrows_previous_id(self):
        r1, = self.srv.handle_line('{"id":7,"method":"describe"}')
        self.assertEqual(r1["id"], 7)
        self.assertIn("result", r1)

        r2, = self.srv.handle_line('{"id":999,"method":"bp",')  # malformed
        self.assertIsNone(r2["id"])
        self.assertEqual(r2["error"]["code"], "E_PARSE")

        r3, = self.srv.handle_line(
            '{"id":8,"method":"describe","params":{"command":"bp"}}')
        self.assertEqual(r3["id"], 8)
        self.assertEqual(r3["result"]["name"], "bp")

    def test_malformed_first_line_then_valid(self):
        r1, = self.srv.handle_line("not json at all")
        self.assertIsNone(r1["id"])
        self.assertEqual(r1["error"]["code"], "E_PARSE")
        r2, = self.srv.handle_line('{"id":1,"method":"capabilities"}')
        self.assertEqual(r2["id"], 1)
        self.assertIn("result", r2)

    def test_error_line_does_not_corrupt_next_id(self):
        # an error reply for id 7 must not leak into the reply for id 8
        self.srv.handle_line('{"id":7,"method":"nope"}')
        r, = self.srv.handle_line('{"id":8,"method":"describe"}')
        self.assertEqual(r["id"], 8)
        self.assertIn("result", r)


# ------------------------------------------------------- legacy v1 validation
class LegacyValidationTests(unittest.TestCase):
    def setUp(self):
        self.srv = RpcServer(NOPE_PROJECT)

    def test_wrong_root_types(self):
        for line in ('"just a string"', "42", "true", "null"):
            r, = self.srv.handle_line(line)
            self.assertIsNone(r["id"], line)
            self.assertEqual(r["error"]["code"], "E_INVALID_REQUEST", line)

    def test_wrong_params_type(self):
        for params in ("[1,2]", '"x"', "7"):
            r, = self.srv.handle_line(
                f'{{"id":3,"method":"classes","params":{params}}}')
            self.assertEqual(r["id"], 3)
            self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS", params)

    def test_missing_and_nonstring_method(self):
        r, = self.srv.handle_line('{"id":1}')
        self.assertEqual(r["error"]["code"], "E_INVALID_REQUEST")
        r, = self.srv.handle_line('{"id":1,"method":42}')
        self.assertEqual(r["id"], 1)
        self.assertEqual(r["error"]["code"], "E_INVALID_REQUEST")

    def test_unknown_method(self):
        r, = self.srv.handle_line('{"id":5,"method":"definitely_nope"}')
        self.assertEqual(r["id"], 5)
        self.assertEqual(r["error"]["code"], "E_METHOD_NOT_FOUND")
        self.assertIn("bp", r["error"]["hint"])

    def test_missing_required_param_validated_before_context(self):
        # NOPE_PROJECT would fail with E_MAPPING if the context were built
        # first; E_INVALID_PARAMS proves validation happens before it.
        r, = self.srv.handle_line('{"id":6,"method":"bp"}')
        self.assertEqual(r["id"], 6)
        self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")
        self.assertIn("spec", r["error"]["message"])

    def test_unknown_param_name(self):
        r, = self.srv.handle_line(
            '{"id":7,"method":"classes","params":{"bogus":1}}')
        self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")
        self.assertIn("bogus", r["error"]["message"])

    def test_wrong_param_types(self):
        cases = [
            ('{"id":1,"method":"classes","params":{"limit":"50"}}', "limit"),
            ('{"id":1,"method":"classes","params":{"limit":true}}', "limit"),
            ('{"id":1,"method":"bp","params":{"spec":null}}', "spec"),
            ('{"id":1,"method":"read_var","params":{"thread":1.5}}', "thread"),
        ]
        for line, pname in cases:
            r, = self.srv.handle_line(line)
            self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS", line)
            self.assertIn(pname, r["error"]["message"], line)

    def test_error_data_shape(self):
        r, = self.srv.handle_line('{"id":1,"method":"nope"}')
        err = r["error"]
        # always-present keys; optional keys absent (never null) when unset
        self.assertEqual(err["code"], "E_METHOD_NOT_FOUND")
        self.assertIs(err["retryable"], False)
        self.assertEqual(err["outcome"], "failed")
        self.assertIn("hint", err)
        self.assertNotIn("context", err)


# ------------------------------------------------------------- JSON-RPC 2.0
class JsonRpc2Tests(unittest.TestCase):
    def setUp(self):
        self.srv = RpcServer(NOPE_PROJECT)

    def v2(self, **kw):
        return self.srv.handle_line(json.dumps(kw))[0]

    def test_result_envelope(self):
        r = self.v2(jsonrpc="2.0", id="abc", method="describe",
                    params={"command": "runs"})
        self.assertEqual(r["jsonrpc"], "2.0")
        self.assertEqual(r["id"], "abc")
        self.assertEqual(r["result"]["name"], "runs")

    def test_explicit_null_id_is_a_request(self):
        r = self.v2(jsonrpc="2.0", id=None, method="capabilities")
        self.assertIsNone(r["id"])
        self.assertIn("result", r)

    def test_wrong_jsonrpc_value(self):
        r = self.v2(jsonrpc="1.0", id=1, method="describe")
        self.assertEqual(r["error"]["code"], INVALID_REQUEST)

    def test_missing_method(self):
        r = self.v2(jsonrpc="2.0", id=1)
        self.assertEqual(r["error"]["code"], INVALID_REQUEST)
        self.assertEqual(r["id"], 1)

    def test_invalid_id_types_reply_null_id(self):
        for bad_id in ({"x": 1}, [1], True):
            r = self.v2(jsonrpc="2.0", id=bad_id, method="describe")
            self.assertIsNone(r["id"], bad_id)
            self.assertEqual(r["error"]["code"], INVALID_REQUEST, bad_id)

    def test_unknown_method(self):
        r = self.v2(jsonrpc="2.0", id=2, method="nope")
        self.assertEqual(r["error"]["code"], METHOD_NOT_FOUND)
        self.assertEqual(r["error"]["data"]["code"], "E_METHOD_NOT_FOUND")

    def test_invalid_params(self):
        r = self.v2(jsonrpc="2.0", id=3, method="bp", params={})
        self.assertEqual(r["error"]["code"], INVALID_PARAMS)
        self.assertEqual(r["error"]["data"]["code"], "E_INVALID_PARAMS")
        r = self.v2(jsonrpc="2.0", id=3, method="bp", params="oops")
        self.assertEqual(r["error"]["code"], INVALID_PARAMS)

    def test_positional_params(self):
        r = self.v2(jsonrpc="2.0", id=4, method="describe",
                    params=["classes"])
        self.assertEqual(r["result"]["name"], "classes")
        r = self.v2(jsonrpc="2.0", id=5, method="describe",
                    params=["a", "b"])
        self.assertEqual(r["error"]["code"], INVALID_PARAMS)

    def test_domain_error_preserves_e_code_in_data(self):
        # classes on a nonexistent project root -> E_MAPPING domain error
        r = self.v2(jsonrpc="2.0", id=6, method="classes")
        self.assertEqual(r["error"]["code"], INTERNAL_ERROR)
        data = r["error"]["data"]
        self.assertEqual(data["code"], "E_MAPPING")
        self.assertIn("retryable", data)
        self.assertIn("outcome", data)
        self.assertIn("hint", data)

    def test_notification_gets_no_reply(self):
        self.assertEqual(
            self.srv.handle_line(
                '{"jsonrpc":"2.0","method":"describe"}'), [])

    def test_notification_error_gets_no_reply(self):
        self.assertEqual(
            self.srv.handle_line(
                '{"jsonrpc":"2.0","method":"nope"}'), [])

    def test_every_reply_is_strict_json(self):
        lines = [
            '{"id":7,"method":"describe"}', "garbage{",
            '{"jsonrpc":"2.0","id":1,"method":"capabilities"}',
            '{"jsonrpc":"2.0","id":2,"method":"nope"}',
            '[{"id":3,"method":"describe"},7]',
        ]
        for line in lines:
            for reply in self.srv.handle_line(line):
                strict_loads(dumps(reply))  # raises on invalid JSON


# ------------------------------------------------------------------- batches
class BatchTests(unittest.TestCase):
    def setUp(self):
        self.srv = RpcServer(NOPE_PROJECT)

    def test_mixed_batch(self):
        replies = self.srv.handle_line(json.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "describe",
             "params": {"command": "bp"}},
            {"jsonrpc": "2.0", "method": "describe"},      # notification
            {"id": 2, "method": "capabilities"},           # legacy element
            {"jsonrpc": "2.0", "id": 3, "method": "nope"}, # method error
            42,                                            # invalid element
        ]))
        self.assertEqual(len(replies), 4)  # notification omitted
        r1, r2, r3, r4 = replies
        self.assertEqual((r1["jsonrpc"], r1["id"]), ("2.0", 1))
        self.assertEqual(r1["result"]["name"], "bp")
        self.assertEqual(r2["id"], 2)  # legacy envelope has no jsonrpc key
        self.assertNotIn("jsonrpc", r2)
        self.assertIn("result", r2)
        self.assertEqual(r3["error"]["code"], METHOD_NOT_FOUND)
        self.assertEqual(r3["id"], 3)
        self.assertIsNone(r4["id"])
        self.assertEqual(r4["error"]["code"], INVALID_REQUEST)

    def test_empty_batch(self):
        r, = self.srv.handle_line("[]")
        self.assertEqual(r["error"]["code"], INVALID_REQUEST)
        self.assertIsNone(r["id"])

    def test_all_notifications_produce_no_output(self):
        self.assertEqual(self.srv.handle_line(json.dumps([
            {"jsonrpc": "2.0", "method": "describe"},
            {"jsonrpc": "2.0", "method": "capabilities"},
        ])), [])

    def test_batch_of_malformed_after_valid_line_keeps_correlation(self):
        # a valid id-7 request, then a broken batch, then id 8
        r, = self.srv.handle_line('{"jsonrpc":"2.0","id":7,"method":"describe"}')
        self.assertEqual(r["id"], 7)
        r, = self.srv.handle_line('[{"jsonrpc":"2.0","id":1,"method":"x"')
        self.assertIsNone(r["id"])  # parse error, not 7, not 1
        r, = self.srv.handle_line('{"jsonrpc":"2.0","id":8,"method":"describe"}')
        self.assertEqual(r["id"], 8)


# ----------------------------------------------------------------- discovery
class DiscoveryTests(unittest.TestCase):
    """describe/capabilities must work with no project and no device."""

    def setUp(self):
        self.srv = RpcServer(NOPE_PROJECT)

    def test_describe_full_catalog_without_project(self):
        r, = self.srv.handle_line('{"id":1,"method":"describe"}')
        cat = r["result"]
        self.assertEqual(cat["catalog_version"], apicatalog.CATALOG_VERSION)
        names = {c["name"] for c in cat["commands"]}
        self.assertEqual(names, set(COMMANDS) | {"describe", "capabilities"})

    def test_describe_single_command(self):
        r, = self.srv.handle_line(
            '{"id":2,"method":"describe","params":{"command":"write_var"}}')
        e = r["result"]
        self.assertEqual(e["name"], "write_var")
        self.assertEqual(e["version"], apicatalog.COMMAND_VERSION)
        by_name = {p["name"]: p for p in e["params"]}
        self.assertTrue(by_name["thread"]["required"])
        self.assertFalse(by_name["frame"]["required"])
        self.assertEqual(by_name["frame"]["default"], 0)
        self.assertIs(e["mutates"], True)
        self.assertEqual(e["requires"], {"project": True, "session": True})

    def test_describe_unknown_command(self):
        r, = self.srv.handle_line(
            '{"id":3,"method":"describe","params":{"command":"nope"}}')
        self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")

    def test_capabilities_without_project(self):
        r, = self.srv.handle_line('{"id":4,"method":"capabilities"}')
        caps = r["result"]
        self.assertEqual(caps["tool_version"], __version__)
        self.assertEqual(caps["protocol"]["versions"], ["1.0", "2.0"])
        self.assertEqual(caps["protocol"]["default"], "1.0")
        states = caps["commands"]
        self.assertEqual(states["classes"], "supported")
        self.assertEqual(states["describe"], "supported")
        self.assertEqual(states["bp"], "unavailable_in_this_session")
        self.assertEqual(states["read_var"], "unavailable_in_this_session")
        self.assertEqual(states["native"], "unverified_runtime")
        self.assertEqual(set(states),
                         set(COMMANDS) | {"describe", "capabilities"})
        for feature_state in caps["features"].values():
            self.assertIn(feature_state, caps["capability_states"])

    def test_capabilities_with_live_session(self):
        srv = RpcServer(NOPE_PROJECT)
        srv._ctx = types.SimpleNamespace(
            _session=types.SimpleNamespace(client=object()))
        r, = srv.handle_line('{"id":1,"method":"capabilities"}')
        self.assertEqual(r["result"]["commands"]["bp"], "supported")
        self.assertEqual(r["result"]["commands"]["native"],
                         "unverified_runtime")  # runtime state wins


# ------------------------------------------------------ catalog completeness
class CatalogCompletenessTests(unittest.TestCase):
    """Every public command must have discoverable schemas and mutation
    metadata."""

    def test_every_command_has_a_complete_entry(self):
        cat = apicatalog.catalog()
        by_name = {c["name"]: c for c in cat["commands"]}
        for name in COMMANDS:
            with self.subTest(command=name):
                e = by_name[name]
                self.assertIsInstance(e["version"], int)
                self.assertTrue(e["summary"])
                self.assertTrue(e["result"])
                self.assertIsInstance(e["mutates"], bool)
                self.assertIsInstance(e["idempotent"], bool)
                self.assertIsInstance(e["retryable"], bool)
                self.assertIsInstance(e["requires"]["project"], bool)
                self.assertIsInstance(e["requires"]["session"], bool)

    def test_entry_params_match_function_signatures(self):
        import inspect
        for name, fn in COMMANDS.items():
            with self.subTest(command=name):
                e = apicatalog.entry_for(name)
                sig_params = [p for p in
                              inspect.signature(fn).parameters.values()
                              if p.name != "ctx"]
                self.assertEqual([p["name"] for p in e["params"]],
                                 [p.name for p in sig_params])
                for spec, p in zip(e["params"], sig_params):
                    has_default = p.default is not inspect.Parameter.empty
                    self.assertEqual(spec["required"], not has_default)
                    if has_default:
                        self.assertEqual(spec["default"], p.default)

    def test_session_requirements_match_cli_surface(self):
        for name in COMMANDS:
            with self.subTest(command=name):
                e = apicatalog.entry_for(name)
                self.assertEqual(e["requires"]["session"],
                                 name in SESSION_VERBS)

    def test_pagination_metadata_complete(self):
        paginated = {"classes", "methods", "res", "res_refs", "bp_list",
                     "runs", "native"}
        for name, fn in COMMANDS.items():
            with self.subTest(command=name):
                e = apicatalog.entry_for(name)
                if name in paginated:
                    page = e["pagination"]
                    self.assertEqual(page["max_limit"], MAX_PAGE)
                    pnames = {p["name"] for p in e["params"]}
                    self.assertLessEqual(set(page["params"]), pnames)
                    self.assertIn("truncated", page["metadata"])
                else:
                    self.assertNotIn("pagination", e)

    def test_meta_overlay_covers_commands(self):
        self.assertEqual(set(apicatalog._META), set(COMMANDS))


# ----------------------------------------------------------------- pagination
class PaginationTests(unittest.TestCase):
    def test_classes_pagination_and_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = make_project(tmp)
            seed_classes(proj, 7)
            srv = RpcServer(tmp)
            r, = srv.handle_line(
                '{"id":1,"method":"classes","params":{"limit":3,"offset":2}}')
            res = r["result"]
            self.assertEqual(res["count"], 3)
            self.assertEqual(res["total"], 7)
            self.assertEqual((res["limit"], res["offset"]), (3, 2))
            self.assertIs(res["truncated"], True)
            r, = srv.handle_line(
                '{"id":2,"method":"classes","params":{"limit":3,"offset":6}}')
            self.assertIs(r["result"]["truncated"], False)

    def test_limit_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_project(tmp)
            srv = RpcServer(tmp)
            r, = srv.handle_line(
                '{"id":1,"method":"classes","params":{"limit":1000000}}')
            self.assertEqual(r["result"]["limit"], MAX_PAGE)
            r, = srv.handle_line(
                '{"id":2,"method":"runs","params":'
                '{"action":"list","limit":1000000}}')
            self.assertEqual(r["result"]["limit"], MAX_PAGE)

    def test_methods_res_and_native_pagination(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = make_project(tmp)
            with proj.db() as db:
                db.execute("INSERT INTO classes(sig, fqcn) VALUES('LA;','A')")
                for i in range(4):
                    db.execute(
                        "INSERT INTO methods(class_id, name, sig, is_native)"
                        " VALUES(1,?,?,?)", (f"m{i}", "()V", i % 2))
                db.execute(
                    "INSERT INTO resources(res_id, name) VALUES(1,'a')")
            srv = RpcServer(tmp)
            r, = srv.handle_line(
                '{"id":1,"method":"methods","params":'
                '{"class_":"A","limit":2,"offset":3}}')
            self.assertEqual(
                {k: r["result"][k] for k in ("count", "total", "truncated")},
                {"count": 1, "total": 4, "truncated": False})
            r, = srv.handle_line('{"id":2,"method":"res","params":{}}')
            self.assertEqual(r["result"]["total"], 1)
            self.assertIn("truncated", r["result"])
            r, = srv.handle_line(
                '{"id":3,"method":"native","params":{"limit":1}}')
            self.assertEqual(r["result"]["count"], 1)
            self.assertEqual(r["result"]["total"], 2)
            self.assertIs(r["result"]["truncated"], True)

    def test_bp_list_pagination(self):
        bps = [{"request_id": i} for i in range(5)]
        ctx = types.SimpleNamespace(
            session=types.SimpleNamespace(list_breakpoints=lambda: bps))
        res = commands.cmd_bp_list(ctx, limit=2, offset=4)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["total"], 5)
        self.assertIs(res["truncated"], False)
        res = commands.cmd_bp_list(ctx)
        self.assertEqual(res["count"], 5)

    def test_pagination_param_types_validated(self):
        srv = RpcServer(NOPE_PROJECT)
        r, = srv.handle_line(
            '{"id":1,"method":"classes","params":{"offset":-1.5}}')
        self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")


# ------------------------------------------------ strict JSON + non-finite #9
class StrictJsonTests(unittest.TestCase):
    def test_sanitize_nested_nonfinite(self):
        payload = {"a": [float("nan"), {"b": float("inf")}],
                   "c": (float("-inf"), 1.5)}
        out = strict_loads(dumps(payload))
        self.assertEqual(out["a"][0], "NaN")
        self.assertEqual(out["a"][1]["b"], "Infinity")
        self.assertEqual(out["c"][0], "-Infinity")
        self.assertEqual(out["c"][1], 1.5)

    def test_jdwp_float_double_values_are_valid_json(self):
        # issue #9 repro: JDWP float/double decodes must survive a strict
        # parser in a documented representation
        cases = [(70, ">f", float("nan"), "NaN"),
                 (68, ">d", float("inf"), "Infinity"),
                 (68, ">d", float("-inf"), "-Infinity")]
        for tag, fmt, value, marker in cases:
            decoded = Reader(bytes([tag]) + struct.pack(fmt, value)).value()
            out = strict_loads(dumps(ok(decoded)))
            self.assertEqual(out["data"]["v"], marker)

    def test_server_reply_with_nonfinite_command_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_project(tmp)
            srv = RpcServer(tmp)
            fake = lambda ctx: {"v": float("nan"),          # noqa: E731
                                "nested": [{"x": float("inf")}]}
            with mock.patch.dict(COMMANDS, {"classes": fake}):
                r, = srv.handle_line('{"id":1,"method":"classes"}')
            out = strict_loads(dumps(r))
            self.assertEqual(out["result"]["v"], "NaN")
            self.assertEqual(out["result"]["nested"][0]["x"], "Infinity")

    def test_allow_nan_guard(self):
        # even an unsanitized non-finite must fail loudly, never emit
        # invalid JSON (allow_nan=False)
        raw = {"v": float("nan")}
        with mock.patch("apkdbg.protocol._sanitize", lambda o: o):
            with self.assertRaises(ValueError):
                dumps(raw)


# ---------------------------------------------------------- stdio end-to-end
class ServeStdioTests(unittest.TestCase):
    def test_serve_stdio_lines_in_lines_out(self):
        stdin = io.StringIO(
            '{"id":7,"method":"describe","params":{"command":"classes"}}\n'
            '{"id":7,"method":\n'
            "\n"  # blank lines are skipped
            '[{"jsonrpc":"2.0","id":8,"method":"capabilities"},'
            '{"jsonrpc":"2.0","method":"describe"}]\n')
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), \
                mock.patch.object(sys, "stdout", stdout), \
                mock.patch.object(sys, "stderr", stderr):
            serve_stdio(NOPE_PROJECT)
        replies = [strict_loads(ln)
                   for ln in stdout.getvalue().splitlines()]
        self.assertEqual(len(replies), 3)
        self.assertEqual(replies[0]["id"], 7)
        self.assertEqual(replies[0]["result"]["name"], "classes")
        self.assertIsNone(replies[1]["id"])  # parse error, not 7
        self.assertEqual(replies[1]["error"]["code"], "E_PARSE")
        self.assertEqual(replies[2]["id"], 8)  # batch element, notif omitted
        # diagnostics stay off stdout
        self.assertIn("serving stdio", stderr.getvalue())

    def test_serve_stdio_closes_session_on_eof(self):
        closed = []
        srv_close = RpcServer.close
        with tempfile.TemporaryDirectory() as tmp:
            make_project(tmp)
            stdin = io.StringIO('{"id":1,"method":"classes"}\n')
            with mock.patch.object(sys, "stdin", stdin), \
                    mock.patch.object(sys, "stdout", io.StringIO()), \
                    mock.patch.object(sys, "stderr", io.StringIO()), \
                    mock.patch.object(RpcServer, "close",
                                      lambda self: (closed.append(1),
                                                    srv_close(self))[1]):
                serve_stdio(tmp)
        self.assertEqual(closed, [1])


# ------------------------------------------------------------- error contract
class ErrorContractTests(unittest.TestCase):
    def test_to_dict_stable_keys(self):
        e = ApkDbgError("boom").to_dict()
        self.assertEqual(e, {"code": "E_INTERNAL", "message": "boom",
                             "retryable": False, "outcome": "failed"})
        e = ApkDbgError("boom", hint="h", detail=1).to_dict()
        self.assertEqual(e["hint"], "h")
        self.assertEqual(e["context"], {"detail": 1})

    def test_unexpected_exception_maps_to_e_internal(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_project(tmp)
            srv = RpcServer(tmp)

            def boom(ctx):
                raise RuntimeError("kaboom")

            with mock.patch.dict(COMMANDS, {"classes": boom}):
                r, = srv.handle_line('{"id":1,"method":"classes"}')
            self.assertEqual(r["error"]["code"], "E_INTERNAL")
            self.assertEqual(r["error"]["message"], "kaboom")
            r, = srv.handle_line(
                '{"jsonrpc":"2.0","id":2,"method":"classes"}')
            # monkeypatch expired -> real classes works again
            self.assertIn("result", r)


if __name__ == "__main__":
    unittest.main()

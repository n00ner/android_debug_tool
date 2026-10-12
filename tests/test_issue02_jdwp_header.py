"""Offline regression tests for issue #2 — JDWP packet header framing.

Pre-fix, the reader thread consumed the 11-byte header and passed all 11
bytes to struct.unpack(">IIB", hdr) (needs exactly 9), crashing on the
first packet; it also read the error-code / command bytes from the
PAYLOAD instead of hdr[9:11]. These tests drive the real
JdwpClient._reader_loop and connect() against a fake JDWP peer on a
socketpair, using packet bytes written out explicitly from the spec
(see tests/jdwp_fakes.py for the layout reference).
"""

from __future__ import annotations

import socket
import struct
import threading
import time
import unittest

from apkdbg.device.jdwp import (
    CS_EVENT, CS_VM, EV_COMPOSITE, HANDSHAKE, JdwpClient, JdwpConnError,
    VM_IDSIZES, VM_SUSPEND, VM_VERSION,
)
from apkdbg.errors import JdwpReplyError
from jdwp_fakes import (command_packet, jdwp_string, location_bytes,
                        recv_exact, reply_packet)

# negotiated ID sizes, deliberately UNEQUAL (field=4, method=8, object=8,
# reftype=4, frame=8) so offset math cannot pass by assuming 8 everywhere
ID_SIZES = (4, 8, 8, 4, 8)


def _serve_handshake_and_init(peer: socket.socket, sizes=ID_SIZES,
                              chunk: int | None = None):
    """Peer coroutine: handshake, then answer IDSizes + Version. When
    `chunk` is set, every reply is dribbled out in `chunk`-byte pieces
    (fragmented socket reads)."""
    assert recv_exact(peer, len(HANDSHAKE)) == HANDSHAKE
    peer.sendall(HANDSHAKE)
    version_payload = (jdwp_string("fake JDWP peer")
                       + struct.pack(">II", 1, 8)
                       + jdwp_string("2.0-fake") + jdwp_string("FakeVM"))
    for _ in range(2):
        hdr = recv_exact(peer, 11)
        length, pid, flags, cs, cmd = struct.unpack(">IIBBB", hdr)
        recv_exact(peer, length - 11)
        if (cs, cmd) == (CS_VM, VM_IDSIZES):
            payload = struct.pack(">IIIII", *sizes)
        else:
            assert (cs, cmd) == (CS_VM, VM_VERSION)
            payload = version_payload
        pkt = reply_packet(pid, 0, payload)
        if chunk:
            for i in range(0, len(pkt), chunk):
                peer.sendall(pkt[i:i + chunk])
                time.sleep(0.005)
        else:
            peer.sendall(pkt)


class _PeerCase(unittest.TestCase):
    """Sets up client <-> peer socketpair and always closes both."""

    def setUp(self):
        self.client = JdwpClient("127.0.0.1", 0, timeout=2)
        self.client.sock, self.peer = socket.socketpair()
        self.client._alive = True
        self.reader = threading.Thread(target=self.client._reader_loop,
                                       daemon=True)
        self.reader.start()

    def tearDown(self):
        self.client.close()
        self.peer.close()
        self.reader.join(timeout=5)


class ConnectFramingTest(unittest.TestCase):
    def test_issue2_connect_idsizes_version(self):
        """Successful connect(): handshake + IDSizes + Version, with
        unequal negotiated ID sizes landing on the right fields."""
        client = JdwpClient("127.0.0.1", 0, timeout=2)
        client.sock, peer = socket.socketpair()
        t = threading.Thread(target=_serve_handshake_and_init, args=(peer,),
                             daemon=True)
        t.start()
        # hand connect() a pre-connected socketpair end instead of TCP
        with _patched_create_connection(client.sock):
            client.connect()
        t.join(timeout=5)
        peer.close()
        self.assertEqual((client.sizes.field, client.sizes.method,
                          client.sizes.object, client.sizes.reftype,
                          client.sizes.frame), ID_SIZES)
        self.assertEqual(client.handshake_info["jdwp_major"], 1)
        self.assertEqual(client.handshake_info["jdwp_minor"], 8)
        self.assertEqual(client.handshake_info["vm_name"], "FakeVM")
        client.close()

    def test_issue2_connect_fragmented_socket_reads(self):
        """Replies dribbled one byte at a time must still assemble."""
        client = JdwpClient("127.0.0.1", 0, timeout=5)
        client.sock, peer = socket.socketpair()
        t = threading.Thread(target=_serve_handshake_and_init,
                             args=(peer, ID_SIZES, 1), daemon=True)
        t.start()
        with _patched_create_connection(client.sock):
            client.connect()
        t.join(timeout=10)
        peer.close()
        self.assertEqual(client.sizes.field, ID_SIZES[0])
        client.close()


class _patched_create_connection:
    """connect() opens its own TCP socket; substitute the socketpair end
    so the REAL connect/handshake/init code runs against the fake peer."""

    def __init__(self, sock):
        self.sock = sock

    def __enter__(self):
        import apkdbg.device.jdwp as mod
        self._mod = mod
        self._orig = mod.socket.create_connection
        mod.socket.create_connection = lambda *a, **k: self.sock
        return self

    def __exit__(self, *exc):
        self._mod.socket.create_connection = self._orig


class ReplyFramingTest(_PeerCase):
    def test_issue2_empty_success_reply(self):
        """Empty successful reply (VirtualMachine.Suspend): no payload,
        no payload bytes stolen by header parsing."""

        def serve():
            hdr = recv_exact(self.peer, 11)
            length, pid, flags, cs, cmd = struct.unpack(">IIBBB", hdr)
            self.assertEqual((cs, cmd), (CS_VM, VM_SUSPEND))
            recv_exact(self.peer, length - 11)
            self.peer.sendall(reply_packet(pid, 0, b""))

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        r = self.client.request(CS_VM, VM_SUSPEND)
        t.join(timeout=5)
        self.assertEqual(len(r.b), 0)

    def test_issue2_error_reply_bytes_come_from_header(self):
        """Error code lives in hdr[9:11]; the payload must reach the
        caller INTACT. Payload begins with bytes (0x00 0x0D) that the
        pre-fix code would have misread as the error code."""
        payload = bytes([0x00, 0x0D]) + b"diagnostic-bytes"

        def serve():
            hdr = recv_exact(self.peer, 11)
            length, pid, flags, cs, cmd = struct.unpack(">IIBBB", hdr)
            recv_exact(self.peer, length - 11)
            # THREAD_NOT_SUSPENDED = 13, in the HEADER where it belongs
            self.peer.sendall(reply_packet(pid, 13, payload))

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        with self.assertRaises(JdwpReplyError) as ctx:
            self.client.request(CS_VM, VM_SUSPEND)
        t.join(timeout=5)
        self.assertEqual(ctx.exception.context["error_no"], 13)
        self.assertIn("THREAD_NOT_SUSPENDED", str(ctx.exception))

    def test_issue2_composite_event_packet(self):
        """Command packets (events) read cmdset/cmd from hdr[9:10] and
        hand the WHOLE payload to the composite decoder."""
        sizes = self.client.sizes  # defaults: all 8
        # one breakpoint event: kind=2, request=7, thread=0x11,
        # location (tag=1, class=0x22, method=0x33, index=4)
        ev = (struct.pack(">BIQ", 2, 7, 0x11)
              + location_bytes(sizes, 1, 0x22, 0x33, 4))
        payload = struct.pack(">BI", 2, 1) + ev  # suspend=SP_ALL, count=1

        def serve():
            self.peer.sendall(command_packet(99, CS_EVENT, EV_COMPOSITE,
                                             payload))

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        got = self.client.next_event(timeout=5)
        t.join(timeout=5)
        self.assertEqual(got["suspend_policy"], 2)
        (e,) = got["events"]
        self.assertEqual((e["kind"], e["kind_id"], e["request_id"]),
                         ("breakpoint", 2, 7))
        self.assertEqual(e["thread"], 0x11)
        self.assertEqual(e["location"],
                         {"tag": 1, "class": 0x22, "method": 0x33,
                          "index": 4})


class BrokenStreamTest(_PeerCase):
    def test_issue2_truncated_packet_then_eof(self):
        """Peer announces length=40, sends 3 payload bytes, closes: the
        waiter is woken with a connection error, not left hanging."""

        def serve():
            hdr = recv_exact(self.peer, 11)
            length, pid = struct.unpack(">II", hdr[:8])
            recv_exact(self.peer, length - 11)
            self.peer.sendall(struct.pack(">IIBH", 40, pid, 0x80, 0)
                              + b"abc")
            self.peer.close()  # EOF mid-packet

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        with self.assertRaises(JdwpConnError):
            self.client.request(CS_VM, VM_SUSPEND)
        t.join(timeout=5)
        self.reader.join(timeout=5)
        self.assertIsNotNone(self.client._dead)
        self.assertFalse(self.client._alive)

    def test_issue2_malformed_length_no_hang(self):
        """A packet whose length field is smaller than the 11-byte header
        must kill the reader with a recorded error, never hang it."""

        def serve():
            # length=4 (< 11) on an event packet: payload decode fails
            self.peer.sendall(struct.pack(">IIBBB", 4, 1, 0,
                                          CS_EVENT, EV_COMPOSITE))

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.reader.join(timeout=5)
        t.join(timeout=5)
        self.assertFalse(self.reader.is_alive(),
                         "reader hung on malformed length")
        self.assertIsNotNone(self.client._dead)
        with self.assertRaises(JdwpConnError):
            self.client.next_event(timeout=1)


if __name__ == "__main__":
    unittest.main()

"""Offline regression tests for issue #11 — a failed JDWP connection
attempt must close its socket (and stop any reader thread) before
raising, including when a context manager's __enter__ fails.

Uses only loopback TCP listeners. EOF at the accepted peer socket proves
the client socket was really closed; a still-open client would keep the
peer's recv() blocked.
"""

from __future__ import annotations

import socket
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from apkdbg.device.jdwp import HANDSHAKE, JdwpClient, JdwpConnError

TIMEOUT = 0.3


class _Listener:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def accept(self):
        self.sock.settimeout(5)
        peer, _ = self.sock.accept()
        peer.settimeout(5)
        return peer

    def close(self):
        self.sock.close()


def _assert_peer_sees_eof(test: unittest.TestCase, peer: socket.socket):
    """Drain until EOF; if the client socket is still open this blocks
    (peer timeout turns it into a test failure, not a hang). A reset
    (close with unread reply data pending, e.g. the rejected-handshake
    case) proves closure just as a clean EOF does."""
    data = b""
    while True:
        try:
            chunk = peer.recv(4096)
        except ConnectionResetError:
            return
        if not chunk:
            return
        data += chunk
        test.assertLess(len(data), 1 << 20)


def run_peer(serve, action, timeout=10):
    """Run the fake peer on an executor while `action` drives the client;
    peer failures (assertions, socket timeouts) re-raise on the test
    thread via result() — a bare Thread would swallow them into
    threading.excepthook and t.join() would not re-raise."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        peer = pool.submit(serve)
        action()
        peer.result(timeout=timeout)


class FailedConnectCleanupTest(unittest.TestCase):
    def setUp(self):
        self.listener = _Listener()
        self.client = JdwpClient("127.0.0.1", self.listener.port,
                                 timeout=TIMEOUT)

    def tearDown(self):
        self.client.close()
        self.listener.close()

    def _assert_clean(self):
        self.assertIsNone(self.client.sock,
                          "failed connect must not leak the socket")
        t = self.client._reader_t
        self.assertTrue(t is None or not t.is_alive(),
                        "failed connect must not leave a reader thread")

    def test_issue11_silent_handshake_peer(self):
        """The issue's reproduction: TCP connects, the peer never answers
        the handshake -> raise, socket closed, peer sees EOF."""
        def serve():
            with self.listener.accept() as peer:
                got = peer.recv(len(HANDSHAKE))
                self.assertEqual(got, HANDSHAKE)
                _assert_peer_sees_eof(self, peer)

        def attempt():
            with self.assertRaises(JdwpConnError):
                self.client.connect()

        run_peer(serve, attempt)
        self._assert_clean()

    def test_issue11_rejected_handshake(self):
        def serve():
            with self.listener.accept() as peer:
                peer.recv(len(HANDSHAKE))
                peer.sendall(b"NOT-A-JDWP-PEER")  # wrong 14-byte reply
                _assert_peer_sees_eof(self, peer)

        def attempt():
            with self.assertRaises(JdwpConnError):
                self.client.connect()

        run_peer(serve, attempt)
        self._assert_clean()

    def test_issue11_eof_during_handshake(self):
        def serve():
            with self.listener.accept() as peer:
                peer.recv(len(HANDSHAKE))  # then close without replying

        def attempt():
            with self.assertRaises(JdwpConnError):
                self.client.connect()

        run_peer(serve, attempt)
        self._assert_clean()

    def test_issue11_timeout_during_init_requests(self):
        """Handshake succeeds, then the peer goes silent on IDSizes: the
        reader thread has already started and must be stopped too."""
        def serve():
            with self.listener.accept() as peer:
                peer.recv(len(HANDSHAKE))
                peer.sendall(HANDSHAKE)
                _assert_peer_sees_eof(self, peer)

        def attempt():
            with self.assertRaises(JdwpConnError):
                self.client.connect()

        run_peer(serve, attempt)
        self._assert_clean()

    def test_issue11_context_manager_entry_failure(self):
        """`with client:` never calls __exit__ when __enter__ raises —
        cleanup must happen inside connect() itself."""
        def serve():
            with self.listener.accept() as peer:
                peer.recv(len(HANDSHAKE))
                _assert_peer_sees_eof(self, peer)

        def attempt():
            with self.assertRaises(JdwpConnError):
                with self.client:
                    pass

        run_peer(serve, attempt)
        self._assert_clean()

    def test_peer_failure_reaches_the_test_result(self):
        """Pattern guard: a peer thread that raises must fail the test —
        with a bare Thread this AssertionError only reached
        threading.excepthook and the suite stayed green."""
        def serve():
            raise AssertionError("injected peer failure")

        with self.assertRaises(AssertionError):
            run_peer(serve, lambda: None)


if __name__ == "__main__":
    unittest.main()

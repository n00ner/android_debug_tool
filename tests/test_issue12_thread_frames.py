"""Offline regression tests for issue #12 — thread_frames must handle
shallow stacks and the signed all-frames count.

Pre-fix, thread_frames() always requested exactly 32 frames (a suspended
thread with fewer rejects with INVALID_LENGTH 504) and wrote the count
UNSIGNED, so the spec-sanctioned count=-1 ("all frames") raised
struct.error instead of encoding 0xFFFFFFFF. Expected payload bytes are
written explicitly; start/length are SIGNED i32 on the wire.
"""

from __future__ import annotations

import struct
import unittest

from apkdbg.device.jdwp import (
    CS_THREADREF, TR_FRAMECOUNT, TR_FRAMES,
)
from jdwp_fakes import id_bytes, location_bytes, wired_client


def _frames_reply(client, frames) -> bytes:
    """frames: list of (frame_id, class, method, index)."""
    out = [struct.pack(">I", len(frames))]
    for fid, cls, meth, idx in frames:
        out.append(id_bytes(fid, client.sizes.frame))
        out.append(location_bytes(client.sizes, 1, cls, meth, idx))
    return b"".join(out)


TWO_FRAMES = [(0xF1, 0xC1, 0xD1, 0), (0xF2, 0xC2, 0xD2, 7)]


class ThreadFramesTest(unittest.TestCase):
    def test_issue12_default_count_clamps_to_framecount(self):
        """A shallow stack (2 frames) with the default count=32 must
        request length=2 — the pre-fix code sent 32 and got
        INVALID_LENGTH from the VM."""
        client, tx = wired_client()
        tx.replies[(CS_THREADREF, TR_FRAMECOUNT)] = struct.pack(">I", 2)
        tx.replies[(CS_THREADREF, TR_FRAMES)] = _frames_reply(
            client, TWO_FRAMES)
        frames = client.thread_frames(0x11)
        self.assertEqual(len(frames), 2)
        payload = tx.payloads(CS_THREADREF, TR_FRAMES)[0]
        # thread id | start i32 | length i32 — SIGNED
        self.assertEqual(payload, id_bytes(0x11, 8)
                         + struct.pack(">i", 0) + struct.pack(">i", 2))
        self.assertEqual([f["frame_id"] for f in frames], [0xF1, 0xF2])
        self.assertEqual(frames[0]["location"],
                         {"tag": 1, "class": 0xC1, "method": 0xD1,
                          "index": 0})

    def test_issue12_count_minus_one_encodes_signed_all_frames(self):
        """count=-1: no FrameCount probe needed, length on the wire is
        the SIGNED -1 (0xFFFFFFFF), not an unsigned-pack error."""
        client, tx = wired_client()
        tx.replies[(CS_THREADREF, TR_FRAMES)] = _frames_reply(
            client, TWO_FRAMES)
        frames = client.thread_frames(0x11, count=-1)
        self.assertEqual(len(frames), 2)
        payload = tx.payloads(CS_THREADREF, TR_FRAMES)[0]
        self.assertEqual(payload, id_bytes(0x11, 8)
                         + struct.pack(">i", 0) + b"\xff\xff\xff\xff")
        # FrameCount must NOT have been requested for the -1 fast path
        self.assertEqual(tx.payloads(CS_THREADREF, TR_FRAMECOUNT), [])

    def test_issue12_explicit_count_within_depth(self):
        client, tx = wired_client()
        tx.replies[(CS_THREADREF, TR_FRAMECOUNT)] = struct.pack(">I", 5)
        tx.replies[(CS_THREADREF, TR_FRAMES)] = _frames_reply(
            client, TWO_FRAMES[:1])
        frames = client.thread_frames(0x11, count=1)
        self.assertEqual(len(frames), 1)
        payload = tx.payloads(CS_THREADREF, TR_FRAMES)[0]
        self.assertEqual(payload[-4:], struct.pack(">i", 1))

    def test_issue12_command_ids(self):
        """ThreadReference.Frames == 6, FrameCount == 7 (regression guard
        for the command constants used on this path)."""
        self.assertEqual((TR_FRAMES, TR_FRAMECOUNT), (6, 7))


if __name__ == "__main__":
    unittest.main()

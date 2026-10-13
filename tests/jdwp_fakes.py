"""Shared deterministic JDWP wire helpers for the offline regression
tests (issues #2-#6, #10, #12). Byte strings are written out explicitly
from the JDWP spec so tests cross-check the production serializer and
parser in BOTH directions instead of trusting either one.

Packet layout (JDWP spec,
https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html):

  header (11 bytes): length u32 (includes the header itself) | id u32 |
                     flags u8
    command packet:  cmdset u8 | cmd u8 | payload
    reply packet:    flags=0x80 | error u16 | payload
  string:            u32 byte-length | UTF-8 bytes (no terminator)
  tagged value:      tag u8 | value (fixed width for primitives;
                     object IDs use the negotiated objectID size)
  location:          type tag u8 | classID | methodID | index u64
"""

from __future__ import annotations

import socket
import struct

from apkdbg.device.jdwp import IdSizes, JdwpClient, Reader

FLAG_REPLY = 0x80


def jdwp_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def reply_packet(packet_id: int, error: int = 0, payload: bytes = b"") -> bytes:
    """Full reply packet: 11-byte header, flags=0x80, error in hdr[9:11]."""
    return struct.pack(">IIBH", 11 + len(payload), packet_id,
                       FLAG_REPLY, error) + payload


def command_packet(packet_id: int, cmdset: int, cmd: int,
                   payload: bytes = b"") -> bytes:
    """Full command packet (flags=0); cmdset/cmd occupy hdr[9:11]."""
    return struct.pack(">IIBBB", 11 + len(payload), packet_id, 0,
                       cmdset, cmd) + payload


def id_bytes(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def location_bytes(sizes: IdSizes, tag: int, class_id: int, method_id: int,
                   index: int) -> bytes:
    return (bytes([tag]) + id_bytes(class_id, sizes.reftype)
            + id_bytes(method_id, sizes.method) + struct.pack(">Q", index))


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Peer-side read loop (mirrors what a real VM would see)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


class CannedTransport:
    """Replaces JdwpClient.request: captures every outbound payload
    verbatim and serves pre-built reply bodies keyed by (cmdset, cmd).
    A reply body may be an Exception instance to raise it instead."""

    def __init__(self, client: JdwpClient):
        self.client = client
        self.calls: list[tuple[int, int, bytes]] = []
        self.replies: dict[tuple[int, int], bytes | Exception] = {}

    def request(self, cmdset, cmd, payload=b"", timeout=None):
        self.calls.append((cmdset, cmd, payload))
        body = self.replies[(cmdset, cmd)]
        if isinstance(body, Exception):
            raise body
        return Reader(body, self.client.sizes)

    def payloads(self, cmdset: int, cmd: int) -> list[bytes]:
        return [p for cs, c, p in self.calls if (cs, c) == (cmdset, cmd)]


def wired_client(sizes: IdSizes | None = None
                 ) -> tuple[JdwpClient, CannedTransport]:
    """A JdwpClient whose transport is a CannedTransport (no sockets)."""
    client = JdwpClient("unused", 0)
    if sizes is not None:
        client.sizes = sizes
    transport = CannedTransport(client)
    client.request = transport.request
    return client, transport

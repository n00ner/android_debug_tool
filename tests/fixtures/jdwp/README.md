JDWP packet fixtures for the offline regression tests.

`invoke_reply_tagged_exception.hex` — a complete, spec-standard
ObjectReference.InvokeMethod REPLY packet whose method threw. Per the
JDWP specification
(https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html,
ObjectReference.InvokeMethod), the reply layout is:

    header (11 bytes): length u32 | id u32 | flags 0x80 | error u16
    return value:    TAGGED value (tag u8 + value)
    exception:       TAGGED exception object (tag u8 + objectID),
                     zero ID when the method returned normally

The tagged exception is part of the STANDARD reply layout, not an
ART-specific deviation. This packet carries a tagged NON-NULL exception
('L' + 0x1122334455667788) after a tagged int return value of 7, with
8-byte negotiated object IDs. Loaded by tests/test_issue04_invoke_reply.py.

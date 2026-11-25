"""Basic unit tests for Task 3: name compression in decode_name.

Run from the folder that contains your resolver.py and dns_model.py:

    python3 -m unittest -v task3_test

These tests check minimum correctness only. Passing them does not mean
your code is complete: test it in the testbed as well, in particular
against the lossy server (10.0.3.2), which compresses names and drops packets.
"""
import sys
import threading
import unittest
from pathlib import Path

# Find resolver.py and dns_model.py next to this file, wherever it is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from resolver import decode_name   # noqa: E402

TIME_LIMIT = 2   # seconds; a decode_name stuck in a loop fails instead of hanging


def run_with_time_limit(func, *args):
    """Run FUNC(*ARGS) in a thread. Return ("result", value), ("error", exception)
    or ("timeout", None) if it did not finish within TIME_LIMIT seconds."""
    outcome = ["timeout", None]

    def run():
        try:
            outcome[:] = ["result", func(*args)]
        except BaseException as e:     # noqa: BLE001  (RecursionError counts as rejecting)
            outcome[:] = ["error", e]

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(TIME_LIMIT)
    return tuple(outcome)


class DecodeNameCompressionTests(unittest.TestCase):
    def decode(self, packet, offset):
        kind, value = run_with_time_limit(decode_name, packet, offset)
        if kind == "timeout":
            self.fail(f"decode_name did not finish within {TIME_LIMIT} seconds")
        if kind == "error":
            raise value
        return value

    def test_decode_name_compression(self):
        # Offset 13 holds only a pointer to the name at offset 0.
        packet = b"\x07example\x03com\x00\xc0\x00"
        self.assertEqual(self.decode(packet, 13), ("example.com.", 15),
                         "(name, offset of the first byte after the pointer)")

    def test_decode_pointer_to_a_pointer(self):
        # Offset 31: a pointer to offset 13, whose name ends with a pointer to offset 0.
        packet = b"\x07example\x03com\x00\x04sccm\x045310\x05lancs\xc0\x00\xc0\x0d"
        self.assertEqual(self.decode(packet, 31), ("sccm.5310.lancs.example.com.", 33),
                         "(name, offset of the first byte after the pointer)")

    def test_decode_name_invalid(self):
        cases = [
            (b"\x07example\x03com", 0, "no zero byte at the end"),
            (b"\xc0\x00", 0, "pointer to itself"),
            (b"\xc0\xff", 0, "pointer past the end of the packet"),
        ]
        for packet, offset, why in cases:
            with self.subTest(why=why):
                kind, value = run_with_time_limit(decode_name, packet, offset)
                if kind == "timeout":
                    self.fail(f"decode_name({packet!r}, {offset}) did not finish within "
                              f"{TIME_LIMIT} seconds ({why})")
                if kind == "error" and isinstance(value, NotImplementedError):
                    self.fail("decode_name is not implemented yet")
                if kind == "result":
                    self.fail(f"decode_name({packet!r}, {offset}) should raise an exception "
                              f"({why}), but it returned {value!r}")


if __name__ == "__main__":
    unittest.main()

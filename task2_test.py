"""Basic unit tests for Task 2: encode_name, decode_name (no compression),
make_query and parse_response.

Run from the folder that contains your resolver.py and dns_model.py:

    python3 -m unittest -v task2_test

These tests check minimum correctness only. Passing them does not mean
your code is complete: test it in the testbed as well, with other names,
record types and servers.
"""
import sys
import unittest
from pathlib import Path

# Find resolver.py and dns_model.py next to this file, wherever it is run from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dns_model import DNSMessage, DNSQuestion            # noqa: E402
from resolver import decode_name, encode_name, make_query, parse_response   # noqa: E402

A, NS = 1, 2
IN = 1


class EncodeNameTests(unittest.TestCase):
    def test_encode_name(self):
        self.assertEqual(encode_name("example.com."), b"\x07example\x03com\x00")

    def test_encode_name_many_labels(self):
        name = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z."
        expected = b"".join(b"\x01" + c.encode() for c in "abcdefghijklmnopqrstuvwxyz") + b"\x00"
        self.assertEqual(encode_name(name), expected)

    def test_encode_name_label_too_long(self):
        # A label can be at most 63 bytes long, so this name must be rejected.
        name = "a" * 64 + ".com."
        try:
            result = encode_name(name)
        except NotImplementedError:
            self.fail("encode_name is not implemented yet")
        except Exception:
            return
        self.fail(f"encode_name should raise an exception for a 64-byte label, "
                  f"but it returned {result!r}")


class DecodeNameTests(unittest.TestCase):
    def test_decode_name(self):
        packet = b"\x07example\x03com\x00"
        self.assertEqual(decode_name(packet, 0), ("example.com.", 13),
                         "(name, offset of the first byte after the name)")

    def test_decode_name_many_labels(self):
        packet = b"".join(b"\x01" + c.encode() for c in "abcdefghijklmnopqrstuvwxyz") + b"\x00"
        self.assertEqual(decode_name(packet, 0),
                         ("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.", len(packet)),
                         "(name, offset of the first byte after the name)")


class MakeQueryTests(unittest.TestCase):
    def test_make_query_returns_bytes(self):
        msg = DNSMessage(ident=1, flags=0, questions=[DNSQuestion("example.com.", A, IN)])
        self.assertIsInstance(make_query(msg), bytes)

    def test_make_query_format(self):
        msg = DNSMessage(ident=1, flags=0, questions=[DNSQuestion("example.com.", A, IN)])
        query = make_query(msg)
        self.assertEqual(query[:12],
                         b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
                         "header (first 12 bytes): identifier 1, flags 0, "
                         "1 question, 0 answer, 0 authority, 0 additional records")
        self.assertEqual(query[12:], b"\x07example\x03com\x00\x00\x01\x00\x01",
                         "question: encoded name, then type A (1), then class IN (1)")


class ParseResponseTests(unittest.TestCase):
    def assertRecord(self, rec, name, rtype, value, ttl):
        self.assertEqual((rec.name, rec.type, rec.cls, rec.ttl, rec.value),
                         (name, rtype, IN, ttl, value),
                         "record fields as (name, type, class, ttl, value)")

    def test_parse_a_record_response(self):
        response = bytes.fromhex(
            "002a8000000100010000000003666f6f03636f6d000001000103666f6f03636f6d"
            "0000010001000000e10004c0000201")
        result = parse_response(response, 42)
        self.assertIsInstance(result, DNSMessage)
        self.assertEqual(result.ident, 42)
        self.assertEqual(result.flags, 0x8000)
        self.assertEqual((len(result.questions), len(result.answers),
                          len(result.authority), len(result.additional)), (1, 1, 0, 0),
                         "number of (questions, answers, authority, additional) records")
        self.assertEqual((result.questions[0].name, result.questions[0].type,
                          result.questions[0].cls), ("foo.com.", A, IN))
        self.assertRecord(result.answers[0], "foo.com.", A, "192.0.2.1", 225)

    def test_parse_referral_with_glue(self):
        # Reply from the TLD server: no answer, an NS record in the authority
        # section and its address (glue) in the additional section.
        response = bytes.fromhex(
            "ac3181000001000000010001026e7307696e666f6c6162036c6162000001000107"
            "696e666f6c6162036c616200000200010000012c0010026e7307696e666f6c6162"
            "036c616200026e7307696e666f6c6162036c616200000100010000012c00040a00"
            "0202")
        result = parse_response(response, 0xAC31)
        self.assertEqual(result.ident, 0xAC31)
        self.assertEqual(result.flags, 0x8100)
        self.assertEqual((len(result.questions), len(result.answers),
                          len(result.authority), len(result.additional)), (1, 0, 1, 1),
                         "number of (questions, answers, authority, additional) records")
        self.assertEqual((result.questions[0].name, result.questions[0].type,
                          result.questions[0].cls), ("ns.infolab.lab.", A, IN))
        self.assertRecord(result.authority[0], "infolab.lab.", NS, "ns.infolab.lab.", 300)
        self.assertRecord(result.additional[0], "ns.infolab.lab.", A, "10.0.2.2", 300)

    def test_parse_ns_record_response(self):
        response = bytes.fromhex(
            "002a80000001000100000000076578616d706c6503636f6d0000020001076578616d"
            "706c6503636f6d0000020001000000e10010026e73076578616d706c6503636f6d00")
        result = parse_response(response, 42)
        self.assertEqual(len(result.answers), 1)
        self.assertRecord(result.answers[0], "example.com.", NS, "ns.example.com.", 225)


if __name__ == "__main__":
    unittest.main()

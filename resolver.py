#!/usr/bin/env python3
"""Student starter code: implement an iterative DNS resolver."""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys

from dns_model import DNSMessage, DNSQuestion, DNSRecord

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}
IN = 1


class DNSError(RuntimeError):
    pass


def fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def encode_name(name: str) -> bytes:
    """Encode an uncompressed QNAME. Provided as a starting point."""

    # getting rid of trailing dot bc it's unnecessary to have
    if name.endswith("."):
        name = name[:-1]

    encoded = bytearray()

    # splitting domain name by section
    for letter in name.split("."):
        # ( assuming input string is ascii, will change if it poses errors)
        data = letter.encode("ascii")
        # small error proofing if data ends up being empty
        if not data:
            raise ValueError(f"empty {name!r} :(")
        encoded.append(len(data))  # length of the byte
        encoded += data  # label of the byte

    # terminates root label?
    encoded.append(0)

    return bytes(encoded)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """
    raise NotImplementedError


def make_query(msg: DNSMessage) -> bytes:
    """Build a standard UDP DNS query with recursion disabled."""
    raise NotImplementedError


def query_server(msg: DNSMessage, timeout: float, server: str) -> bytes:
    """Send one UDP query to SERVER and return the raw response bytes."""
    data = make_query(msg)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(data, (server, 53))
        response, _ = sock.recvfrom(4096)
    return response


def query(server: str, name: str, qtype: int, timeout: float, ident: int = -1) -> DNSMessage:
    """Send ONE query for NAME and QTYPE to SERVER and return the parsed reply.

    Recursion desired is off. If IDENT is -1 a random identifier is used.
    """
    if ident == -1:
        ident = random.randrange(0, 65536)
    msg = DNSMessage(ident=ident, flags=0, questions=[
                     DNSQuestion(fqdn(name), qtype)])

    response = query_server(msg, timeout, server)
    reply = parse_response(response, msg.ident)
    if reply.ident != msg.ident:
        raise DNSError("unexpected DNS response ID")
    return reply


def parse_response(packet: bytes, expected_id: int):
    """TODO: parse header, question, and all resource-record sections.

    Your parser must support compressed names (RFC 1035 section 4.1.4) in
    owner names and NS, CNAME, and MX RDATA. Return a useful representation
    containing answer, authority, and additional records. Use the supplied
    DNSMessage, DNSQuestion, and DNSRecord classes from dns_model.py.
    """
    raise NotImplementedError


def resolve_iteratively(name: str, qtype: int, root: str, timeout: float = 2.0,
                        trace: bool = False) -> list[DNSRecord]:
    """TODO: resolve NAME iteratively, starting at the ROOT server.

    Follow referrals using glue A records. Handle timeouts and NXDOMAIN/NODATA responses. Return the list of final answer DNSRecord objects.
    With TRACE, print each query and referral step.
    """
    raise NotImplementedError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("type", choices=QTYPE)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--server", metavar="ADDRESS",
                        help="send one query to this server")
    target.add_argument("--root", metavar="ADDRESS",
                        help="resolve iteratively, starting at this root server")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--trace", action="store_true",
                        help="print each resolution step (only with --root)")
    args = parser.parse_args()

    try:
        if args.server:
            response = query(args.server, args.name,
                             QTYPE[args.type], args.timeout)
            print(str(response))
        else:
            records = resolve_iteratively(
                args.name, QTYPE[args.type], args.root, args.timeout, args.trace)
            answer = DNSMessage(0, 0x8000, [DNSQuestion(fqdn(args.name), QTYPE[args.type])],
                                answers=records)
            print(str(answer))

    except DNSError as e:
        print(f"DNS error: {e}")
        return 1
    except socket.timeout:
        print("Query timed out")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

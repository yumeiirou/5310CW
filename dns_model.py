"""Supplied DNS record model and deterministic dig-style output renderer."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress

IN = 1
TYPE_NAME = {1: "A", 2: "NS", 5: "CNAME",
             6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
TYPE_ID = {value: key for key, value in TYPE_NAME.items()}
CLASS_NAME = {1: "IN"}
RCODE_NAME = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
              3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# Simple class to model a DNS query entry.


class DNSBase:
    name: str        # Domain name
    type: int        # Query type (e.g., A, NS, MX)
    cls: int = IN    # Query class (default is IN for Internet)

    def __init__(self, name: str, type: int, cls: int = IN):
        self.name = name
        self.type = type
        self.cls = cls

    def format(self) -> str:
        return f"{self.name:<30} {CLASS_NAME[self.cls]:<7} {TYPE_NAME[self.type]:<7}"

    def __str__(self) -> str:
        return self.format()


class DNSQuestion(DNSBase):
    """A class to model a DNS question entry."""
    pass

# Class to model a DNS resource record.


class DNSRecord(DNSQuestion):
    ttl: int            # Time to live
    value: str          # Record value

    def __init__(self, name: str, type: int, value: str="", cls: int = IN, ttl: int = 0):
        super().__init__(name, type, cls)
        object.__setattr__(self, 'ttl', ttl)
        object.__setattr__(self, 'value', value)

    def format_record(self) -> str:
        return f"{self.name:<30} {self.ttl:<7} {CLASS_NAME[self.cls]:<7} {TYPE_NAME[self.type]:<7} {self.format_rdata()}"

    def format_rdata(self) -> str:
        if self.type == 15 and isinstance(self.value, tuple):
            return f"{self.value[0]} {self.value[1]}"
        if self.type == 16:
            value = str(self.value).replace("\\", "\\\\").replace('"', '\\"')
            return f'"{value}"'
        if isinstance(self.value, bytes):
            return f"\\# {len(self.value)} {self.value.hex()}"
        return str(self.value)

    def __str__(self) -> str:
        return self.format_record()

# Class to model a DNS message, including header and sections.


@dataclass
class DNSMessage:
    ident: int
    flags: int
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authority: list[DNSRecord] = field(default_factory=list)
    additional: list[DNSRecord] = field(default_factory=list)

    # constructor

    def __init__(self, ident: int, flags: int, questions: list[DNSQuestion] = None,
                 answers: list[DNSRecord] = None, authority: list[DNSRecord] = None,
                 additional: list[DNSRecord] = None):
        self.ident = ident
        self.flags = flags
        # A new list for each message; a [] default would be shared by all of them.
        self.questions = questions if questions is not None else []
        self.answers = answers if answers is not None else []
        self.authority = authority if authority is not None else []
        self.additional = additional if additional is not None else []

    @property
    def rcode(self) -> int:
        return self.flags & 0xF

    def _flag_names(self) -> list[str]:
        values = ((0x8000, "qr"), (0x0400, "aa"), (0x0200, "tc"),
                  (0x0100, "rd"), (0x0080, "ra"), (0x0020, "ad"), (0x0010, "cd"))
        return [name for bit, name in values if self.flags & bit]

    # Method to render the DNS message in a stable, dig-inspired format.
    def __str__(self) -> str:
        """Render a parsed response in a stable, dig-inspired format."""
        opcode = (self.flags >> 11) & 0xF
        opcode_name = ("QUERY", "IQUERY", "STATUS")[
            opcode] if opcode < 3 else str(opcode)
        lines = [
            f";; ->>HEADER<<- opcode: {opcode_name}, status: {RCODE_NAME.get(self.rcode, self.rcode)}, id: {self.ident}",
            f";; flags: {' '.join(self._flag_names())}; QUERY: {len(self.questions)}, ANSWER: {len(self.answers)}, AUTHORITY: {len(self.authority)}, ADDITIONAL: {len(self.additional)}",
        ]
        for heading, records in (("QUESTION", self.questions), ("ANSWER", self.answers), ("AUTHORITY", self.authority), ("ADDITIONAL", self.additional)):
            if not records:
                continue
            lines.extend(("", f";; {heading} SECTION:"))
            lines.extend(str(record) for record in records)
        return "\n".join(lines)

"""Data types shared by the parser, the checks and the scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Link:
    """A link found in the email. It is only parsed, never fetched or resolved."""

    href: str
    text: str = ""  # anchor text for HTML links, empty for URLs found in plain text
    source: str = "text"  # "html" or "text"


@dataclass(frozen=True)
class Attachment:
    """Attachment metadata from the MIME headers. The payload is never decoded."""

    filename: str
    content_type: str  # as declared by the sender
    encoded_size: int  # bytes of the still-encoded payload


@dataclass
class ParsedEmail:
    input_type: str  # "email" (headers present) or "body_only"
    sha256: str
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to_domains: list[str] = field(default_factory=list)
    return_path_domain: str = ""
    auth_results: str | None = None  # topmost Authentication-Results header only
    subject: str = ""
    text: str = ""  # text/plain parts plus the visible text of text/html parts
    links: list[Link] = field(default_factory=list)
    password_inputs: int = 0  # <input type="password"> elements in HTML parts
    attachments: list[Attachment] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    """What a check reports; the scoring adds the category and the weight."""

    id: str
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Indicator:
    id: str
    category: str
    weight: int
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass
class Result:
    input_type: str
    verdict: str  # "phishing", "suspicious" or "likely_legitimate"
    score: int  # 0-100
    indicators: list[Indicator]
    notes: list[str]
    sender_domain: str | None
    email_sha256: str

    def signals(self) -> list[dict]:
        """Indicator ids and weights only: what the scan history stores."""
        return [{"id": i.id, "weight": i.weight} for i in self.indicators]

    def to_dict(self) -> dict:
        data = asdict(self)
        for item in data["indicators"]:
            item["evidence"] = list(item["evidence"])
        return data

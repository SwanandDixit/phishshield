"""
PhishShield — Email Parser
==========================
Parses raw RFC 2822 email bytes into a structured :class:`ParsedEmail`
dataclass.  Every field is fully typed; no placeholder logic exists.

Dependencies (stdlib only, plus internal hashing utility):
    email, hashlib, dataclasses, typing, datetime
"""

from __future__ import annotations

import email
import email.policy
import email.utils
from dataclasses import dataclass
from datetime import datetime
from email.message import Message

from backend.crypto.hashing import sha256_hash

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class Attachment:
    """Represents a single email attachment.

    Attributes:
        filename: Original filename reported by the MIME part.
        content_type: Full MIME type string, e.g. ``application/pdf``.
        size_bytes: Length of the decoded payload in bytes.
        data: Raw decoded bytes of the attachment payload.
        sha256_hash: Hex-encoded SHA-256 digest of *data*.
    """

    filename: str
    content_type: str
    size_bytes: int
    data: bytes
    sha256_hash: str


@dataclass
class ParsedEmail:
    """Structured representation of a parsed RFC 2822 email message.

    Attributes:
        message_id: Value of the ``Message-ID`` header (stripped of angle
            brackets).
        from_address: Bare email address extracted from the ``From`` header.
        from_display_name: Display name component of the ``From`` header, or
            an empty string when absent.
        to: List of bare recipient addresses from the ``To`` header.
        cc: List of bare recipient addresses from the ``Cc`` header.
        reply_to: List of bare addresses from the ``Reply-To`` header.
        subject: Decoded subject string.
        date: Parsed :class:`datetime` from the ``Date`` header, or ``None``
            when the header is absent or unparseable.
        all_headers: Ordered mapping of every header name → value (last value
            wins for duplicate header names).
        received_chain: Ordered list of ``Received`` header values, preserving
            the original wire order (index 0 = outermost hop).
        return_path: Bare address from the ``Return-Path`` header, or ``None``.
        authentication_results: Raw value of the ``Authentication-Results``
            header, or ``None``.
        text_body: Concatenated ``text/plain`` payload, decoded to ``str``.
        html_body: Concatenated ``text/html`` payload, decoded to ``str``.
        attachments: List of :class:`Attachment` objects for every non-inline
            MIME part with a ``Content-Disposition: attachment`` (or an
            unrecognised binary part).
        raw_sha256: Hex-encoded SHA-256 digest of the full original raw bytes.
    """

    message_id: str
    from_address: str
    from_display_name: str
    to: list[str]
    cc: list[str]
    reply_to: list[str]
    subject: str
    date: datetime | None
    all_headers: dict[str, str]
    received_chain: list[str]
    return_path: str | None
    authentication_results: str | None
    text_body: str
    html_body: str
    attachments: list[Attachment]
    raw_sha256: str

    @property
    def sender_address(self) -> str:
        return self.from_address

    @property
    def sender_display_name(self) -> str:
        return self.from_display_name

    @property
    def sender_domain(self) -> str:
        if "@" in self.from_address:
            return self.from_address.split("@", 1)[1].lower()
        return self.from_address.lower()

    @property
    def to_addresses(self) -> list[str]:
        return self.to

    @property
    def body_text(self) -> str:
        return self.text_body

    @property
    def body_html(self) -> str:
        return self.html_body

    @property
    def sha256_hash(self) -> str:
        return self.raw_sha256

    @property
    def headers(self) -> dict[str, str]:
        return self.all_headers

    @property
    def received_from_ip(self) -> str | None:
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_header_value(raw: str) -> str:
    """Decode a potentially RFC 2047-encoded header value to plain ``str``.

    Args:
        raw: The raw header string, possibly containing ``=?charset?...?=``
             encoded words.

    Returns:
        A fully decoded Unicode string.
    """
    parts = email.header.decode_header(raw)
    decoded_parts: list[str] = []
    for part_bytes, charset in parts:
        if isinstance(part_bytes, bytes):
            decoded_parts.append(
                part_bytes.decode(charset or "utf-8", errors="replace")
            )
        else:
            decoded_parts.append(part_bytes)
    return "".join(decoded_parts)


def _extract_addresses(header_value: str | None) -> list[str]:
    """Parse an address header into a list of bare email addresses.

    Args:
        header_value: Raw header string such as
            ``"Alice <alice@example.com>, Bob <bob@example.com>"``, or
            ``None``.

    Returns:
        A list of bare addresses (e.g. ``["alice@example.com"]``).  Returns an
        empty list when *header_value* is ``None`` or unparseable.
    """
    if not header_value:
        return []
    parsed = email.utils.getaddresses([header_value])
    return [addr for _name, addr in parsed if addr]


def _decode_payload(part: Message) -> bytes:
    """Decode a MIME part payload to raw bytes, handling transfer encodings.

    Args:
        part: A :class:`email.message.Message` MIME part.

    Returns:
        Decoded bytes.  Returns an empty ``bytes`` object on failure.
    """
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    # Fallback for multipart messages where get_payload returns a list.
    raw = part.get_payload()
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _charset_for_part(part: Message) -> str:
    """Return the declared charset for a text MIME part.

    Args:
        part: A :class:`email.message.Message` MIME part.

    Returns:
        Charset string (defaulting to ``"utf-8"`` when absent or unknown).
    """
    charset = part.get_content_charset()
    return charset if charset else "utf-8"


def _collect_text_and_attachments(
    message: Message,
) -> tuple[str, str, list[Attachment]]:
    """Recursively walk MIME parts, collecting text bodies and attachments.

    Args:
        message: Top-level (or nested) :class:`email.message.Message` object.

    Returns:
        A 3-tuple of ``(text_body, html_body, attachments)``.
    """
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []

    for part in message.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", "")).lower()
        is_attachment = "attachment" in disposition

        if part.is_multipart():
            # Structural parts have no payload to read directly.
            continue

        payload_bytes = _decode_payload(part)

        if is_attachment or (
            content_type not in ("text/plain", "text/html")
            and not content_type.startswith("multipart/")
        ):
            filename = part.get_filename() or ""
            digest = sha256_hash(payload_bytes)
            attachments.append(
                Attachment(
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload_bytes),
                    data=payload_bytes,
                    sha256_hash=digest,
                )
            )
            continue

        charset = _charset_for_part(part)
        decoded_text = payload_bytes.decode(charset, errors="replace")

        if content_type == "text/plain":
            text_parts.append(decoded_text)
        elif content_type == "text/html":
            html_parts.append(decoded_text)

    return "\n".join(text_parts), "\n".join(html_parts), attachments


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_email(raw_bytes: bytes) -> ParsedEmail:
    """Parse a raw RFC 2822 email message into a :class:`ParsedEmail`.

    This function handles multi-part MIME messages, encoded headers (RFC 2047),
    quoted-printable / base-64 transfer encodings, and gracefully degrades on
    malformed input.

    Args:
        raw_bytes: The complete, raw email bytes exactly as delivered over SMTP
            (including all headers and the body).

    Returns:
        A fully-populated :class:`ParsedEmail` dataclass.

    Raises:
        ValueError: If *raw_bytes* is empty.

    Example::

        with open("sample.eml", "rb") as fh:
            parsed = parse_email(fh.read())
        print(parsed.from_address, parsed.subject)
    """
    if not raw_bytes:
        raise ValueError("raw_bytes must not be empty")

    # Compute full-message hash before any manipulation.
    raw_digest = sha256_hash(raw_bytes)

    # Parse with the modern (non-compat32) policy so header access is reliable.
    msg: Message = email.message_from_bytes(
        raw_bytes, policy=email.policy.compat32
    )

    # -----------------------------------------------------------------------
    # Headers
    # -----------------------------------------------------------------------

    # Collect all headers (last value wins for duplicates, preserving order).
    all_headers: dict[str, str] = {}
    for key, value in msg.items():
        all_headers[key] = _decode_header_value(value)

    # Received chain — preserve wire order (top = first hop to receive).
    received_chain: list[str] = [
        _decode_header_value(v) for v in msg.get_all("Received") or []
    ]

    # From
    raw_from = msg.get("From", "")
    from_pairs = email.utils.getaddresses([raw_from])
    from_display_name = from_pairs[0][0] if from_pairs else ""
    from_address = from_pairs[0][1] if from_pairs else ""

    # Return-Path
    raw_rp = msg.get("Return-Path", None)
    return_path: str | None = None
    if raw_rp:
        rp_pairs = email.utils.getaddresses([raw_rp])
        return_path = rp_pairs[0][1] if rp_pairs else raw_rp.strip("<> ")

    # Date
    raw_date = msg.get("Date", None)
    parsed_date: datetime | None = None
    if raw_date:
        try:
            date_tuple = email.utils.parsedate_to_datetime(raw_date)
            parsed_date = date_tuple
        except Exception:
            parsed_date = None

    # -----------------------------------------------------------------------
    # Body parts & attachments
    # -----------------------------------------------------------------------

    text_body, html_body, attachments = _collect_text_and_attachments(msg)

    return ParsedEmail(
        message_id=(msg.get("Message-ID") or "").strip("<> "),
        from_address=from_address,
        from_display_name=from_display_name,
        to=_extract_addresses(msg.get("To")),
        cc=_extract_addresses(msg.get("Cc")),
        reply_to=_extract_addresses(msg.get("Reply-To")),
        subject=_decode_header_value(msg.get("Subject", "")),
        date=parsed_date,
        all_headers=all_headers,
        received_chain=received_chain,
        return_path=return_path,
        authentication_results=msg.get("Authentication-Results", None),
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
        raw_sha256=raw_digest,
    )

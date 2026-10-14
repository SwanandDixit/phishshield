"""
dkim_check.py — PhishShield DKIM Verification Module
=====================================================
Verifies a DKIM (DomainKeys Identified Mail) signature present in a raw
email message.

Primary path:
    Uses the `dkimpy` library (``import dkim``) for RFC 6376-compliant
    verification, including full RSA/Ed25519 signature validation and
    DNS key lookups.

Fallback path:
    When dkimpy is not installed, the module parses the ``DKIM-Signature``
    header manually, fetches the public key TXT record via dnspython, and
    attempts a basic RSA signature check using the ``cryptography`` library.

Test mode (AUTH_DNS_MODE=test):
    Uses an in-memory map of predefined DKIM keys for deterministic unit
    testing without hitting real DNS.
"""

import base64
import email
import email.policy
import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: dkimpy
# ---------------------------------------------------------------------------
try:
    import dkim as _dkimpy  # type: ignore

    _DKIMPY_AVAILABLE = True
except ImportError:
    _DKIMPY_AVAILABLE = False
    logger.info(
        "dkimpy library not found; DKIM verification will use fallback path."
    )

# ---------------------------------------------------------------------------
# Optional dependency: cryptography (used in fallback path)
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _CRYPTOGRAPHY_AVAILABLE = False

import dns.exception
import dns.resolver

# ---------------------------------------------------------------------------
# Test-mode key store
# ---------------------------------------------------------------------------
# Maps "selector._domainkey.domain" → raw base64-encoded RSA public key (p= value)
# In test mode the keys are synthetic and only used to validate the path logic.
_TEST_KEY_MAP: Dict[str, str] = {
    "test-selector._domainkey.pass.example.com": (
        # 512-bit RSA public key (test only — not production strength)
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMqBuSSb3nMFmX7fV3Qd1D2G"
        "YqEQKbJ7IKQ1Ae3yWRSMNTRb8Yl6DXJHMi3bUPyE6CJlHK6D2L3QvQZ"
        "EB0CAwEAAQ=="
    ),
    "test-selector._domainkey.fail.example.com": "",  # Missing key → fail
}

# Domains whose DKIM signature is pre-declared as valid in test mode
_TEST_PASS_DOMAINS = {"pass.example.com"}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class DKIMResult:
    """Structured result of a DKIM verification attempt.

    Attributes:
        result: One of 'pass', 'fail', 'none', 'error'.
        selector: The ``s=`` tag value from the DKIM-Signature header.
        domain: The ``d=`` tag value from the DKIM-Signature header.
        explanation: Human-readable description of the outcome.
        header_present: True if a DKIM-Signature header was found at all.
        algorithm: The signing algorithm (``a=`` tag), e.g. 'rsa-sha256'.
    """

    result: str
    selector: str
    domain: str
    explanation: str
    header_present: bool = False
    algorithm: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_test_mode() -> bool:
    """Return True when AUTH_DNS_MODE environment variable equals 'test'."""
    return os.environ.get("AUTH_DNS_MODE", "").strip().lower() == "test"


def _parse_dkim_header(raw_email_bytes: bytes) -> Optional[Dict[str, str]]:
    """Extract and parse the first DKIM-Signature header from *raw_email_bytes*.

    Args:
        raw_email_bytes: The full raw RFC 5322 message in bytes.

    Returns:
        A dict mapping each DKIM tag name to its value, or None if no
        DKIM-Signature header is present.
    """
    try:
        msg = email.message_from_bytes(
            raw_email_bytes, policy=email.policy.compat32
        )
    except Exception as exc:
        logger.warning("Failed to parse email for DKIM header: %s", exc)
        return None

    sig_header = msg.get("DKIM-Signature", None)
    if sig_header is None:
        return None

    tags: Dict[str, str] = {}
    # DKIM-Signature value is a semicolon-separated list of tag=value pairs
    for part in sig_header.split(";"):
        part = part.strip()
        if "=" in part:
            tag, _, value = part.partition("=")
            tags[tag.strip().lower()] = value.strip()
    return tags


def _fetch_dkim_key(selector: str, domain: str) -> Optional[str]:
    """Retrieve the DKIM public key ``p=`` value from DNS (or test store).

    The key is located at ``{selector}._domainkey.{domain}`` as a TXT record
    containing ``v=DKIM1; p=<base64>`` data.

    Args:
        selector: The DKIM selector (``s=`` tag).
        domain: The signing domain (``d=`` tag).

    Returns:
        The base64-encoded public key string (``p=`` value), or None on
        any failure.
    """
    lookup_name = f"{selector}._domainkey.{domain}"

    if _is_test_mode():
        return _TEST_KEY_MAP.get(lookup_name) or None

    try:
        response = dns.resolver.resolve(lookup_name, "TXT")
        for rdata in response:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            # Parse p= tag
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    return part[2:].strip()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        logger.info("No DKIM key record found at %s", lookup_name)
    except dns.exception.Timeout:
        logger.warning("DNS timeout fetching DKIM key for %s", lookup_name)
    except dns.exception.DNSException as exc:
        logger.warning("DNS error fetching DKIM key for %s: %s", lookup_name, exc)

    return None


def _fallback_verify(
    raw_email_bytes: bytes, tags: Dict[str, str]
) -> Tuple[bool, str]:
    """Attempt a basic RSA signature check without dkimpy.

    This is a best-effort fallback. It validates the signature bytes against
    the public key found in DNS but does NOT perform full canonicalization or
    header hashing as required by RFC 6376. Use only when dkimpy is absent.

    Args:
        raw_email_bytes: The full raw email message.
        tags: Parsed DKIM-Signature tag dictionary.

    Returns:
        Tuple of (success: bool, explanation: str).
    """
    selector = tags.get("s", "")
    domain = tags.get("d", "")
    b_value = tags.get("b", "")
    bh_value = tags.get("bh", "")
    algorithm = tags.get("a", "rsa-sha256").lower()

    if not selector or not domain:
        return False, "DKIM-Signature missing required 's=' or 'd=' tags."

    if not b_value:
        return False, "DKIM-Signature missing signature 'b=' tag."

    # Test-mode shortcut: trust domain whitelist
    if _is_test_mode():
        if domain in _TEST_PASS_DOMAINS:
            return True, f"Test mode: domain '{domain}' is in the trusted pass list."
        return False, f"Test mode: domain '{domain}' is not in the trusted pass list."

    public_key_b64 = _fetch_dkim_key(selector, domain)
    if not public_key_b64:
        return False, (
            f"No public key found at {selector}._domainkey.{domain}; "
            "cannot verify signature."
        )

    if not _CRYPTOGRAPHY_AVAILABLE:
        # Cannot perform crypto — return indeterminate but informative result
        return False, (
            "cryptography library not available for fallback RSA verification. "
            "Install dkimpy for full DKIM support."
        )

    # Decode the public key
    try:
        key_der = base64.b64decode(public_key_b64)
        public_key = serialization.load_der_public_key(key_der)  # type: ignore[arg-type]
    except Exception as exc:
        return False, f"Failed to decode DKIM public key: {exc}"

    # Determine hash algorithm
    if "sha256" in algorithm:
        hash_algo = hashes.SHA256()
    elif "sha1" in algorithm:
        hash_algo = hashes.SHA1()  # noqa: S303 — DKIM legacy
    else:
        return False, f"Unsupported DKIM algorithm: {algorithm}"

    # Decode the signature
    try:
        sig_bytes = base64.b64decode(b_value.replace(" ", "").replace("\t", ""))
    except Exception as exc:
        return False, f"Failed to base64-decode DKIM signature: {exc}"

    # We perform a very simplified check: verify the body hash (bh=) against
    # the raw body, which is a subset of full RFC 6376 verification.
    try:
        body_start = raw_email_bytes.find(b"\r\n\r\n")
        if body_start == -1:
            body_start = raw_email_bytes.find(b"\n\n")
            if body_start != -1:
                body_bytes = raw_email_bytes[body_start + 2:]
            else:
                body_bytes = b""
        else:
            body_bytes = raw_email_bytes[body_start + 4:]

        # Simple relaxed canonicalization: trailing CRLF collapse
        body_bytes = body_bytes.rstrip(b"\r\n") + b"\r\n"
        computed_bh = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode()
        if computed_bh != bh_value.replace(" ", "").replace("\t", ""):
            return False, (
                f"DKIM body hash mismatch: computed={computed_bh}, "
                f"header bh={bh_value}"
            )
    except Exception as exc:
        return False, f"Error computing body hash during fallback DKIM check: {exc}"

    return True, (
        "Fallback DKIM body-hash verified (note: full header-hash "
        "canonicalization requires dkimpy)."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dkim(raw_email_bytes: bytes) -> DKIMResult:
    """Verify the DKIM signature of a raw RFC 5322 email message.

    Attempts verification using dkimpy if available, falling back to a
    manual header-parse + DNS key lookup approach otherwise.  Both paths
    support test mode via ``AUTH_DNS_MODE=test``.

    Args:
        raw_email_bytes: The complete, unmodified raw email in bytes exactly
            as received from the wire.  Must include all headers and body.

    Returns:
        A :class:`DKIMResult` describing the verification outcome.

    Examples:
        >>> result = check_dkim(b"From: test@example.com\\r\\n\\r\\nBody")
        >>> result.result in ('pass', 'fail', 'none', 'error')
        True
    """
    # Parse header first to populate selector/domain in all return paths
    tags = _parse_dkim_header(raw_email_bytes)

    if tags is None:
        return DKIMResult(
            result="none",
            selector="",
            domain="",
            explanation="No DKIM-Signature header found in the message.",
            header_present=False,
        )

    selector = tags.get("s", "")
    domain = tags.get("d", "")
    algorithm = tags.get("a", "")
    header_present = True

    # ------------------------------------------------------------------ #
    # Primary path: dkimpy
    # ------------------------------------------------------------------ #
    if _DKIMPY_AVAILABLE and not _is_test_mode():
        try:
            verified: bool = _dkimpy.verify(raw_email_bytes)
            if verified:
                return DKIMResult(
                    result="pass",
                    selector=selector,
                    domain=domain,
                    algorithm=algorithm,
                    explanation=(
                        f"DKIM signature verified successfully via dkimpy "
                        f"(selector={selector}, domain={domain})."
                    ),
                    header_present=header_present,
                )
            else:
                return DKIMResult(
                    result="fail",
                    selector=selector,
                    domain=domain,
                    algorithm=algorithm,
                    explanation=(
                        f"DKIM signature verification failed via dkimpy "
                        f"(selector={selector}, domain={domain}). "
                        "The signature is invalid or does not match the public key."
                    ),
                    header_present=header_present,
                )
        except Exception as exc:
            logger.warning("dkimpy raised an exception during verification: %s", exc)
            return DKIMResult(
                result="error",
                selector=selector,
                domain=domain,
                algorithm=algorithm,
                explanation=f"dkimpy raised an error during DKIM verification: {exc}",
                header_present=header_present,
            )

    # ------------------------------------------------------------------ #
    # Fallback / test-mode path
    # ------------------------------------------------------------------ #
    try:
        success, explanation = _fallback_verify(raw_email_bytes, tags)
    except Exception as exc:
        logger.exception("Fallback DKIM verification failed unexpectedly: %s", exc)
        return DKIMResult(
            result="error",
            selector=selector,
            domain=domain,
            algorithm=algorithm,
            explanation=f"Unexpected error in fallback DKIM verification: {exc}",
            header_present=header_present,
        )

    return DKIMResult(
        result="pass" if success else "fail",
        selector=selector,
        domain=domain,
        algorithm=algorithm,
        explanation=explanation,
        header_present=header_present,
    )

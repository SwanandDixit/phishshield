"""
dmarc_check.py — PhishShield DMARC Evaluation Module
=====================================================
Looks up and evaluates the DMARC (Domain-based Message Authentication,
Reporting, and Conformance) policy for a given domain, then determines
whether SPF and DKIM authentication results align with the RFC 5322 From:
header domain.

References:
    - RFC 7489: DMARC specification
    - RFC 7208: SPF specification (for alignment rules)
    - RFC 6376: DKIM specification (for alignment rules)
"""

import logging
import os
import re
from dataclasses import dataclass

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test-mode fake DNS data
# ---------------------------------------------------------------------------
_TEST_DMARC_MAP: dict[str, str] = {
    "_dmarc.pass.example.com": (
        "v=DMARC1; p=reject; sp=quarantine; aspf=r; adkim=r; pct=100"
    ),
    "_dmarc.quarantine.example.com": (
        "v=DMARC1; p=quarantine; aspf=s; adkim=s; pct=50"
    ),
    "_dmarc.none-policy.example.com": (
        "v=DMARC1; p=none; aspf=r; adkim=r; pct=100"
    ),
    "_dmarc.strict.example.com": (
        "v=DMARC1; p=reject; aspf=s; adkim=s; pct=100"
    ),
    # Intentionally absent — used to test 'none' result
    # "_dmarc.nodmarc.example.com": ...
}

# Known multi-part TLDs (non-exhaustive but covers common cases)
_MULTI_TLDS: set[str] = {
    "co.uk", "com.au", "com.br", "co.nz", "co.in", "org.uk",
    "net.au", "gov.au", "gov.uk", "ac.uk", "me.uk", "ltd.uk",
    "plc.uk", "net.uk",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class DMARCResult:
    """Structured result of a DMARC policy lookup and alignment evaluation.

    Attributes:
        policy: The DMARC policy as published (``p=`` tag): one of
            'none', 'quarantine', 'reject', or 'unknown'.
        result: Overall DMARC evaluation outcome: 'pass', 'fail', 'none',
            or 'error'.
        spf_aligned: True if the SPF-authenticated domain aligns with the
            RFC 5322 From domain under the applicable aspf mode.
        dkim_aligned: True if the DKIM signing domain aligns with the
            RFC 5322 From domain under the applicable adkim mode.
        raw_record: The raw DMARC TXT record string, or empty string if
            not found.
        from_domain: The domain extracted from the RFC 5322 From: header.
        subdomain_policy: The ``sp=`` policy (if specified), else empty.
        pct: The ``pct=`` percentage (0–100) of messages to apply policy to.
        aspf_mode: Alignment mode for SPF: 'r' (relaxed) or 's' (strict).
        adkim_mode: Alignment mode for DKIM: 'r' (relaxed) or 's' (strict).
        explanation: Human-readable description of the outcome.
    """

    policy: str
    result: str
    spf_aligned: bool
    dkim_aligned: bool
    raw_record: str
    from_domain: str = ""
    subdomain_policy: str = ""
    pct: int = 100
    aspf_mode: str = "r"
    adkim_mode: str = "r"
    explanation: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_test_mode() -> bool:
    """Return True when AUTH_DNS_MODE environment variable equals 'test'."""
    return os.environ.get("AUTH_DNS_MODE", "").strip().lower() == "test"


def _fetch_dmarc_record(domain: str) -> str | None:
    """Fetch the DMARC TXT record from ``_dmarc.{domain}``.

    Args:
        domain: The organisation domain to look up.

    Returns:
        The raw DMARC record string, or None if absent or on error.
    """
    lookup = f"_dmarc.{domain}"

    if _is_test_mode():
        return _TEST_DMARC_MAP.get(lookup)

    try:
        response = dns.resolver.resolve(lookup, "TXT")
        for rdata in response:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.strip().lower().startswith("v=dmarc1"):
                return txt.strip()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        logger.info("No DMARC record found at %s", lookup)
    except dns.exception.Timeout:
        logger.warning("DNS timeout looking up DMARC record for %s", lookup)
    except dns.exception.DNSException as exc:
        logger.warning("DNS error looking up DMARC record for %s: %s", lookup, exc)

    return None


def _parse_dmarc_record(record: str) -> dict[str, str]:
    """Parse a DMARC TXT record string into a tag→value dictionary.

    Tags are case-insensitive per RFC 7489 §6.3.  Values are returned
    as-is (original casing preserved for display; normalise when using).

    Args:
        record: The raw DMARC record string (e.g. ``'v=DMARC1; p=reject; ...'``).

    Returns:
        Dictionary mapping lowercase tag names to their string values.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            tag, _, value = part.partition("=")
            tags[tag.strip().lower()] = value.strip()
    return tags


def _extract_org_domain(domain: str) -> str:
    """Return the organisational domain for *domain* (best-effort).

    RFC 7489 requires the Public Suffix List to determine the org domain.
    This implementation uses a simplified two-label heuristic sufficient
    for most common TLDs.

    Args:
        domain: A fully-qualified domain name.

    Returns:
        The organisational domain (e.g. 'mail.example.co.uk' → 'example.co.uk').
    """
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()

    # Check if last two labels form a known multi-part TLD
    potential_multi = ".".join(parts[-2:])
    if potential_multi in _MULTI_TLDS and len(parts) > 2:
        # org domain = label + multi-TLD
        return ".".join(parts[-3:])

    # Default: org domain = last two labels
    return ".".join(parts[-2:])


def _domains_align(
    from_domain: str, auth_domain: str, mode: str
) -> bool:
    """Determine whether *auth_domain* aligns with *from_domain*.

    Args:
        from_domain: The RFC 5322 From domain (organisational domain).
        auth_domain: The domain authenticated by SPF or DKIM.
        mode: Alignment mode — ``'s'`` (strict) requires an exact match;
              ``'r'`` (relaxed) allows subdomain relationships.

    Returns:
        True if the domains align under the specified mode.
    """
    from_lower = from_domain.strip().lower().rstrip(".")
    auth_lower = auth_domain.strip().lower().rstrip(".")

    if not from_lower or not auth_lower:
        return False

    if mode == "s":
        return from_lower == auth_lower

    # Relaxed: auth domain must be the from domain or a subdomain thereof
    org_from = _extract_org_domain(from_lower)
    org_auth = _extract_org_domain(auth_lower)
    return org_from == org_auth


def _extract_from_domain(from_header: str) -> str:
    """Extract the domain portion from a raw RFC 5322 From: header value.

    Args:
        from_header: The raw value of the From: header, e.g.
            ``'Alice <alice@example.com>'`` or ``'alice@example.com'``.

    Returns:
        The lowercase domain string, or empty string if not parseable.
    """
    # Try angle-bracket form first
    match = re.search(r"<[^@]+@([^>]+)>", from_header)
    if match:
        return match.group(1).strip().lower()

    # Try bare address
    match = re.search(r"[^@\s]+@([^\s,;>\"']+)", from_header)
    if match:
        return match.group(1).strip().lower()

    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dmarc(
    from_header: str,
    spf_result: str,
    spf_domain: str,
    dkim_result: str,
    dkim_domain: str,
) -> DMARCResult:
    """Evaluate DMARC policy and alignment for an incoming message.

    Looks up the DMARC record for the organisational domain found in
    *from_header*, then checks whether the SPF and DKIM authentication
    results align with that domain according to the published ``aspf=``
    and ``adkim=`` alignment modes.

    A DMARC 'pass' requires at least one of SPF or DKIM to both
    authenticate successfully *and* align with the From domain.

    Args:
        from_header: The raw value of the RFC 5322 ``From:`` header.
        spf_result: Result string from SPF check: 'pass', 'fail',
            'softfail', 'neutral', 'none', or 'error'.
        spf_domain: The domain that was authenticated by SPF (i.e. the
            envelope-from / MAIL FROM domain).
        dkim_result: Result string from DKIM check: 'pass', 'fail',
            'none', or 'error'.
        dkim_domain: The ``d=`` domain from the DKIM-Signature header.

    Returns:
        A :class:`DMARCResult` instance describing the policy, alignment
        results, and overall verdict.

    Examples:
        >>> result = check_dmarc(
        ...     "user@pass.example.com",
        ...     "pass", "pass.example.com",
        ...     "pass", "pass.example.com",
        ... )
        >>> result.result
        'pass'
    """
    from_domain = _extract_from_domain(from_header)
    if not from_domain:
        # Use the raw header as a last resort
        from_domain = from_header.strip().lower()

    org_domain = _extract_org_domain(from_domain)

    # Fetch DMARC record (try org domain; RFC 7489 §6.6.3 tree walk)
    raw_record = _fetch_dmarc_record(from_domain)
    lookup_domain = from_domain

    if raw_record is None and from_domain != org_domain:
        raw_record = _fetch_dmarc_record(org_domain)
        lookup_domain = org_domain

    if raw_record is None:
        return DMARCResult(
            policy="none",
            result="none",
            spf_aligned=False,
            dkim_aligned=False,
            raw_record="",
            from_domain=from_domain,
            explanation=(
                f"No DMARC record found for '{from_domain}' "
                f"or its organisational domain '{org_domain}'."
            ),
        )

    tags = _parse_dmarc_record(raw_record)

    # Extract policy tags with RFC-specified defaults
    policy = tags.get("p", "none").lower()
    subdomain_policy = tags.get("sp", "").lower()
    aspf_mode = tags.get("aspf", "r").lower()
    adkim_mode = tags.get("adkim", "r").lower()

    try:
        pct = int(tags.get("pct", "100"))
        pct = max(0, min(100, pct))
    except ValueError:
        pct = 100

    # Normalise valid policy values
    if policy not in ("none", "quarantine", "reject"):
        logger.warning(
            "DMARC record for %s has unrecognised policy '%s'; treating as 'none'.",
            lookup_domain,
            policy,
        )
        policy = "none"

    # Evaluate alignment
    spf_pass = spf_result.lower() == "pass"
    dkim_pass = dkim_result.lower() == "pass"

    spf_aligned = spf_pass and _domains_align(from_domain, spf_domain, aspf_mode)
    dkim_aligned = dkim_pass and _domains_align(from_domain, dkim_domain, adkim_mode)

    # DMARC passes if at least one identifier aligns and its auth passed
    dmarc_passes = spf_aligned or dkim_aligned

    if dmarc_passes:
        result = "pass"
        explanation = (
            f"DMARC evaluation passed for '{from_domain}'. "
            + (f"SPF aligned ({aspf_mode})." if spf_aligned else "")
            + (" " if spf_aligned and dkim_aligned else "")
            + (f"DKIM aligned ({adkim_mode})." if dkim_aligned else "")
        )
    else:
        result = "fail"
        reasons: list[str] = []
        if not spf_pass:
            reasons.append(f"SPF result was '{spf_result}' (not 'pass')")
        elif not spf_aligned:
            reasons.append(
                f"SPF passed but '{spf_domain}' does not align with "
                f"From domain '{from_domain}' (mode={aspf_mode})"
            )
        if not dkim_pass:
            reasons.append(f"DKIM result was '{dkim_result}' (not 'pass')")
        elif not dkim_aligned:
            reasons.append(
                f"DKIM passed but '{dkim_domain}' does not align with "
                f"From domain '{from_domain}' (mode={adkim_mode})"
            )
        explanation = (
            f"DMARC evaluation failed for '{from_domain}'. "
            f"Policy: {policy}. Reasons: {'; '.join(reasons)}."
        )

    return DMARCResult(
        policy=policy,
        result=result,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        raw_record=raw_record,
        from_domain=from_domain,
        subdomain_policy=subdomain_policy,
        pct=pct,
        aspf_mode=aspf_mode,
        adkim_mode=adkim_mode,
        explanation=explanation,
    )

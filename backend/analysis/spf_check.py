"""
spf_check.py — PhishShield SPF Verification Module
====================================================
Evaluates the SPF (Sender Policy Framework) record for a given sender domain
and determines whether a sending IP address is authorized to send mail on
behalf of that domain.

Supports:
  - Full dnspython-based DNS resolution
  - SPF mechanisms: include:, a, mx, ip4:, ip6:, redirect=, all (+/-/~/?)
  - Test mode via AUTH_DNS_MODE=test environment variable
  - Graceful handling of DNS exceptions
"""

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.exception
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test-mode fake DNS data
# ---------------------------------------------------------------------------
_TEST_DNS_MAP: Dict[str, List[str]] = {
    "test-pass.example.com": [
        "v=spf1 ip4:203.0.113.1 ip4:203.0.113.0/24 -all"
    ],
    "test-fail.example.com": [
        "v=spf1 ip4:192.0.2.1 -all"
    ],
    "test-softfail.example.com": [
        "v=spf1 ip4:192.0.2.1 ~all"
    ],
    "test-neutral.example.com": [
        "v=spf1 ip4:192.0.2.1 ?all"
    ],
    "test-include.example.com": [
        "v=spf1 include:test-pass.example.com -all"
    ],
    "test-redirect.example.com": [
        "v=spf1 redirect=test-pass.example.com"
    ],
    "test-none.example.com": [],
}

# Maximum number of DNS lookups (RFC 7208 §4.6.4 limit is 10)
_MAX_DNS_LOOKUPS = 10


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class SPFResult:
    """Structured result of an SPF evaluation.

    Attributes:
        result: One of 'pass', 'fail', 'softfail', 'neutral', 'none', 'error'.
        explanation: Human-readable description of why the result was reached.
        raw_record: The raw SPF TXT record string (empty if not found).
        sending_ip: The IP address that was evaluated.
        domain: The sender domain that was evaluated.
    """

    result: str
    explanation: str
    raw_record: str
    sending_ip: str = ""
    domain: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_test_mode() -> bool:
    """Return True when AUTH_DNS_MODE environment variable is set to 'test'."""
    return os.environ.get("AUTH_DNS_MODE", "").strip().lower() == "test"


def _fetch_txt_records(domain: str) -> List[str]:
    """Retrieve TXT records for *domain*, honouring test mode.

    Args:
        domain: The DNS domain name to query.

    Returns:
        A list of TXT record strings.  Empty list if the domain has no TXT
        records or does not exist.

    Raises:
        dns.exception.DNSException: Propagated for callers that need to
            distinguish timeout from NXDOMAIN, etc.
    """
    if _is_test_mode():
        return _TEST_DNS_MAP.get(domain, [])

    answers: List[str] = []
    try:
        response = dns.resolver.resolve(domain, "TXT")
        for rdata in response:
            # Each rdata may be composed of multiple strings; join them.
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            answers.append(txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass  # Legitimate absence of records
    except dns.exception.Timeout as exc:
        logger.warning("DNS timeout querying %s: %s", domain, exc)
        raise
    except dns.exception.DNSException as exc:
        logger.warning("DNS error querying %s: %s", domain, exc)
        raise
    return answers


def _fetch_spf_record(domain: str) -> Optional[str]:
    """Return the first TXT record that begins with 'v=spf1' for *domain*.

    Args:
        domain: The domain to look up.

    Returns:
        The SPF record string, or None if not present.
    """
    try:
        records = _fetch_txt_records(domain)
    except dns.exception.DNSException:
        return None

    for record in records:
        if record.strip().lower().startswith("v=spf1"):
            return record.strip()
    return None


def _resolve_a_records(domain: str) -> List[str]:
    """Return IPv4 addresses from A records for *domain*.

    Args:
        domain: The domain to resolve.

    Returns:
        List of IPv4 address strings.
    """
    if _is_test_mode():
        return []

    addresses: List[str] = []
    try:
        response = dns.resolver.resolve(domain, "A")
        for rdata in response:
            addresses.append(str(rdata.address))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.DNSException as exc:
        logger.warning("DNS A lookup failed for %s: %s", domain, exc)
    return addresses


def _resolve_aaaa_records(domain: str) -> List[str]:
    """Return IPv6 addresses from AAAA records for *domain*.

    Args:
        domain: The domain to resolve.

    Returns:
        List of IPv6 address strings.
    """
    if _is_test_mode():
        return []

    addresses: List[str] = []
    try:
        response = dns.resolver.resolve(domain, "AAAA")
        for rdata in response:
            addresses.append(str(rdata.address))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.DNSException as exc:
        logger.warning("DNS AAAA lookup failed for %s: %s", domain, exc)
    return addresses


def _resolve_mx_records(domain: str) -> List[str]:
    """Return the hostnames pointed to by MX records for *domain*.

    Args:
        domain: The domain to resolve.

    Returns:
        List of MX target hostname strings.
    """
    if _is_test_mode():
        return []

    hostnames: List[str] = []
    try:
        response = dns.resolver.resolve(domain, "MX")
        for rdata in response:
            hostnames.append(str(rdata.exchange).rstrip("."))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.DNSException as exc:
        logger.warning("DNS MX lookup failed for %s: %s", domain, exc)
    return hostnames


def _ip_in_network(ip_str: str, network_str: str) -> bool:
    """Return True if *ip_str* belongs to *network_str* (CIDR or plain IP).

    Args:
        ip_str: Sending IP address string.
        network_str: IPv4/IPv6 network or host string, optionally with prefix.

    Returns:
        True if the IP is within the network, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        net = ipaddress.ip_network(network_str, strict=False)
        return ip in net
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Core evaluator
# ---------------------------------------------------------------------------

def _evaluate_spf(
    record: str,
    sending_ip: str,
    sender_domain: str,
    lookup_count: List[int],
) -> str:
    """Recursively evaluate an SPF *record* against *sending_ip*.

    Args:
        record: The full SPF record string (starting with 'v=spf1').
        sending_ip: The IP address of the sending MTA.
        sender_domain: The domain from which the SPF record was fetched
            (used for bare 'a' and 'mx' mechanisms).
        lookup_count: A mutable single-element list used to track and cap
            recursive DNS lookups across recursive calls.

    Returns:
        One of 'pass', 'fail', 'softfail', 'neutral', 'none'.
    """
    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        return "none"

    mechanisms = tokens[1:]
    default_qualifier = "?"  # neutral if no mechanism matches

    for mechanism in mechanisms:
        mechanism = mechanism.strip()
        if not mechanism:
            continue

        # Determine qualifier (+/-/~/?)
        qualifier = "+"
        if mechanism[0] in ("+", "-", "~", "?"):
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        mech_lower = mechanism.lower()

        # ------------------------------------------------------------------ #
        # redirect= modifier (not a mechanism; no qualifier)
        # ------------------------------------------------------------------ #
        if mech_lower.startswith("redirect="):
            target = mechanism[len("redirect="):]
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                logger.warning("SPF: too many DNS lookups (permerror)")
                return "fail"
            redirected = _fetch_spf_record(target)
            if redirected is None:
                return "none"
            return _evaluate_spf(redirected, sending_ip, target, lookup_count)

        # ------------------------------------------------------------------ #
        # all mechanism
        # ------------------------------------------------------------------ #
        if mech_lower == "all":
            if qualifier == "+":
                return "pass"
            elif qualifier == "-":
                return "fail"
            elif qualifier == "~":
                return "softfail"
            else:
                return "neutral"

        # ------------------------------------------------------------------ #
        # ip4: mechanism
        # ------------------------------------------------------------------ #
        if mech_lower.startswith("ip4:"):
            network = mechanism[4:]
            if _ip_in_network(sending_ip, network):
                return _qualifier_to_result(qualifier)
            continue

        # ------------------------------------------------------------------ #
        # ip6: mechanism
        # ------------------------------------------------------------------ #
        if mech_lower.startswith("ip6:"):
            network = mechanism[4:]
            if _ip_in_network(sending_ip, network):
                return _qualifier_to_result(qualifier)
            continue

        # ------------------------------------------------------------------ #
        # include: mechanism
        # ------------------------------------------------------------------ #
        if mech_lower.startswith("include:"):
            target = mechanism[len("include:"):]
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                logger.warning("SPF: too many DNS lookups (permerror)")
                return "fail"
            included = _fetch_spf_record(target)
            if included is None:
                continue  # RFC 7208: treat as "not match" on permerror
            sub_result = _evaluate_spf(included, sending_ip, target, lookup_count)
            if sub_result == "pass":
                return _qualifier_to_result(qualifier)
            continue

        # ------------------------------------------------------------------ #
        # a mechanism (bare 'a' or 'a:domain' or 'a/prefix' or 'a:dom/pfx')
        # ------------------------------------------------------------------ #
        if mech_lower == "a" or mech_lower.startswith("a:") or mech_lower.startswith("a/"):
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return "fail"
            target_domain, prefix4, prefix6 = _parse_domain_spec(mechanism[1:] if mech_lower.startswith("a") else sender_domain, sender_domain)
            a_addrs = _resolve_a_records(target_domain)
            for addr in a_addrs:
                net = f"{addr}/{prefix4}" if prefix4 else addr
                if _ip_in_network(sending_ip, net):
                    return _qualifier_to_result(qualifier)
            aaaa_addrs = _resolve_aaaa_records(target_domain)
            for addr in aaaa_addrs:
                net = f"{addr}/{prefix6}" if prefix6 else addr
                if _ip_in_network(sending_ip, net):
                    return _qualifier_to_result(qualifier)
            continue

        # ------------------------------------------------------------------ #
        # mx mechanism (bare 'mx' or 'mx:domain' or 'mx/prefix')
        # ------------------------------------------------------------------ #
        if mech_lower == "mx" or mech_lower.startswith("mx:") or mech_lower.startswith("mx/"):
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return "fail"
            target_domain, prefix4, prefix6 = _parse_domain_spec(mechanism[2:] if mech_lower.startswith("mx") else sender_domain, sender_domain)
            mx_hosts = _resolve_mx_records(target_domain)
            for host in mx_hosts:
                lookup_count[0] += 1
                a_addrs = _resolve_a_records(host)
                for addr in a_addrs:
                    net = f"{addr}/{prefix4}" if prefix4 else addr
                    if _ip_in_network(sending_ip, net):
                        return _qualifier_to_result(qualifier)
                aaaa_addrs = _resolve_aaaa_records(host)
                for addr in aaaa_addrs:
                    net = f"{addr}/{prefix6}" if prefix6 else addr
                    if _ip_in_network(sending_ip, net):
                        return _qualifier_to_result(qualifier)
            continue

        # ------------------------------------------------------------------ #
        # exists: mechanism (basic support — just does DNS A lookup)
        # ------------------------------------------------------------------ #
        if mech_lower.startswith("exists:"):
            target = mechanism[len("exists:"):]
            lookup_count[0] += 1
            if lookup_count[0] > _MAX_DNS_LOOKUPS:
                return "fail"
            a_addrs = _resolve_a_records(target)
            if a_addrs:
                return _qualifier_to_result(qualifier)
            continue

        # Unknown mechanism — skip silently
        logger.debug("SPF: unrecognized mechanism '%s', skipping", mechanism)

    return _qualifier_to_result(default_qualifier)


def _qualifier_to_result(qualifier: str) -> str:
    """Translate an SPF qualifier character to its canonical result string.

    Args:
        qualifier: One of '+', '-', '~', '?'.

    Returns:
        The canonical SPF result string.
    """
    mapping = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
    return mapping.get(qualifier, "neutral")


def _parse_domain_spec(spec: str, default_domain: str):
    """Parse an SPF domain-spec that may include CIDR prefixes.

    Handles forms like:
        (empty)         → (default_domain, None, None)
        :domain         → (domain, None, None)
        /prefix4        → (default_domain, prefix4, None)
        :domain/prefix4 → (domain, prefix4, None)
        :domain/p4//p6  → (domain, p4, p6)

    Args:
        spec: The part of the mechanism after 'a' or 'mx'.
        default_domain: Domain to use when spec does not provide one.

    Returns:
        Tuple of (domain: str, prefix4: Optional[str], prefix6: Optional[str]).
    """
    if not spec or spec == ":":
        return default_domain, None, None

    domain = default_domain
    prefix4: Optional[str] = None
    prefix6: Optional[str] = None

    # Strip leading colon
    if spec.startswith(":"):
        spec = spec[1:]

    # Handle dual-cidr-length: /prefix4//prefix6
    dual_match = re.match(r"^([^/]*)(?:/(\d+))?(?://(\d+))?$", spec)
    if dual_match:
        d, p4, p6 = dual_match.groups()
        if d:
            domain = d
        if p4:
            prefix4 = p4
        if p6:
            prefix6 = p6

    return domain, prefix4, prefix6


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_spf(sending_ip: str, sender_email: str) -> SPFResult:
    """Evaluate the SPF policy for *sender_email* against *sending_ip*.

    The function fetches the SPF TXT record published by the domain part of
    *sender_email*, then walks through its mechanisms in order to determine
    whether *sending_ip* is permitted to send mail for that domain.

    Args:
        sending_ip: The IP address of the SMTP server that delivered the
            message (IPv4 or IPv6 string notation).
        sender_email: The RFC 5321 MAIL FROM address (envelope sender).
            Only the domain part is used for the DNS lookup.

    Returns:
        An :class:`SPFResult` instance capturing the verdict, explanation,
        the raw SPF record found (if any), and context fields.

    Examples:
        >>> result = check_spf("203.0.113.1", "user@test-pass.example.com")
        >>> result.result
        'pass'
    """
    # Extract domain from email address
    if "@" in sender_email:
        domain = sender_email.split("@", 1)[1].strip().lower()
    else:
        domain = sender_email.strip().lower()

    raw_record = ""

    try:
        spf_record = _fetch_spf_record(domain)
    except dns.exception.DNSException as exc:
        return SPFResult(
            result="error",
            explanation=f"DNS error while looking up SPF for {domain}: {exc}",
            raw_record="",
            sending_ip=sending_ip,
            domain=domain,
        )

    if spf_record is None:
        return SPFResult(
            result="none",
            explanation=f"No SPF record found for domain '{domain}'.",
            raw_record="",
            sending_ip=sending_ip,
            domain=domain,
        )

    raw_record = spf_record
    lookup_count: List[int] = [0]

    try:
        verdict = _evaluate_spf(spf_record, sending_ip, domain, lookup_count)
    except Exception as exc:  # Catch unexpected evaluation errors
        logger.exception("Unexpected error evaluating SPF for %s: %s", domain, exc)
        return SPFResult(
            result="error",
            explanation=f"Unexpected error during SPF evaluation: {exc}",
            raw_record=raw_record,
            sending_ip=sending_ip,
            domain=domain,
        )

    explanations: Dict[str, str] = {
        "pass": (
            f"The sending IP {sending_ip} is authorized to send mail for {domain}."
        ),
        "fail": (
            f"The sending IP {sending_ip} is NOT authorized to send mail for "
            f"{domain} and the domain policy is to reject (-all)."
        ),
        "softfail": (
            f"The sending IP {sending_ip} is NOT authorized to send mail for "
            f"{domain}, but the domain policy only suggests rejection (~all)."
        ),
        "neutral": (
            f"The SPF record for {domain} makes no assertion about "
            f"the sending IP {sending_ip}."
        ),
        "none": f"No effective SPF mechanism matched for {domain}.",
    }

    return SPFResult(
        result=verdict,
        explanation=explanations.get(
            verdict, f"SPF evaluation returned '{verdict}' for {domain}."
        ),
        raw_record=raw_record,
        sending_ip=sending_ip,
        domain=domain,
    )

"""
PhishShield – TLS context builder for the API server and SMTP ingest.

Generates a TLS context using server certificates created by scripts/gen_certs.ps1.
Enforces TLS 1.2 as minimum; disables SSLv2, SSLv3, TLS 1.0, TLS 1.1.
"""
from __future__ import annotations

import ssl
from pathlib import Path


def build_server_tls_context(
    cert_file: str,
    key_file: str,
    ca_file: str | None = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """
    Build an SSL context for the HTTPS server.

    Args:
        cert_file:   Path to server certificate (PEM).
        key_file:    Path to server private key (PEM).
        ca_file:     Path to CA certificate bundle (optional).
        min_version: Minimum TLS version (default TLS 1.2).

    Returns:
        Configured ssl.SSLContext.
    """
    if not Path(cert_file).exists():
        raise FileNotFoundError(
            f"TLS certificate not found: {cert_file}\n"
            "Run scripts/gen_certs.ps1 to generate development certificates."
        )
    if not Path(key_file).exists():
        raise FileNotFoundError(f"TLS private key not found: {key_file}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_version
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Load certificate chain and private key
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # Load CA for client verification (optional for dev)
    if ca_file and Path(ca_file).exists():
        ctx.load_verify_locations(cafile=ca_file)

    # Security hardening
    ctx.options |= ssl.OP_NO_COMPRESSION  # CRIME mitigation
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5"
    )

    return ctx


def build_smtp_starttls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """
    Build an SSL context for SMTP STARTTLS.
    Same security settings as the HTTPS server context.
    """
    return build_server_tls_context(cert_file, key_file)


def get_tls_info(ssl_object: ssl.SSLObject | ssl.SSLSocket) -> dict:
    """
    Extract TLS protocol version and cipher suite from an active SSL connection.

    Returns:
        Dict with 'protocol', 'cipher_name', 'cipher_bits'.
    """
    cipher = ssl_object.cipher()
    return {
        "protocol": ssl_object.version() or "unknown",
        "cipher_name": cipher[0] if cipher else "unknown",
        "cipher_bits": cipher[2] if cipher else 0,
        "established": True,
    }

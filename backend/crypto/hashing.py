"""
PhishShield – Message hashing with SHA-256.

Uses only SHA-256 (or stronger); MD5 and SHA-1 are never used for security.
"""
from __future__ import annotations

import hashlib


def sha256_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        Hexadecimal SHA-256 digest string (64 characters).
    """
    return hashlib.sha256(data).hexdigest()


def sha256_hash_bytes(data: bytes) -> bytes:
    """Return SHA-256 digest as raw bytes."""
    return hashlib.sha256(data).digest()


def sha256_file(path: str) -> str:
    """
    Compute SHA-256 of a file, reading in chunks to handle large files.

    Args:
        path: Filesystem path to the file.

    Returns:
        Hex SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_hash(data: bytes, expected_hex: str) -> bool:
    """
    Verify that SHA-256(data) matches the expected hex digest.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channels.
    """
    import hmac as _hmac
    computed = sha256_hash(data)
    # compare_digest is constant-time even for strings
    return _hmac.compare_digest(computed.lower(), expected_hex.lower())

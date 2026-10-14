# PhishShield – Cryptographic Design

## 1. Algorithm Selections & Rationale

### 1.1 AES-256-GCM (At-Rest Encryption)

**Why AES-256-GCM:**
- NIST SP 800-38D approved Authenticated Encryption with Associated Data (AEAD)
- Provides confidentiality (AES-CTR) + integrity + authenticity (GHASH tag) in one primitive
- 256-bit key size: 128-bit security level, quantum-resistant under Grover's algorithm
- GCM authentication tag (128-bit) detects any modification of ciphertext or AAD

**Implementation details:**
- Nonce: 96-bit random per encryption (os.urandom(12)) per NIST recommendation
- No nonce reuse: each call generates a fresh nonce, stored alongside ciphertext
- Key derivation: HKDF-SHA256 derives storage key from master key with domain info
- Master key: 256-bit, loaded from AES_MASTER_KEY env var, never hardcoded

**Why not AES-CBC:** CBC requires separate MAC, vulnerable to padding oracle attacks.
**Why not ChaCha20-Poly1305:** Both are secure; AES-GCM chosen for hardware acceleration.

### 1.2 Ed25519 (Digital Signatures)

**Why Ed25519:**
- Based on Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519
- 128-bit security level with 32-byte keys and 64-byte signatures
- SafeCurves compliant: Curve25519 designed to avoid common implementation pitfalls
- Constant-time implementation in the `cryptography` library (resistant to timing attacks)
- No random nonce required for signing (deterministic: same message + key = same signature)
- ~50µs per signature on modern hardware (10× faster than RSA-2048)

**Why not ECDSA:** ECDSA requires a random nonce; nonce reuse completely breaks security (Sony PS3 attack). Ed25519 is deterministic.
**Why not RSA-PKCS1v15:** Vulnerable to various padding attacks. RSA-PSS is the safe choice if RSA is needed.

### 1.3 RSA-PSS (Alternative Signatures)

**Why RSA-PSS over PKCS1v15:**
- PSS (Probabilistic Signature Scheme) has a tight security proof in the random oracle model
- PKCS1v15 is vulnerable to Bleichenbacher-style attacks
- Parameters: SHA-256 hash, MGF1-SHA256 mask, MAX_LENGTH salt

**Minimum key size:** 2048 bits enforced; 3072 recommended for new deployments.

### 1.4 HMAC-SHA256 (Message Authentication)

**Why HMAC-SHA256:**
- RFC 2104 standard. Provably secure when SHA-256 is a pseudorandom function
- Protects against length-extension attacks (unlike plain SHA-256(key || message))
- 256-bit tag: 128-bit security level
- Constant-time comparison: `hmac.compare_digest()` prevents timing side-channels

**Constant-time rationale:** Byte-by-byte string comparison in Python leaks timing information proportional to where the first differing byte is. `hmac.compare_digest` runs in time proportional to tag length, regardless of where mismatch occurs.

### 1.5 HKDF-SHA256 (Key Derivation)

**Why HKDF:**
- RFC 5869: "Extract-then-Expand" paradigm
- Extract phase: distills entropy from master key material
- Expand phase: produces multiple independent keys with different `info` strings
- Domain separation: `b"phishshield-email-storage"` and `b"phishshield-hmac-auth"` produce independent keys even from the same master key

**Why not PBKDF2 for key derivation:** PBKDF2 is designed for password stretching (slow). HKDF is designed for high-entropy key material (fast, no stretching needed).

**Why PBKDF2 for passwords:** 600,000 iterations makes brute-force expensive; SHA-256 is the hash (NIST 2023 recommendation).

### 1.6 bcrypt (Password Hashing)

**Why bcrypt:**
- Cost factor 12: ~250ms per hash on modern hardware, infeasible to GPU-crack
- Built-in salt: prevents rainbow table attacks
- Adaptive: cost factor can be increased as hardware improves

**Why not SHA-256(password):** Deterministic, GPU-parallelizable, no salt.
**Why not MD5/SHA-1:** Broken for security purposes. PhishShield never uses them.

---

## 2. Replay Protection Design

```
Message: {nonce, timestamp, payload, signature}

Validation:
  1. Verify timestamp ∈ [now - 5min, now + 5min]     → rejects stale/future messages
  2. Query DB: SELECT nonce FROM used_nonces          → rejects replayed nonces
  3. If new: INSERT nonce with expires_at = now + 10min
  4. Verify signature over (nonce, timestamp, payload)

Attack scenarios blocked:
  - Attacker replays a valid message → nonce already in DB
  - Attacker delays message > 5min   → timestamp too old
  - Attacker uses future timestamp   → timestamp too far ahead
  - Attacker modifies message        → signature invalid
```

---

## 3. TLS Configuration

```python
ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # Blocks SSLv3, TLS 1.0, TLS 1.1
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.options |= ssl.OP_NO_COMPRESSION  # CRIME attack mitigation
ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:...")
```

**Forward secrecy:** ECDHE key exchange ensures session keys are ephemeral.
**No compression:** CRIME attack uses TLS compression to oracle-attack secrets.

---

## 4. Security Properties Summary

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| Confidentiality (transit) | TLS 1.2+ | Eavesdropping impossible |
| Confidentiality (rest) | AES-256-GCM | Stored emails unreadable without key |
| Integrity (transit) | TLS MAC | Modification detected |
| Integrity (rest) | AES-GCM tag | Tampered emails rejected on decrypt |
| Authenticity | Ed25519 / HMAC | Origin verified |
| Non-repudiation | Ed25519 | Sender cannot deny signing |
| Replay resistance | Nonce + timestamp | Old messages rejected |
| Auth brute-force | bcrypt + rate limit | Password cracking infeasible |
| Key isolation | HKDF info strings | Compromise of one key ≠ all keys |

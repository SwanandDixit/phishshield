# PhishShield – Threat Model

## 1. System Overview

PhishShield is a secure email gateway that intercepts all incoming emails, analyzes them through multiple security layers, and classifies them as LEGITIMATE, SUSPICIOUS, or MALICIOUS.

**Trust boundaries:**
- External Internet → SMTP ingest (port 2525 with STARTTLS)
- SMTP ingest → Analysis pipeline
- Analysis pipeline → SQLite DB (encrypted at rest)
- Admin browser → HTTPS API (port 8443, TLS 1.2+)

---

## 2. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| External attacker | Can craft any email | Deliver phishing, malware, or cause OPSEC failures |
| Network MitM | Can intercept TCP traffic | Read/modify emails in transit |
| Compromised sending server | Valid SMTP session | Spoof legitimate senders |
| Replay attacker | Captured valid signed messages | Re-deliver old authorized messages |
| Insider threat | DB read access | Read quarantined email content |

---

## 3. Threat Analysis (STRIDE)

### 3.1 Spoofing (Sender Identity)
**Threat:** Attacker sends email claiming to be from a trusted domain.
**Controls:**
- SPF: DNS check authorizes the sending server's IP
- DKIM: Cryptographic signature verifies domain ownership
- DMARC: Policy enforcement + alignment check
- Display-name spoofing detection (regex + Levenshtein distance)
- Homoglyph detection (Unicode normalization + character substitution map)
- Reply-To / Return-Path mismatch detection

### 3.2 Tampering (Message Integrity)
**Threat:** Attacker intercepts and modifies an email in transit.
**Controls:**
- SHA-256 hash of every message (tamper evidence)
- Ed25519 / RSA-PSS digital signatures on trusted messages
- HMAC-SHA256 for partner gateway authentication (constant-time comparison)
- AES-256-GCM encryption with authentication tag (stored emails)
- TLS for transport (protects against passive eavesdropping)

### 3.3 Replay Attacks
**Threat:** Attacker captures a valid, signed email and re-sends it.
**Controls:**
- Every signed message includes a unique nonce (UUID4)
- Timestamp must be within ±5 minutes of server time
- Used nonces stored in DB with TTL (persistent across restarts)
- Second use of any nonce immediately triggers hard override (score=100)

### 3.4 Information Disclosure
**Threat:** Unauthorized access to quarantined email content.
**Controls:**
- All quarantined/stored emails encrypted with AES-256-GCM
- Master key stored only in environment variable (never in code or DB)
- Key derivation with HKDF isolates storage key from master key
- JWT authentication required for all API endpoints
- Rate limiting prevents brute-force against the login endpoint
- bcrypt password hashing with cost factor (resistant to GPU cracking)

### 3.5 Denial of Service
**Threat:** Flood of emails overwhelms the pipeline.
**Controls:**
- Rate limiting: 60 requests/minute per IP (configurable)
- SMTP processing is asynchronous (aiosmtpd + asyncio)
- SQLite with WAL mode handles concurrent reads/writes
- Nonce cache purge prevents unbounded DB growth

### 3.6 Elevation of Privilege
**Threat:** Analyst account gains admin access.
**Controls:**
- Role-based access control: admin vs. analyst
- Admin-only endpoints: release quarantine, delete email, generate keys, retrain model
- JWT claims include role; verified server-side on every request
- No client-side role storage (role re-verified from DB)

---

## 4. Attack Surface

| Interface | Exposure | Protection |
|-----------|---------|------------|
| SMTP port 2525 | Public | STARTTLS, input validation, rate limiting |
| HTTPS API 8443 | Public | TLS 1.2+, JWT auth, CORS, rate limiting |
| React frontend | Browser | HTTPS, CSP headers, XSS-safe rendering |
| SQLite DB | Local file | AES encryption of sensitive data |
| ML model files | Local | No secrets; artifact integrity via hash |

---

## 5. Cryptographic Choices (Summary)

See [CRYPTO_DESIGN.md](CRYPTO_DESIGN.md) for full rationale.

- **AES-256-GCM**: NIST-approved AEAD cipher. 256-bit key exceeds 128-bit security level. GCM tag prevents undetected tampering.
- **Ed25519**: Uses Curve25519 (SafeCurves-compliant). Faster than RSA, constant-time implementation in `cryptography` library.
- **HMAC-SHA256**: RFC 2104. Constant-time comparison (`hmac.compare_digest`) prevents timing attacks.
- **HKDF-SHA256**: RFC 5869. Domain-separated key derivation prevents key reuse across functions.
- **bcrypt**: 2010+ standard for password hashing. Cost factor 12 (configurable). Resistant to GPU/FPGA cracking.

---

## 6. Known Limitations

1. **Development TLS**: Self-signed cert. Browsers will warn. Add a CA-signed cert for production.
2. **SQLite concurrency**: Suitable for demo/development. Use PostgreSQL for production load.
3. **DNS in test mode**: Fake DNS resolver returns predefined results; does not test real-world SPF/DKIM records. Set `AUTH_DNS_MODE=live` for real checks.
4. **ML model**: Trained on SpamAssassin 2002 corpus. Phishing patterns have evolved; re-train on a modern corpus for production use.
5. **SMTP on port 2525**: Real mail servers use port 25 (requires root or CAP_NET_BIND_SERVICE). Use iptables redirect or a proxy for production.
6. **VirusTotal**: Optional (requires `VT_API_KEY`). Without it, attachment hash lookups are skipped.

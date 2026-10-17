"""
PhishShield – dataset download / synthetic generation script.

Downloads the SpamAssassin public corpus when network is available;
falls back to a clearly-labelled synthetic dataset when it is not.
Output: backend/ml/data/emails.csv  (columns: text, label, source)
"""

from __future__ import annotations

import io
import random
import string
import tarfile
from pathlib import Path

import pandas as pd
import requests

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent
DATA_DIR = _HERE / "data"
OUTPUT_CSV = DATA_DIR / "emails.csv"

# ---------------------------------------------------------------------------
# SpamAssassin corpus URLs
# ---------------------------------------------------------------------------
CORPUS_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
HAM_ARCHIVE = "20021010_easy_ham.tar.bz2"
SPAM_ARCHIVE = "20021010_spam.tar.bz2"
DOWNLOAD_TIMEOUT = 30  # seconds

# ---------------------------------------------------------------------------
# Synthetic data templates
# ---------------------------------------------------------------------------
PHISHING_TEMPLATES: list[str] = [
    "Your account has been compromised. Click here to verify: http://paypa1.com/verify",
    "URGENT: Your password expires in 24 hours. Login at: http://192.168.1.1/login",
    "We detected unusual sign-in activity. Confirm your identity immediately: http://secure-bank-update.net/auth",
    "Your PayPal account is LIMITED. Act now to restore access: http://paypa1-support.com/restore",
    "Dear customer, your Netflix subscription will be suspended. Update billing: http://netf1ix-billing.com",
    "Your Amazon account has been locked due to suspicious activity. Verify: http://amaz0n-verify.net/account",
    "ALERT: Unauthorized access to your bank account! Secure it now: http://172.16.0.1/secure",
    "Congratulations! You've won a $1000 gift card. Claim at: http://claimprize-now.com/gift",
    "Your Apple ID has been disabled. Click to unlock: http://app1e-id-support.com/unlock",
    "Important security update required. Login to confirm: http://microsoft-secure-update.net/verify",
    "You have a pending tax refund of $500. Verify your details: http://irs-refund-portal.net",
    "Your credit card was charged $299. If not you, dispute here: http://cardfraud-alert.com/dispute",
    "ACTION REQUIRED: Your email account will be deleted in 24 hours. Verify: http://mail-verify-now.com",
    "Limited time offer! Get a FREE iPhone 15. Register now: http://free-iphone15-promo.xyz",
    "Your social security number has been flagged. Contact us immediately: http://ssa-verify-secure.net",
    "FINAL NOTICE: Your account balance is overdue. Pay now to avoid suspension: http://billing-urgent.net",
    "You have 1 unread security message. View it here: http://secure-message-center.net/inbox",
    "Your DHL package could not be delivered. Confirm address: http://dhl-tracking-update.net",
    "HR Department: Please update your direct deposit information IMMEDIATELY: http://hrportal-update.com",
    "Your Google account password was changed. If not you, click here: http://google-alert-verify.com",
    "Wire transfer of $10,000 pending your approval. Confirm: http://wire-confirm-now.net",
    "URGENT: IRS Notice – You owe back taxes. Avoid arrest: http://irs-payment-portal.net",
    "Your Dropbox account storage is full. Upgrade for FREE now: http://dropbox-upgrade-offer.com",
    "Security breach detected on your account! Reset password: http://account-breach-reset.net",
    "You are eligible for a COVID relief payment. Claim $1400 here: http://covid-relief-claim.net",
    "Your subscription renews tomorrow for $99.99. Cancel at: http://cancel-subscription-now.com",
    "VERIFY YOUR IDENTITY NOW or your account will be permanently closed: http://identity-verify-urgent.com",
    "Click here to unsubscribe or your account will be charged $49.99/month: http://unsub-billing.net",
    "Your password will expire in 12 hours. Update immediately: http://password-expire-alert.com",
    "Congratulations! Your loan of $25,000 is approved. Confirm details: http://loan-approve-now.com",
]

PHISHING_VARIATIONS: list[str] = [
    "Dear valued user, we noticed a login attempt from {location}. Verify your identity: http://{domain}/verify",
    "Your account #ACCT-{num} requires immediate attention. Click: http://{domain}/action",
    "URGENT NOTICE: Transaction of ${amount} was declined. Fix now: http://{domain}/fix",
    "Security Alert from {bank}: Unusual activity detected. Confirm: http://{domain}/confirm",
    "Your {service} account has been compromised. Reset password at http://{domain}/reset",
]

LEGITIMATE_TEMPLATES: list[str] = [
    "Hi team, please find the meeting notes attached. Best regards, John",
    "Your order #12345 has shipped. Track at ups.com/track",
    "Reminder: The project deadline is next Friday. Please submit your deliverables.",
    "Monthly newsletter: Check out our latest blog posts and company updates.",
    "Hi Sarah, just following up on the report you mentioned last week. Let me know if you need help.",
    "Your GitHub pull request #234 has been merged by maintainer@example.com",
    "Invoice #INV-2023-0045 from Acme Corp is attached. Payment due in 30 days.",
    "Meeting agenda for Monday: Q4 planning, budget review, and team updates. See you at 10am.",
    "Thank you for attending the webinar. Here's the recording link: company.zoom.us/recording",
    "Your flight booking confirmation: AA1234 departing JFK on Dec 15 at 8:45am.",
    "Happy birthday from the whole team! Hope you have a wonderful day.",
    "The quarterly report is now available on the intranet. Login to download.",
    "JIRA ticket PROJ-456 has been assigned to you. View details in the project dashboard.",
    "Your doctor appointment is confirmed for November 20th at 2:30 PM. Call to reschedule.",
    "Welcome to the team! Your onboarding documents have been emailed to your work address.",
    "Library book reminder: 'Clean Code' is due for return in 3 days.",
    "Your AWS bill for October is ready. Total: $45.23. View at aws.amazon.com/billing",
    "Slack notification: @dev-team mentioned you in #backend channel.",
    "Your annual review is scheduled for Dec 1. Please prepare a self-evaluation.",
    "Course completion certificate: Python for Data Science – well done!",
    "Server maintenance window: Sat 2am-4am UTC. Brief outage expected.",
    "Minutes from the board meeting on Nov 5th are now available on SharePoint.",
    "Your domain example.com will expire in 30 days. Renew at your registrar.",
    "CI/CD pipeline: Build #789 succeeded. All 142 tests passed.",
    "Reminder: Please complete your compliance training by end of month.",
    "Your Spotify Premium renews Dec 1 for $9.99. Manage at spotify.com/account",
    "Hi Bob, I've attached the updated slide deck for tomorrow's presentation.",
    "New comment on your Stack Overflow answer: Great explanation, thanks!",
    "Your backup completed successfully. 3.2 GB stored to OneDrive.",
    "Office closed Dec 24–26 for the holidays. Emergency contact: ops@company.com",
]

LEGITIMATE_VARIATIONS: list[str] = [
    "Hi {name}, your {item} order has been confirmed. Expected delivery: {date}.",
    "Team update: {project} is on track. Next milestone: {milestone}.",
    "Your {service} subscription receipt for {month}. Amount: ${amount}.",
    "{name}, please review the attached document and provide feedback by {date}.",
    "Reminder: {event} starts in 1 hour. Join via the calendar invite.",
]

# ---------------------------------------------------------------------------
# Helpers – synthetic data generation
# ---------------------------------------------------------------------------

_LOCATIONS = ["Russia", "China", "Brazil", "Nigeria", "unknown location", "127.0.0.1"]
_DOMAINS = [
    "paypa1-secure.net", "amaz0n-verify.com", "192.168.0.1",
    "secure-login-now.xyz", "account-alert-secure.com",
]
_BANKS = ["Chase", "Bank of America", "Wells Fargo", "Citibank", "HSBC"]
_SERVICES = ["Netflix", "Amazon", "PayPal", "Google", "Apple", "Spotify", "Dropbox"]
_NAMES = ["Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Hank"]
_ITEMS = ["laptop", "headphones", "keyboard", "monitor", "webcam", "chair"]
_PROJECTS = ["Phoenix", "Orion", "Titan", "Atlas", "Nova", "Apex"]
_MILESTONES = ["QA review", "stakeholder demo", "beta release", "code freeze"]
_MONTHS = ["January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]
_EVENTS = ["all-hands meeting", "design review", "sprint planning", "1:1 with manager"]


def _rand_num(low: int = 100, high: int = 9999) -> str:
    return str(random.randint(low, high))


def _rand_date() -> str:
    return f"{random.choice(['Mon', 'Tue', 'Wed', 'Thu', 'Fri'])}, {random.randint(1, 28)} {random.choice(_MONTHS)}"


def _expand_phishing(template: str) -> str:
    """Fill in {placeholders} in a phishing variation template."""
    return template.format(
        location=random.choice(_LOCATIONS),
        domain=random.choice(_DOMAINS),
        num=_rand_num(),
        amount=_rand_num(50, 5000),
        bank=random.choice(_BANKS),
        service=random.choice(_SERVICES),
    )


def _expand_legitimate(template: str) -> str:
    """Fill in {placeholders} in a legitimate variation template."""
    return template.format(
        name=random.choice(_NAMES),
        item=random.choice(_ITEMS),
        project=random.choice(_PROJECTS),
        milestone=random.choice(_MILESTONES),
        service=random.choice(_SERVICES),
        month=random.choice(_MONTHS),
        amount=_rand_num(5, 200),
        date=_rand_date(),
        event=random.choice(_EVENTS),
    )


def _add_noise(text: str) -> str:
    """Append a short random suffix to avoid identical duplicate rows."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{text} [ref:{suffix}]"


def generate_synthetic_dataset(n_phishing: int = 3000, n_legit: int = 3000) -> pd.DataFrame:
    """
    Generate a synthetic email dataset when the real corpus is unavailable.

    Parameters
    ----------
    n_phishing:
        Number of phishing email rows to generate.
    n_legit:
        Number of legitimate email rows to generate.

    Returns
    -------
    pd.DataFrame
        DataFrame with columns ``text``, ``label``, ``source``.
    """
    print("[SYNTHETIC] Generating synthetic dataset — NOT real email data.")
    print(f"[SYNTHETIC] Target: {n_phishing} phishing + {n_legit} legitimate emails.")

    records: list[dict[str, object]] = []

    # ---- Phishing rows ----
    all_phishing = PHISHING_TEMPLATES + [
        _expand_phishing(t) for t in PHISHING_VARIATIONS * 20
    ]
    for _ in range(n_phishing):
        base = random.choice(all_phishing)
        records.append({"text": _add_noise(base), "label": 1, "source": "synthetic"})

    # ---- Legitimate rows ----
    all_legit = LEGITIMATE_TEMPLATES + [
        _expand_legitimate(t) for t in LEGITIMATE_VARIATIONS * 20
    ]
    for _ in range(n_legit):
        base = random.choice(all_legit)
        records.append({"text": _add_noise(base), "label": 0, "source": "synthetic"})

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[SYNTHETIC] Generated {len(df)} rows (label distribution: "
          f"{df['label'].value_counts().to_dict()}).")
    return df


# ---------------------------------------------------------------------------
# Helpers – SpamAssassin corpus download
# ---------------------------------------------------------------------------

def _download_archive(filename: str) -> bytes:
    """
    Download a single SpamAssassin corpus archive.

    Parameters
    ----------
    filename:
        Archive filename (e.g. ``20021010_spam.tar.bz2``).

    Returns
    -------
    bytes
        Raw archive content.

    Raises
    ------
    requests.RequestException
        If the download fails for any reason.
    """
    url = CORPUS_BASE + filename
    print(f"[DOWNLOAD] Fetching {url} …")
    resp = requests.get(url, timeout=DOWNLOAD_TIMEOUT, stream=True)
    resp.raise_for_status()
    chunks: list[bytes] = []
    for chunk in resp.iter_content(chunk_size=65536):
        if chunk:
            chunks.append(chunk)
    data = b"".join(chunks)
    print(f"[DOWNLOAD] {filename}: {len(data):,} bytes downloaded.")
    return data


def _extract_emails_from_archive(data: bytes) -> list[str]:
    """
    Extract plain-text email bodies from a bz2-compressed tar archive.

    Parameters
    ----------
    data:
        Raw bytes of the ``.tar.bz2`` archive.

    Returns
    -------
    list[str]
        List of email text strings.
    """
    emails: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            try:
                content = f.read().decode("latin-1", errors="replace")
                emails.append(content[:4000])  # truncate very long emails
            except Exception as exc:  # noqa: BLE001
                print(f"[WARN] Could not read {member.name}: {exc}")
    return emails


def download_spamassassin_corpus() -> pd.DataFrame:
    """
    Download the SpamAssassin public corpus and return a DataFrame.

    Returns
    -------
    pd.DataFrame
        DataFrame with columns ``text``, ``label``, ``source``.

    Raises
    ------
    RuntimeError
        If either archive fails to download.
    """
    ham_data = _download_archive(HAM_ARCHIVE)
    spam_data = _download_archive(SPAM_ARCHIVE)

    print("[PARSE] Extracting ham emails …")
    ham_emails = _extract_emails_from_archive(ham_data)
    print(f"[PARSE] Extracted {len(ham_emails)} ham emails.")

    print("[PARSE] Extracting spam emails …")
    spam_emails = _extract_emails_from_archive(spam_data)
    print(f"[PARSE] Extracted {len(spam_emails)} spam emails.")

    records: list[dict[str, object]] = (
        [{"text": t, "label": 0, "source": "spamassassin"} for t in ham_emails]
        + [{"text": t, "label": 1, "source": "spamassassin"} for t in spam_emails]
    )
    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[PARSE] Total corpus rows: {len(df)} "
          f"(label distribution: {df['label'].value_counts().to_dict()}).")
    return df


# ---------------------------------------------------------------------------
# Main entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    """Download the real corpus or fall back to a synthetic dataset, then save to CSV."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    df: pd.DataFrame

    try:
        print("=" * 60)
        print("PhishShield – Dataset Preparation")
        print("=" * 60)
        print("[INFO] Attempting to download SpamAssassin public corpus …")
        df = download_spamassassin_corpus()
        print("[INFO] ✓ Using REAL SpamAssassin corpus data.")
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Download failed: {exc}")
        print("[INFO] Falling back to SYNTHETIC dataset.")
        print("=" * 60)
        df = generate_synthetic_dataset()
        print("[INFO] ✓ Using SYNTHETIC data (clearly labelled in 'source' column).")

    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[INFO] Dataset saved → {OUTPUT_CSV}")
    print(f"[INFO] Rows: {len(df)}  |  Columns: {list(df.columns)}")
    print("=" * 60)


if __name__ == "__main__":
    main()

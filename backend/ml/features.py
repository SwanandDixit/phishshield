"""
PhishShield – Feature Extraction Module.

Provides:
  - extract_text_features   : TF-IDF vectorisation
  - extract_url_features    : URL-based heuristics
  - extract_header_features : SPF/DKIM/DMARC and reply-to mismatch
  - extract_urgency_features: Urgency language, money refs, caps ratio
  - extract_structural_features: HTML tag counts, link/image/attachment counts

All extractors integrate into a single sklearn-compatible Pipeline via a
FeatureUnion of custom transformers.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import numpy as np
from numpy.typing import NDArray
from scipy.sparse import hstack, issparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: URL shortener domains (non-exhaustive)
URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cli.gs", "pic.gd", "digg.com", "tiny.cc", "lnkd.in",
    "db.tt", "qr.ae", "cur.lv", "ity.im", "q.gs", "po.st", "bc.vc",
    "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us", "u.bb",
    "yourls.org", "prettylinkpro.com", "scrnch.me", "filoops.info",
    "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im",
    "link.zip.net",
})

#: TLDs commonly associated with phishing or abuse
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".xyz", ".top", ".club", ".online", ".site", ".tech",
    ".info", ".pw", ".cc", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".loan", ".win", ".bid", ".review", ".science",
    ".work", ".party", ".racing", ".men", ".download",
})

#: Urgency / phishing language triggers
URGENCY_WORDS: list[str] = [
    "urgent", "immediately", "expire", "expires", "expiring",
    "suspend", "suspended", "suspension", "verify", "verification",
    "confirm", "confirmation", "login", "password", "account",
    "click", "update", "limited time", "act now", "action required",
    "security alert", "unauthorized", "compromised", "breach",
    "locked", "blocked", "disabled", "validate", "reactivate",
    "required", "mandatory", "last chance", "final notice",
    "warning", "alert", "access denied", "will be closed",
]

#: Money / financial reference patterns
MONEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\s?\d+", re.IGNORECASE),
    re.compile(r"\d+\s?(?:dollars?|usd|eur|gbp|€|£)", re.IGNORECASE),
    re.compile(r"(?:refund|prize|reward|payment|transfer|wire)\s+of", re.IGNORECASE),
]

#: HTML tag detector
_HTML_TAG_RE = re.compile(r"<[^>]+>")
#: Anchor tag href extractor
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
#: img src extractor
_IMG_RE = re.compile(r'<img\b[^>]*>', re.IGNORECASE)
#: URL detector (broad)
_URL_RE = re.compile(
    r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE
)
#: IPv4 address in URL host
_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


# ---------------------------------------------------------------------------
# URL feature extraction
# ---------------------------------------------------------------------------

def extract_url_features(text: str) -> dict[str, float]:
    """
    Extract URL-based heuristic features from email text.

    Parameters
    ----------
    text:
        Raw email body / full message text.

    Returns
    -------
    dict[str, float]
        Dictionary with keys:

        * ``url_count``            – total number of URLs found
        * ``ip_urls``              – URLs whose host is an IPv4 address
        * ``shortener_urls``       – URLs using a known shortener service
        * ``https_ratio``          – fraction of URLs using HTTPS (0.0–1.0)
        * ``suspicious_tld_count`` – URLs with a suspicious TLD
        * ``avg_url_length``       – average character length of URLs
    """
    urls: list[str] = _URL_RE.findall(text)
    n = len(urls)

    if n == 0:
        return {
            "url_count": 0.0,
            "ip_urls": 0.0,
            "shortener_urls": 0.0,
            "https_ratio": 0.0,
            "suspicious_tld_count": 0.0,
            "avg_url_length": 0.0,
        }

    ip_count = 0
    shortener_count = 0
    https_count = 0
    suspicious_tld = 0
    total_len = 0

    for url in urls:
        total_len += len(url)
        if url.lower().startswith("https://"):
            https_count += 1
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            # Strip leading www.
            host_clean = re.sub(r"^www\.", "", host.lower())
            if _IP_RE.match(host):
                ip_count += 1
            if host_clean in URL_SHORTENERS:
                shortener_count += 1
            # Check TLD
            parts = host_clean.rsplit(".", 1)
            tld = f".{parts[-1]}" if len(parts) > 1 else ""
            if tld in SUSPICIOUS_TLDS:
                suspicious_tld += 1
        except Exception:  # noqa: BLE001
            pass

    return {
        "url_count": float(n),
        "ip_urls": float(ip_count),
        "shortener_urls": float(shortener_count),
        "https_ratio": https_count / n,
        "suspicious_tld_count": float(suspicious_tld),
        "avg_url_length": total_len / n,
    }


# ---------------------------------------------------------------------------
# Header feature extraction
# ---------------------------------------------------------------------------

def extract_header_features(header_dict: dict[str, str] | None = None) -> dict[str, float]:
    """
    Extract email authentication header features.

    Parameters
    ----------
    header_dict:
        Mapping of header name → header value (case-insensitive matching
        is applied internally).  Pass ``None`` or ``{}`` if headers are
        unavailable; all features will be 0.

    Returns
    -------
    dict[str, float]
        Dictionary with keys:

        * ``spf_pass``               – 1.0 if SPF result is *pass*, else 0.0
        * ``dkim_pass``              – 1.0 if DKIM result is *pass*, else 0.0
        * ``dmarc_pass``             – 1.0 if DMARC result is *pass*, else 0.0
        * ``has_reply_to_mismatch``  – 1.0 if Reply-To domain differs from
                                       From domain, else 0.0
    """
    if not header_dict:
        return {
            "spf_pass": 0.0,
            "dkim_pass": 0.0,
            "dmarc_pass": 0.0,
            "has_reply_to_mismatch": 0.0,
        }

    # Normalise keys to lower-case for lookup
    headers: dict[str, str] = {k.lower(): v for k, v in header_dict.items()}

    def _auth_result(key: str) -> float:
        val = headers.get(key, "").lower()
        return 1.0 if "pass" in val else 0.0

    spf = _auth_result("received-spf") or _auth_result("spf")
    dkim = _auth_result("dkim-signature") or _auth_result("dkim")

    # DMARC is typically in Authentication-Results
    auth_results = headers.get("authentication-results", "")
    dmarc = 1.0 if re.search(r"dmarc\s*=\s*pass", auth_results, re.IGNORECASE) else 0.0

    # Reply-To vs From domain mismatch
    from_val = headers.get("from", "")
    reply_to_val = headers.get("reply-to", "")
    mismatch = 0.0
    if from_val and reply_to_val:
        def _domain(addr: str) -> str:
            m = re.search(r"@([\w.\-]+)", addr)
            return m.group(1).lower() if m else ""

        if _domain(from_val) != _domain(reply_to_val):
            mismatch = 1.0

    return {
        "spf_pass": spf,
        "dkim_pass": dkim,
        "dmarc_pass": dmarc,
        "has_reply_to_mismatch": mismatch,
    }


# ---------------------------------------------------------------------------
# Urgency feature extraction
# ---------------------------------------------------------------------------

def extract_urgency_features(text: str) -> dict[str, float]:
    """
    Extract urgency/social-engineering signals from email text.

    Parameters
    ----------
    text:
        Raw email body / full message text.

    Returns
    -------
    dict[str, float]
        Dictionary with keys:

        * ``urgency_word_count``  – number of urgency/phishing keywords found
        * ``money_ref_count``     – number of money/financial references
        * ``exclamation_count``   – number of exclamation marks
        * ``caps_ratio``          – ratio of upper-case letters to all letters
    """
    lower = text.lower()

    urgency_count = sum(1 for w in URGENCY_WORDS if w in lower)
    money_count = sum(len(p.findall(text)) for p in MONEY_PATTERNS)
    exclamation_count = text.count("!")

    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(1 for c in letters if c.isupper()) / max(len(letters), 1)

    return {
        "urgency_word_count": float(urgency_count),
        "money_ref_count": float(money_count),
        "exclamation_count": float(exclamation_count),
        "caps_ratio": caps_ratio,
    }


# ---------------------------------------------------------------------------
# Structural feature extraction
# ---------------------------------------------------------------------------

def extract_structural_features(text: str, subject: str = "") -> dict[str, float]:
    """
    Extract structural / layout features from email text.

    Parameters
    ----------
    text:
        Raw email body / full message text.
    subject:
        Email subject line (may be empty).

    Returns
    -------
    dict[str, float]
        Dictionary with keys:

        * ``subject_length``   – character length of the subject
        * ``body_length``      – character length of the body text
        * ``html_tag_count``   – number of HTML tags in the body
        * ``link_count``       – number of hyperlinks (``<a href>``)
        * ``image_count``      – number of ``<img>`` tags
        * ``attachment_count`` – heuristic count of attachment references
    """
    html_tags = len(_HTML_TAG_RE.findall(text))
    links = len(_HREF_RE.findall(text)) + len(_URL_RE.findall(text))
    images = len(_IMG_RE.findall(text))

    # Attachment heuristics: common MIME boundary indicators or filenames
    attachment_count = len(re.findall(
        r"(?:Content-Disposition:\s*attachment|filename=[\"'][^\"']+\.[a-z]{2,4}[\"'])",
        text, re.IGNORECASE,
    ))

    return {
        "subject_length": float(len(subject)),
        "body_length": float(len(text)),
        "html_tag_count": float(html_tags),
        "link_count": float(links),
        "image_count": float(images),
        "attachment_count": float(attachment_count),
    }


# ---------------------------------------------------------------------------
# TF-IDF text features
# ---------------------------------------------------------------------------

def extract_text_features() -> TfidfVectorizer:
    """
    Construct a TF-IDF vectoriser with phishing-optimised parameters.

    Returns
    -------
    TfidfVectorizer
        Unfitted vectoriser ready to be embedded in a Pipeline.

    Notes
    -----
    Parameters chosen:

    * ``sublinear_tf=True``        – dampens very frequent terms
    * ``max_features=10000``       – vocabulary cap to control dimensionality
    * ``ngram_range=(1, 2)``       – unigrams + bigrams for phrase detection
    * ``stop_words='english'``     – remove common English stopwords
    """
    return TfidfVectorizer(
        sublinear_tf=True,
        max_features=10_000,
        ngram_range=(1, 2),
        stop_words="english",
        strip_accents="unicode",
        analyzer="word",
        min_df=2,
    )


# ---------------------------------------------------------------------------
# Custom sklearn Transformers
# ---------------------------------------------------------------------------

class TextSelector(BaseEstimator, TransformerMixin):
    """
    Select the raw text column from a list of dicts or a DataFrame.

    Parameters
    ----------
    key:
        The key / column name holding the email text (default ``'text'``).
    """

    def __init__(self, key: str = "text") -> None:
        self.key = key

    def fit(self, X: Any, y: Any = None) -> "TextSelector":  # noqa: N803
        return self

    def transform(self, X: Any) -> list[str]:  # noqa: N803
        """Return a list of strings extracted from *X*."""
        if hasattr(X, "__getitem__"):
            try:
                return list(X[self.key])
            except (KeyError, TypeError):
                pass
        # Assume X is already an iterable of strings
        return list(X)


class EngineeredFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    Combine URL, urgency, and structural features into a 2-D NumPy array.

    Each input sample must be a ``dict`` or a ``pandas.Series`` with at
    least a ``'text'`` key.  Header features (``header_features_dict``) are
    read from the key ``'headers'`` if present, otherwise defaulted to zero.

    Feature order (must stay stable for model interpretability):

    URL (6) + header (4) + urgency (4) + structural (6) = **20 features**
    """

    #: Ordered list of engineered feature names (used for interpretability).
    FEATURE_NAMES: list[str] = [
        # URL
        "url_count", "ip_urls", "shortener_urls",
        "https_ratio", "suspicious_tld_count", "avg_url_length",
        # Header
        "spf_pass", "dkim_pass", "dmarc_pass", "has_reply_to_mismatch",
        # Urgency
        "urgency_word_count", "money_ref_count",
        "exclamation_count", "caps_ratio",
        # Structural
        "subject_length", "body_length", "html_tag_count",
        "link_count", "image_count", "attachment_count",
    ]

    def fit(self, X: Any, y: Any = None) -> "EngineeredFeatureTransformer":  # noqa: N803
        return self

    def transform(self, X: Any) -> NDArray[np.float64]:  # noqa: N803
        """
        Transform a collection of samples into a 2-D feature matrix.

        Parameters
        ----------
        X:
            Iterable of ``dict``-like objects (each with at minimum a
            ``'text'`` key, optionally ``'subject'`` and ``'headers'``).

        Returns
        -------
        NDArray[np.float64]
            Shape ``(n_samples, 20)``.
        """
        rows: list[list[float]] = []
        for sample in X:
            if isinstance(sample, str):
                text = sample
                subject = ""
                headers: dict[str, str] = {}
            else:
                text = sample.get("text", "") if hasattr(sample, "get") else str(sample)
                subject = sample.get("subject", "") if hasattr(sample, "get") else ""
                headers = sample.get("headers", {}) if hasattr(sample, "get") else {}

            url_f = extract_url_features(text)
            hdr_f = extract_header_features(headers)
            urg_f = extract_urgency_features(text)
            str_f = extract_structural_features(text, subject)

            row = (
                [url_f[k] for k in [
                    "url_count", "ip_urls", "shortener_urls",
                    "https_ratio", "suspicious_tld_count", "avg_url_length",
                ]]
                + [hdr_f[k] for k in [
                    "spf_pass", "dkim_pass", "dmarc_pass", "has_reply_to_mismatch",
                ]]
                + [urg_f[k] for k in [
                    "urgency_word_count", "money_ref_count",
                    "exclamation_count", "caps_ratio",
                ]]
                + [str_f[k] for k in [
                    "subject_length", "body_length", "html_tag_count",
                    "link_count", "image_count", "attachment_count",
                ]]
            )
            rows.append(row)

        return np.array(rows, dtype=np.float64)


class RawTextTransformer(BaseEstimator, TransformerMixin):
    """
    Pass raw text samples through to the TF-IDF vectoriser.

    When the pipeline input is a list of dicts, this transformer
    extracts the ``'text'`` field; when the input is already a list of
    strings it passes them through unchanged.
    """

    def fit(self, X: Any, y: Any = None) -> "RawTextTransformer":  # noqa: N803
        return self

    def transform(self, X: Any) -> list[str]:  # noqa: N803
        """Return a flat list of text strings."""
        result: list[str] = []
        for sample in X:
            if isinstance(sample, str):
                result.append(sample)
            elif hasattr(sample, "get"):
                result.append(sample.get("text", ""))
            else:
                result.append(str(sample))
        return result


# ---------------------------------------------------------------------------
# Combined feature pipeline
# ---------------------------------------------------------------------------

def build_feature_union() -> FeatureUnion:
    """
    Build a :class:`sklearn.pipeline.FeatureUnion` combining TF-IDF text
    features with engineered heuristic features.

    The union produces a sparse/dense matrix suitable for downstream
    estimators.  Input to the union must be an iterable of ``dict``-like
    objects with at least a ``'text'`` key.

    Returns
    -------
    FeatureUnion
        Unfitted feature union.
    """
    tfidf_pipeline = Pipeline([
        ("extract_text", RawTextTransformer()),
        ("tfidf", extract_text_features()),
    ])

    return FeatureUnion(
        transformer_list=[
            ("tfidf_text", tfidf_pipeline),
            ("engineered", EngineeredFeatureTransformer()),
        ]
    )


def build_full_pipeline(classifier: Any) -> Pipeline:
    """
    Wrap the feature union and a classifier into a single end-to-end Pipeline.

    Parameters
    ----------
    classifier:
        Any sklearn-compatible estimator (e.g. ``VotingClassifier``).

    Returns
    -------
    Pipeline
        Unfitted pipeline.
    """
    return Pipeline([
        ("features", build_feature_union()),
        ("clf", classifier),
    ])

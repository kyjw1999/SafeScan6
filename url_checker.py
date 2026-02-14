import re
from urllib.parse import unquote, urlparse

DOMAIN_SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "security",
    "account",
    "password",
    "confirm",
    "signin",
    "alert",
    "support",
    "billing",
    "invoice",
    "payment",
    "bank",
    "wallet",
    "otp",
    "free",
    "premium",
    "bonus",
    "gift",
    "reward",
    "claim",
    "winner",
    "win",
]

PATH_SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "confirm",
    "signin",
    "reset",
    "otp",
    "code",
    "bank",
    "wallet",
    "billing",
    "invoice",
    "payment",
    "gift",
    "prize",
    "reward",
    "suspend",
    "suspended",
    "unlock",
    "recover",
    "urgent",
    "alert",
    "free",
    "premium",
    "gift",
    "bonus",
    "claim",
    "winner",
    "win",
]

EXPLICIT_PHISHING_TOKENS = {
    "phish",
    "phishing",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
}

RISKY_TLDS = {
    "xyz",
    "top",
    "icu",
    "site",
    "click",
    "live",
    "tk",
    "monster",
    "work",
    "buzz",
    "rest",
    "fit",
    "gq",
    "country",
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

BRAND_ALLOWLIST = {
    # If a domain contains these brand strings but isn't an official domain suffix, add extra risk.
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.uk", "google.ae", "googleusercontent.com", "googleapis.com", "g.co"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ae"},
    "netflix": {"netflix.com"},
}

AUTH_TERMS = {
    "login",
    "signin",
    "verify",
    "account",
    "password",
    "secure",
    "security",
    "update",
}

INCENTIVE_TERMS = {
    "free",
    "premium",
    "gift",
    "bonus",
    "prize",
    "reward",
    "winner",
    "win",
    "claim",
}


def _clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))


def _token_match(text: str, token: str) -> bool:
    if not text or not token:
        return False
    # Full-token match when possible; fallback to substring for short tokens.
    if len(token) <= 3:
        return token in text
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", text))


def check_url(raw_url: str):
    """Return (safe: bool, report: dict) with risk + reasons (codes + optional value)."""

    url = (raw_url or "").strip()
    if not url:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": "",
            "domain": "",
            "reasons": [{"code": "EMPTY_URL"}],
        }

    normalized = url
    if not re.match(r"^https?://", normalized, re.IGNORECASE):
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
    except Exception:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    if not parsed.netloc:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    domain = (parsed.hostname or "").strip(".").lower()
    if not domain:
        return False, {
            "message_key": "Invalid URL format",
            "risk": 100,
            "normalized": normalized,
            "domain": "",
            "reasons": [{"code": "INVALID_URL"}],
        }

    reasons = []
    risk = 0.0

    # Scheme/security
    if (parsed.scheme or "").lower() != "https":
        risk += 14
        reasons.append({"code": "NOT_HTTPS"})

    # Common obfuscation tricks
    if "@" in (parsed.netloc or ""):
        risk += 35
        reasons.append({"code": "HAS_AT_SYMBOL"})

    port = parsed.port
    if port not in (None, 80, 443):
        risk += 12
        reasons.append({"code": "NON_STANDARD_PORT", "value": str(port)})

    if normalized.count("%") >= 3:
        risk += 12
        reasons.append({"code": "ENCODED_OBFUSCATION"})

    if _IPV4_RE.match(domain):
        risk += 45
        reasons.append({"code": "IP_ADDRESS_HOST"})

    if domain.startswith("xn--") or ".xn--" in domain:
        risk += 25
        reasons.append({"code": "PUNYCODE_DOMAIN"})

    # Suspicious patterns in host
    dot_count = domain.count(".")
    if dot_count > 3:
        risk += 20
        reasons.append({"code": "TOO_MANY_SUBDOMAINS", "value": str(dot_count + 1)})

    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        risk += 20
        reasons.append({"code": "MANY_HYPHENS", "value": str(hyphen_count)})

    # Length-based signals
    if len(normalized) >= 100:
        risk += 15
        reasons.append({"code": "LONG_URL", "value": str(len(normalized))})
    elif len(normalized) >= 75:
        risk += 8
        reasons.append({"code": "LONG_URL", "value": str(len(normalized))})

    # TLD risk (very rough heuristic)
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld and tld in RISKY_TLDS:
        risk += 18
        reasons.append({"code": "RISKY_TLD", "value": tld})

    # URL shorteners hide destination
    if domain in URL_SHORTENERS:
        risk += 30
        reasons.append({"code": "URL_SHORTENER"})

    # Keyword match in domain
    domain_keyword_hits = []
    for word in DOMAIN_SUSPICIOUS_WORDS:
        if word in domain:
            domain_keyword_hits.append(word)
            reasons.append({"code": "SUSPICIOUS_KEYWORD", "value": word})

    if domain_keyword_hits:
        risk += min(48, 12 * len(domain_keyword_hits))

    if len(domain_keyword_hits) >= 2:
        # Multiple sensitive keywords in one domain is a strong phishing signal.
        risk += 18
        reasons.append({"code": "MULTIPLE_SUSPICIOUS_KEYWORDS", "value": str(len(domain_keyword_hits))})

    if len(domain_keyword_hits) >= 3:
        risk += 15
        reasons.append({"code": "SUSPICIOUS_WORD_CLUSTER", "value": str(len(domain_keyword_hits))})

    path_query = " ".join(
        [
            unquote(parsed.path or ""),
            unquote(parsed.params or ""),
            unquote(parsed.query or ""),
            unquote(parsed.fragment or ""),
        ]
    ).lower()

    path_keyword_hits = []
    for word in PATH_SUSPICIOUS_WORDS:
        if _token_match(path_query, word):
            path_keyword_hits.append(word)
            reasons.append({"code": "SUSPICIOUS_PATH_KEYWORD", "value": word})

    if path_keyword_hits:
        risk += min(45, 15 * len(path_keyword_hits))

    if len(path_keyword_hits) >= 2:
        risk += 12
        reasons.append(
            {"code": "MULTIPLE_SUSPICIOUS_PATH_KEYWORDS", "value": str(len(path_keyword_hits))}
        )

    domain_parts_text = re.sub(r"[^a-z0-9]+", " ", domain)
    domain_tokens = {t for t in domain_parts_text.split() if t}
    has_auth_term = any(t in domain_tokens for t in AUTH_TERMS)
    has_incentive_term = any(t in domain_tokens for t in INCENTIVE_TERMS)
    if has_auth_term and has_incentive_term:
        risk += 22
        reasons.append({"code": "INCENTIVE_AUTH_COMBO"})

    if any(token in domain or token in path_query for token in EXPLICIT_PHISHING_TOKENS):
        risk += 60
        reasons.append({"code": "EXPLICIT_PHISHING_TERM"})

    # Brand impersonation (very small allowlist; educational heuristic).
    for brand, allowed_suffixes in BRAND_ALLOWLIST.items():
        if brand in domain and not any(domain == sfx or domain.endswith("." + sfx) for sfx in allowed_suffixes):
            risk += 35
            reasons.append({"code": "BRAND_IMPERSONATION", "value": brand})
            if has_auth_term or has_incentive_term:
                risk += 18
                reasons.append({"code": "BRAND_WITH_RISK_TERMS", "value": brand})

    risk = _clamp(risk, 0, 100)

    if risk >= 70:
        msg_key = "High risk URL"
        safe = False
    elif risk >= 55:
        msg_key = "Suspicious URL"
        safe = False
    else:
        msg_key = "URL looks safe"
        safe = True

    if not reasons and safe:
        reasons = [{"code": "NO_MAJOR_FLAGS"}]

    return safe, {
        "message_key": msg_key,
        "risk": round(risk, 2),
        "normalized": normalized,
        "domain": domain,
        "reasons": reasons,
    }

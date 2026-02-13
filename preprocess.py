import re
from urllib.parse import urlparse

# Lightweight preprocessing for bilingual (Arabic/English) phishing text classification.
# Keep it simple and deterministic so the same logic can be mirrored in the offline app.

URL_RE = re.compile(
    r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>\"]*)?)",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b")

AR_LETTER_RE = re.compile(r"[\u0600-\u06FF]")
# Arabic diacritics (tashkeel) + Quranic marks ranges.
AR_DIACRITICS_RE = re.compile(r"[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]")

# Basic stopwords only (avoid being overly aggressive; small datasets are sensitive).
AR_STOPWORDS = {
    "\u0641\u064a",  # في
    "\u0639\u0644\u0649",  # على
    "\u0645\u0646",  # من
    "\u0627\u0644\u0649",  # الى
    "\u0625\u0644\u0649",  # إلى
    "\u0639\u0646",  # عن
    "\u0623\u0646",  # أن
    "\u0625\u0646",  # إن
    "\u0643\u0627\u0646",  # كان
    "\u0645\u0627",  # ما
    "\u0647\u0630\u0627",  # هذا
    "\u0647\u0630\u0647",  # هذه
    "\u0630\u0644\u0643",  # ذلك
    "\u062a\u0644\u0643",  # تلك
    "\u0647\u0646\u0627\u0643",  # هناك
    "\u0645\u0639",  # مع
    "\u0627\u0648",  # او
    "\u0623\u0648",  # أو
    "\u062b\u0645",  # ثم
    "\u0643\u0645\u0627",  # كما
    "\u0644\u0642\u062f",  # لقد
}

EN_STOPWORDS = {
    "the",
    "is",
    "in",
    "on",
    "at",
    "and",
    "or",
    "to",
    "of",
    "a",
    "an",
    "for",
    "we",
    "you",
    "your",
    "our",
}


def _strip_url_punctuation(value: str) -> str:
    v = str(value or "").strip()
    v = v.lstrip("<([{\"'")
    v = v.rstrip(")]}>.,;:!?\"'")
    return v.strip()


def _split_token_parts(value: str) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[^a-z0-9\u0600-\u06FF]+", value.lower())
    return [p for p in parts if len(p) > 1]


def _url_feature_tokens(raw_url: str) -> list[str]:
    url = _strip_url_punctuation(raw_url)
    if not url:
        return []

    normalized = url if re.match(r"^https?://", url, re.IGNORECASE) else f"http://{url}"

    try:
        parsed = urlparse(normalized)
    except Exception:
        return []

    host = (parsed.hostname or "").lower().strip(".")
    tokens: list[str] = []

    scheme = (parsed.scheme or "").lower()
    if scheme:
        tokens.append(f"url_{scheme}")

    if host:
        host_parts = _split_token_parts(host)
        tokens.extend(host_parts)

        labels = [p for p in host.split(".") if p]
        if labels:
            tld = labels[-1]
            if tld:
                tokens.append(f"tld_{tld}")
        if host.count("-") >= 2:
            tokens.append("hyphen_domain")
        if host.count(".") >= 3:
            tokens.append("many_subdomains")

    path_blob = " ".join([parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""])
    path_parts = _split_token_parts(path_blob)
    tokens.extend(path_parts)

    seen = set()
    out = []
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= 20:
            break
    return out


def _replace_url(match: re.Match[str]) -> str:
    tokens = _url_feature_tokens(match.group(0))
    if tokens:
        return " URLTOKEN " + " ".join(tokens) + " "
    return " URLTOKEN "


def _replace_email(match: re.Match[str]) -> str:
    email = str(match.group(0) or "").strip().lower()
    parts = email.split("@")
    domain = parts[1] if len(parts) == 2 else ""
    tokens = _split_token_parts(domain)
    if domain:
        labels = [p for p in domain.split(".") if p]
        if labels:
            tokens.append(f"mail_tld_{labels[-1]}")

    if tokens:
        return " EMAILTOKEN " + " ".join(tokens[:10]) + " "
    return " EMAILTOKEN "


def is_probably_arabic(text: str) -> bool:
    value = text or ""
    return bool(AR_LETTER_RE.search(value))


def normalize_arabic(text: str) -> str:
    s = text or ""
    s = AR_DIACRITICS_RE.sub("", s)
    s = s.replace("\u0640", "")  # tatweel
    # Normalize common letter variants.
    s = s.replace("\u0623", "\u0627").replace("\u0625", "\u0627").replace("\u0622", "\u0627")
    s = s.replace("\u0649", "\u064A")
    s = s.replace("\u0624", "\u0648").replace("\u0626", "\u064A")
    # Optional normalization often used in IR/NLP.
    s = s.replace("\u0629", "\u0647")
    return s


def clean_text(text: str) -> str:
    s = str(text or "")

    # Keep URL/email signals, plus extracted URL tokens for URL-focused learning.
    s = EMAIL_RE.sub(_replace_email, s)
    s = URL_RE.sub(_replace_url, s)

    if is_probably_arabic(s):
        s = normalize_arabic(s)

    s = s.lower()

    # Keep: latin, digits, underscores, Arabic block, and our *_token placeholders.
    s = re.sub(r"[^a-z0-9_\u0600-\u06FF\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()

    if not s:
        return ""

    tokens = s.split()
    tokens = [
        t
        for t in tokens
        if (t not in EN_STOPWORDS) and (t not in AR_STOPWORDS) and len(t) > 1
    ]
    return " ".join(tokens)

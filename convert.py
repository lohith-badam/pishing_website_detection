# convert.py
import re

# Whitelist of domains considered always safe (customize as you wish)
SAFE_DOMAINS = [
    'youtube.com', 'youtu.be', 'google.com', 'github.com', 'openai.com',
    'wikipedia.org', 'microsoft.com', 'apple.com'
]

SHORTENER_PATTERN = re.compile(
    r'bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
    r'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
    r'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
    r'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|lnkd\\.in|'
    r'db\\.tt|qr\\.ae|adf\\.ly|bitly\\.com|cur\\.lv|tinyurl\\.com|ity\\.im|q\\.gs|po\\.st|bc\\.vc|'
    r'twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|yourls\\.org|prettylinkpro\\.com|'
    r'scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|1url\\.com|tweez\\.me|v\\.gd|tr\\.im|link\\.zip\\.net',
    re.I
)

def is_whitelisted(url: str) -> bool:
    return any(domain in url for domain in SAFE_DOMAINS)

def is_shortlink(url: str) -> bool:
    return bool(SHORTENER_PATTERN.search(url))

def convertion(url: str, prediction: int, shortcuts=None):
    """
    Normalize final decision text.
    prediction: model output (1=safe, -1=phishing)
    shortcuts: optional dict from FeatureExtraction.get_short_checks()
    Returns: (status, headline)
    """
    shortcuts = shortcuts or {}
    # Hard allowlist: if whitelisted, it's Safe
    if is_whitelisted(url):
        return ("Safe", "Whitelisted domain")

    # If model says phishing OR shortlink (high-risk) => Phishing
    if prediction == -1 or is_shortlink(url):
        msg_bits = []
        if is_shortlink(url): msg_bits.append("URL shortener detected")
        if shortcuts.get("redirect_count", 0) > 1: msg_bits.append("multiple redirects")
        if shortcuts.get("is_ip"): msg_bits.append("raw IP used")
        headline = " / ".join(msg_bits) if msg_bits else "Flagged by ML model"
        return ("Phishing", headline)

    # If HTTPS is missing and redirects exist, be cautious but allow Safe status
    if not shortcuts.get("has_https") and shortcuts.get("redirect_count", 0) > 1:
        return ("Safe", "Non-HTTPS with redirects (monitor)")

    return ("Safe", "No major red flags")

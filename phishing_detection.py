"""
modules/phishing_detection.py
Module 1 - AI Phishing Detection
"""

import re
from email import message_from_string, message_from_bytes
from email.utils import parseaddr
from urllib.parse import urlparse

URGENT_KEYWORDS = [
    "urgent", "immediately", "action required", "act now", "verify your account",
    "suspended", "suspension", "unusual activity", "confirm your identity",
    "your account will be", "within 24 hours", "final notice", "last warning",
    "failure to", "avoid termination", "limited time", "respond now",
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "log in", "sign in", "signin", "credentials",
    "update your payment", "billing information", "confirm your password",
    "reset your password", "validate your account", "unlock your account",
]

LURE_KEYWORDS = [
    "you have won", "congratulations", "claim your prize", "gift card",
    "inheritance", "lottery", "bitcoin", "crypto giveaway", "wire transfer",
    "invoice attached", "refund", "tax refund", "package could not be delivered",
]

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com",
    ".pif", ".jar", ".msi", ".ps1", ".hta", ".wsf", ".lnk", ".iso", ".img",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".cab"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".club", ".click", ".link", ".work",
    ".gq", ".ml", ".cf", ".tk", ".country", ".stream", ".download",
}

POPULAR_BRANDS = [
    "paypal", "apple", "microsoft", "amazon", "google", "netflix", "facebook",
    "instagram", "bankofamerica", "wellsfargo", "chase", "dhl", "fedex", "ups",
    "usps", "coinbase", "linkedin", "office365", "outlook", "docusign",
]

URL_REGEX = re.compile(r"""https?://[^\s"'<>()]+""", re.IGNORECASE)

ANCHOR_REGEX = re.compile(
    r"""<a\s[^>]*href=["']?(?P<href>[^"'>\s]+)["']?[^>]*>(?P<text>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)


class PhishingResult:
    def __init__(self):
        self.score = 0
        self.label = "Safe"
        self.red_flags = []
        self.recommendations = []
        self.sender = ""
        self.subject = ""
        self.urls = []
        self.attachments = []

    def add_flag(self, description, weight):
        self.red_flags.append({"issue": description, "weight": weight})
        self.score += weight

    def to_dict(self):
        return {
            "score": self.score,
            "label": self.label,
            "sender": self.sender,
            "subject": self.subject,
            "urls": self.urls,
            "attachments": self.attachments,
            "red_flags": self.red_flags,
            "recommendations": self.recommendations,
        }


def parse_eml_bytes(raw_bytes: bytes) -> dict:
    msg = message_from_bytes(raw_bytes)
    return _message_to_fields(msg)


def parse_pasted_text(text: str) -> dict:
    if re.search(r"^(from|subject|to)\s*:", text, re.IGNORECASE | re.MULTILINE):
        msg = message_from_string(text)
        return _message_to_fields(msg)

    return {
        "from": "",
        "subject": "",
        "body": text,
        "html": text,
        "attachments": [],
    }


def _message_to_fields(msg) -> dict:
    body_text = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if filename and "attachment" in disposition.lower():
                attachments.append(filename)
            elif content_type == "text/plain":
                body_text += _safe_decode(part)
            elif content_type == "text/html":
                body_html += _safe_decode(part)
    else:
        payload = _safe_decode(msg)
        if msg.get_content_type() == "text/html":
            body_html = payload
        else:
            body_text = payload

    return {
        "from": msg.get("From", ""),
        "subject": msg.get("Subject", ""),
        "body": body_text or _strip_html(body_html),
        "html": body_html or body_text,
        "attachments": attachments,
    }


def _safe_decode(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    return re.sub(r"\s+", " ", text).strip()


def analyze_email(fields: dict) -> PhishingResult:
    result = PhishingResult()

    result.sender = fields.get("from", "")
    result.subject = fields.get("subject", "")

    body = fields.get("body", "") or ""
    html = fields.get("html", "") or ""
    combined = f"{result.subject}\n{body}".lower()

    urls = set(URL_REGEX.findall(body)) | set(URL_REGEX.findall(html))
    result.urls = sorted(urls)
    result.attachments = fields.get("attachments", [])

    _check_sender_spoofing(result)
    _check_urgent_language(result, combined)
    _check_credential_bait(result, combined)
    _check_lures(result, combined)
    _check_urls(result, result.urls)
    _check_mismatched_anchors(result, html)
    _check_brand_lookalikes(result, result.urls, result.sender)
    _check_attachments(result, result.attachments)

    _finalize(result)
    return result


def _check_sender_spoofing(result: PhishingResult):
    display_name, email_addr = parseaddr(result.sender)

    if not email_addr:
        if result.sender:
            result.add_flag("Sender address is malformed or hidden", 10)
        return

    domain = email_addr.split("@")[-1].lower()
    lowered_name = display_name.lower()

    for brand in POPULAR_BRANDS:
        if brand in lowered_name and brand not in domain:
            result.add_flag(
                f"Display name mentions '{brand}' but real domain is '{domain}'",
                20,
            )
            break

    freemail = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com"}

    if domain in freemail and any(b in lowered_name for b in POPULAR_BRANDS):
        result.add_flag(
            f"Brand-style sender is using a free email domain: {domain}",
            12,
        )


def _check_urgent_language(result: PhishingResult, text: str):
    hits = [k for k in URGENT_KEYWORDS if k in text]
    if hits:
        weight = min(6 + 3 * len(hits), 18)
        result.add_flag(
            f"Urgent or pressuring language detected: {', '.join(hits[:4])}",
            weight,
        )


def _check_credential_bait(result: PhishingResult, text: str):
    hits = [k for k in CREDENTIAL_KEYWORDS if k in text]
    if hits:
        result.add_flag(
            f"Requests credentials or account action: {', '.join(hits[:4])}",
            14,
        )


def _check_lures(result: PhishingResult, text: str):
    hits = [k for k in LURE_KEYWORDS if k in text]
    if hits:
        result.add_flag(
            f"Classic scam wording detected: {', '.join(hits[:3])}",
            12,
        )


def _check_urls(result: PhishingResult, urls):
    for url in urls:
        host = urlparse(url).netloc.lower()

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", host):
            result.add_flag(f"Link points directly to an IP address: {host}", 15)

        if any(host == s or host.endswith("." + s) for s in URL_SHORTENERS):
            result.add_flag(f"Uses URL shortener: {host}", 10)

        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                result.add_flag(f"Link uses suspicious TLD: {host}", 8)
                break

        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            result.add_flag(f"Link contains '@' to hide real host: {url}", 12)

        if re.search(r"(login|signin|verify|secure|account|update|confirm)", url, re.I):
            result.add_flag(f"Link mimics login or verification page: {host}", 8)


def _check_mismatched_anchors(result: PhishingResult, html: str):
    if not html:
        return

    for match in ANCHOR_REGEX.finditer(html):
        href = match.group("href").strip()
        text = _strip_html(match.group("text")).strip()

        if re.search(r"[a-z0-9.-]+\.[a-z]{2,}", text, re.I) and href.startswith("http"):
            visible_host = re.sub(r"^https?://", "", text.lower()).split("/")[0]
            real_host = urlparse(href).netloc.lower()

            if visible_host and real_host and visible_host not in real_host:
                result.add_flag(
                    f"Link text says '{visible_host}' but goes to '{real_host}'",
                    18,
                )


def _check_brand_lookalikes(result: PhishingResult, urls, sender):
    corpus = " ".join(urls) + " " + sender

    for brand in POPULAR_BRANDS:
        for token in re.findall(r"[a-z0-9.-]+", corpus, re.IGNORECASE):
            low = token.lower()

            if brand in low:
                continue

            deleet = low.translate(str.maketrans("013457", "oieast"))

            if brand in deleet and brand not in low:
                result.add_flag(
                    f"Look-alike domain impersonating '{brand}': {token}",
                    16,
                )
                break


def _check_attachments(result: PhishingResult, attachments):
    for name in attachments:
        lower = name.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""

        if re.search(r"\.(pdf|doc|docx|jpg|png|xls|xlsx)\.[a-z0-9]{2,4}$", lower):
            result.add_flag(f"Double extension file: {name}", 20)
        elif ext in RISKY_EXTENSIONS:
            result.add_flag(f"Dangerous executable attachment: {name}", 22)
        elif ext in ARCHIVE_EXTENSIONS:
            result.add_flag(f"Archive attachment may hide malware: {name}", 8)


def _finalize(result: PhishingResult):
    result.score = min(result.score, 100)

    if result.score >= 60:
        result.label = "Dangerous"
    elif result.score >= 30:
        result.label = "Suspicious"
    else:
        result.label = "Safe"

    recs = []

    if result.label == "Dangerous":
        recs.append("Do NOT click links or open attachments.")
        recs.append("Do not reply or provide personal information.")
        recs.append("Report this email to IT or your email provider.")
        recs.append("Delete the email after reporting it.")

    elif result.label == "Suspicious":
        recs.append("Verify the sender using an official source.")
        recs.append("Do not enter passwords through email links.")
        recs.append("Hover over links before clicking.")

    else:
        recs.append("No strong phishing signs detected.")
        recs.append("Still verify unexpected requests.")

    if result.attachments:
        recs.append("Be careful with attachments (especially archives/executables).")

    result.recommendations = recs

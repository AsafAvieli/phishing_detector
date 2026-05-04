"""
Email phishing analysis engine.

Parses RFC 822 / MIME messages and scores risk using heuristic indicators:
link analysis, sender reputation, urgent language, header integrity,
email authentication results, and attachment naming.
"""

from __future__ import annotations

import ipaddress
import json
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any
from urllib.parse import urlparse

from thefuzz import fuzz

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Well-known brands that phishers frequently impersonate.
# Used as baselines for both typosquatting and display-name spoofing checks.
LEGITIMATE_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "gmail.com",
        "microsoft.com",
        "outlook.com",
        "live.com",
        "amazon.com",
        "apple.com",
        "icloud.com",
        "paypal.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "linkedin.com",
        "facebook.com",
        "meta.com",
        "dropbox.com",
        "docusign.com",
        "adobe.com",
        "netflix.com",
    }
)

# 82–99 catches look-alike domains (e.g. "paypa1.com") while excluding
# exact matches (100) and unrelated short strings that happen to score high.
TYPO_SQUAT_RATIO_MIN: int = 82
TYPO_SQUAT_RATIO_MAX: int = 99

# A score of 45+ means at least two moderate indicators fired — enough
# confidence to call the email suspicious without too many false positives.
PHISHING_RISK_THRESHOLD: int = 45

# TLDs that are free/cheap to register and heavily abused in phishing campaigns.
SUSPICIOUS_TLD_SUFFIXES: tuple[str, ...] = (
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".work",
    ".click",
    ".link",
    ".buzz",
)

# Social-engineering phrases that pressure the recipient into acting without thinking.
URGENT_PATTERN = re.compile(
    r"\b("
    r"urgent|immediately|asap|act now|action required|verify your account|"
    r"account (?:suspended|locked|compromised)|confirm your identity|"
    r"limited time|expires (?:today|soon)|click (?:here|below) (?:now|immediately)|"
    r"unusual activity|security alert|password expir|update your payment|"
    r"wire transfer|gift card"
    r")\b",
    re.IGNORECASE,
)

# Matches http/https URLs in both plain-text and raw HTML bodies.
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'\)\]]+",
    re.IGNORECASE,
)

# Attackers hide executables behind a harmless-looking first extension
# (e.g. "invoice.pdf.exe") hoping the user only reads the first part.
DOUBLE_EXT_PATTERN = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|zip|rar|7z)"
    r"\.(?:exe|bat|cmd|com|pif|scr|vbs|js|jse|wsf|wsh|msi|dll|cpl|jar|ps1)\b",
    re.IGNORECASE,
)

# Maps brand keywords (found in display names) to the domain that brand actually owns.
# Used to catch "Microsoft Security Team <attacker@gmail.com>"-style spoofing,
# which typosquatting alone cannot detect because gmail.com is a legitimate domain.
BRAND_DISPLAY_NAMES: dict[str, str] = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "meta": "meta.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "adobe": "adobe.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
}

# Each weight reflects how strongly that indicator alone predicts phishing.
# Display-name spoofing and malicious attachments are weighted highest because
# they require deliberate deception rather than just careless configuration.
WEIGHT_SUSPICIOUS_LINK: int = 18
WEIGHT_TYPO_SQUAT: int = 28
WEIGHT_URGENT_LANGUAGE: int = 15
WEIGHT_HEADER_MISMATCH: int = 22
WEIGHT_AUTH_FAILURE: int = 26
WEIGHT_MALICIOUS_ATTACHMENT: int = 32
WEIGHT_DISPLAY_NAME_SPOOF: int = 35
MAX_LINK_WARNINGS: int = 5  # cap so a single email with 20 bad links doesn't dominate the score


def _parse_email(raw: str | bytes) -> EmailMessage:
    """Parse raw RFC 822 content into an EmailMessage."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    return BytesParser(policy=policy.default).parsebytes(raw)


def _extract_domain_from_addr(addr: str | None) -> str | None:
    """Return lowercase domain from an email address or None."""
    if not addr:
        return None
    # Handles both "Display Name <user@domain.com>" and bare "user@domain.com".
    m = re.search(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", addr, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _first_address_domain(header_value: str | None) -> str | None:
    """Extract domain from the first address in a From/Reply-To/Return-Path header."""
    if not header_value:
        return None
    return _extract_domain_from_addr(header_value.strip().split(",")[0].strip())


def _collect_bodies(msg: EmailMessage) -> str:
    """Concatenate all text parts (plain and HTML) for URL and keyword scanning.

    We scan both because phishers sometimes hide links only in the HTML part,
    knowing many users view rendered email rather than raw source.
    """
    chunks: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        chunks.append(payload)
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_content()
            if isinstance(payload, str):
                chunks.append(payload)
        except Exception:
            pass
    return "\n".join(chunks)


def _hostname_is_ip(host: str) -> bool:
    """Return True if the host is a raw IP address (IPv4 or IPv6).

    Legitimate services use domain names; IP-based URLs strongly suggest
    the sender is trying to hide the actual hosting infrastructure.
    """
    host = host.strip("[]")  # IPv6 addresses in URLs are wrapped in brackets
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _check_suspicious_urls(body: str) -> list[str]:
    """Flag URLs that use raw IP addresses or high-risk TLDs."""
    warnings: list[str] = []
    seen_hosts: set[str] = set()
    for match in URL_PATTERN.finditer(body):
        if len(warnings) >= MAX_LINK_WARNINGS:
            break
        url = match.group(0).rstrip(".,);]")  # strip punctuation that follows URLs in prose
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        if host in seen_hosts:  # deduplicate — same host appearing many times is one indicator
            continue
        seen_hosts.add(host)
        if _hostname_is_ip(host):
            warnings.append(f"Suspicious link: URL uses IP address as host ({host})")
            continue
        if any(host.endswith(sfx) for sfx in SUSPICIOUS_TLD_SUFFIXES):
            warnings.append(f"Suspicious link: uncommon or high-risk TLD in URL ({host})")
    return warnings


def _check_typosquat(sender_domain: str | None) -> list[str]:
    """Detect sender domains that closely resemble a known legitimate domain.

    e.g. 'paypa1.com' (ratio ~90%) vs 'paypal.com' — close enough to fool
    a casual reader but different enough to pass DNS checks.
    """
    if not sender_domain:
        return []
    if sender_domain in LEGITIMATE_DOMAINS:
        return []  # exact match is fine
    warnings: list[str] = []
    for legit in LEGITIMATE_DOMAINS:
        ratio = fuzz.ratio(sender_domain, legit)
        if TYPO_SQUAT_RATIO_MIN <= ratio <= TYPO_SQUAT_RATIO_MAX:
            warnings.append(
                f"Possible typosquatting: sender domain '{sender_domain}' is "
                f"similar to '{legit}' (similarity {ratio}%)"
            )
            break  # one typosquat match is enough; avoid duplicate warnings
    return warnings


def _check_urgent_language(body: str, subject: str) -> list[str]:
    """Scan subject and body for pressure tactics designed to make the user act fast."""
    text = f"{subject}\n{body}"
    if URGENT_PATTERN.search(text):
        return ["Urgent or pressure language detected in subject or body"]
    return []


def _check_display_name_spoofing(msg: EmailMessage) -> list[str]:
    """Detect display-name impersonation.

    A phisher writes "Microsoft Security Team <attacker@gmail.com>".
    gmail.com is a real domain so typosquatting won't fire — but the display
    name falsely implies the email comes from Microsoft. This check catches that.
    """
    from_header = msg.get("From", "") or ""
    # The display name is everything before the angle bracket in "Name <addr>".
    m = re.match(r'^"?([^"<@\n]+?)"?\s*<', from_header.strip())
    if not m:
        return []
    display_name = m.group(1).strip().lower()
    sender_domain = _first_address_domain(from_header)
    if not sender_domain:
        return []

    for brand_keyword, brand_domain in BRAND_DISPLAY_NAMES.items():
        if brand_keyword in display_name:
            # Subdomains like "mail.paypal.com" are legitimate; only flag mismatches.
            if sender_domain != brand_domain and not sender_domain.endswith("." + brand_domain):
                return [
                    f"Display name spoofing: sender claims to be '{m.group(1).strip()}' "
                    f"but email is from '{sender_domain}', not {brand_domain}"
                ]
    return []


def _check_header_mismatch(msg: EmailMessage) -> list[str]:
    """Detect inconsistencies between From, Reply-To, and Return-Path domains.

    In legitimate email these three domains usually match. A mismatch means
    replies or bounces would go somewhere different from where the email
    appears to originate — a classic Business Email Compromise (BEC) tactic.
    """
    warnings: list[str] = []
    from_dom = _first_address_domain(msg.get("From"))
    reply_dom = _first_address_domain(msg.get("Reply-To"))
    rp = msg.get("Return-Path") or ""
    rp_dom = _extract_domain_from_addr(rp.strip("<>"))  # Return-Path looks like <user@domain>

    if from_dom and reply_dom and from_dom != reply_dom:
        warnings.append(
            f"Header mismatch: From domain ({from_dom}) differs from "
            f"Reply-To domain ({reply_dom})"
        )
    if from_dom and rp_dom and from_dom != rp_dom:
        warnings.append(
            f"Header mismatch: From domain ({from_dom}) differs from "
            f"Return-Path domain ({rp_dom})"
        )
    return warnings


def _check_authentication_failures(msg: EmailMessage) -> list[str]:
    """Parse Authentication-Results for SPF, DKIM, and DMARC failures.

    SPF verifies the sending server is authorised for the domain.
    DKIM verifies the email content wasn't tampered with in transit.
    DMARC ties SPF/DKIM together and defines what to do on failure.
    Any failure here means the receiving mail server already suspected forgery.
    """
    warnings: list[str] = []
    # Multiple Authentication-Results headers can appear (one per mail hop).
    auth_headers = msg.get_all("Authentication-Results", failobj=[]) or []
    combined = " ".join(auth_headers).lower()

    def _mentions_failure(protocol: str) -> bool:
        p = protocol.lower()
        return bool(
            re.search(rf"{p}\s*=\s*(fail|softfail|permerror|temperror)", combined)
        )

    if _mentions_failure("spf"):
        warnings.append("Authentication failure: SPF reported fail or softfail")
    if _mentions_failure("dkim"):
        warnings.append("Authentication failure: DKIM reported fail or softfail")
    if _mentions_failure("dmarc"):
        warnings.append("Authentication failure: DMARC reported fail or softfail")

    return warnings


def _check_attachments(msg: EmailMessage) -> list[str]:
    """Flag attachments with double extensions (e.g. invoice.pdf.exe).

    Windows hides known extensions by default, so a user sees "invoice.pdf"
    and double-clicks what is actually an executable. This is a common
    malware delivery technique in phishing campaigns.
    """
    warnings: list[str] = []
    if not msg.is_multipart():
        return warnings
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        if DOUBLE_EXT_PATTERN.search(filename):
            warnings.append(
                f"Malicious attachment pattern: double extension in '{filename}'"
            )
    return warnings


def _compute_risk_score(warnings_by_category: dict[str, list[str]]) -> int:
    """Sum weighted scores for each triggered category, capped at 100.

    Suspicious links scale with count (more bad links = higher risk) but are
    capped at 35 so a single email full of bad links doesn't skew the total.
    All other categories are binary: fired or not.
    """
    score = 0
    if warnings_by_category.get("suspicious_links"):
        score += min(
            len(warnings_by_category["suspicious_links"]) * WEIGHT_SUSPICIOUS_LINK,
            35,
        )
    if warnings_by_category.get("typosquat"):
        score += WEIGHT_TYPO_SQUAT
    if warnings_by_category.get("urgent_language"):
        score += WEIGHT_URGENT_LANGUAGE
    if warnings_by_category.get("header_mismatch"):
        score += WEIGHT_HEADER_MISMATCH
    if warnings_by_category.get("auth_failure"):
        score += WEIGHT_AUTH_FAILURE
    if warnings_by_category.get("malicious_attachment"):
        score += WEIGHT_MALICIOUS_ATTACHMENT
    if warnings_by_category.get("display_name_spoof"):
        score += WEIGHT_DISPLAY_NAME_SPOOF
    return min(100, score)


def analyze_email(raw_email: str | bytes) -> dict[str, Any]:
    """Run all checks on a raw email and return a verdict.

    Returns a dict with:
        is_phishing        bool   — True if risk_score >= PHISHING_RISK_THRESHOLD
        risk_score         int    — 0–100 composite risk score
        detected_indicators list  — human-readable description of each flag
    """
    msg = _parse_email(raw_email)
    subject = msg.get("Subject", "") or ""
    body = _collect_bodies(msg)
    sender_raw = msg.get("From", "")
    sender_domain = _first_address_domain(sender_raw)

    suspicious_links = _check_suspicious_urls(body)
    typosquat = _check_typosquat(sender_domain)
    urgent = _check_urgent_language(body, subject)
    header_mismatch = _check_header_mismatch(msg)
    auth_failure = _check_authentication_failures(msg)
    malicious_attachment = _check_attachments(msg)
    display_name_spoof = _check_display_name_spoofing(msg)

    categories: dict[str, list[str]] = {
        "suspicious_links": suspicious_links,
        "typosquat": typosquat,
        "urgent_language": urgent,
        "header_mismatch": header_mismatch,
        "auth_failure": auth_failure,
        "malicious_attachment": malicious_attachment,
        "display_name_spoof": display_name_spoof,
    }

    detected: list[str] = []
    for items in categories.values():
        detected.extend(items)

    risk_score = _compute_risk_score(categories)
    is_phishing = risk_score >= PHISHING_RISK_THRESHOLD

    return {
        "is_phishing": is_phishing,
        "risk_score": risk_score,
        "detected_indicators": detected,
    }


def analyze_email_json(raw_email: str | bytes) -> str:
    """Return analysis result as a JSON string (used by the API layer)."""
    return json.dumps(analyze_email(raw_email), indent=2)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Scan an email file for phishing indicators.",
    )
    parser.add_argument(
        "email_file",
        help="Path to a .txt or .eml file containing the raw email content.",
    )
    args = parser.parse_args()

    try:
        with open(args.email_file, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        print(f"Error: file not found — {args.email_file}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        sys.exit(1)

    result = analyze_email(raw)
    is_phishing: bool = result["is_phishing"]
    risk_score: int = result["risk_score"]
    indicators: list[str] = result["detected_indicators"]

    print("=" * 60)
    print("PHISHING DETECTION REPORT")
    print("=" * 60)
    print(f"Verdict    : {'⚠  LIKELY PHISHING' if is_phishing else '✓  Looks clean'}")
    print(f"Risk score : {risk_score} / 100")
    print(f"Indicators : {len(indicators)} detected")
    print("-" * 60)

    if indicators:
        for item in indicators:
            print(f"  • {item}")
    else:
        print("  No heuristic indicators triggered.")

    print("=" * 60)
    # Exit code 1 when phishing is detected — useful for shell scripting and CI pipelines.
    sys.exit(1 if is_phishing else 0)

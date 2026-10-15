"""Heuristic checks for suspicious URL characteristics.

These are *risk indicators*: patterns common in phishing URLs that also occur on
legitimate sites. A finding here never means a URL is confirmed malicious; that is
the job of threat_intel.py.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass
from urllib.parse import unquote

from .parsing import ParsedURL, to_unicode

SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 40}
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str  # "low" | "medium" | "high"
    title: str
    explanation: str  # why this matters, in plain language
    evidence: str     # what exactly in this URL triggered it

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def to_dict(self) -> dict:
        return {**asdict(self), "weight": self.weight}


# --- Reference data ---------------------------------------------------------

# Brand -> registrable domains it legitimately uses. Extend for your users' region.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "apple": {"apple.com", "icloud.com", "apple.news"},
    "icloud": {"icloud.com", "apple.com"},
    "microsoft": {"microsoft.com", "live.com", "microsoftonline.com", "office.com", "outlook.com", "sharepoint.com", "azure.com"},
    "office365": {"office.com", "office365.com", "microsoft.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "google": {"google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "gmail.com", "youtube.com"},
    "gmail": {"gmail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazonaws.com", "amazon.ca"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "facebook.net", "fbcdn.net"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "steamcommunity": {"steamcommunity.com"},
    "steampowered": {"steampowered.com"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "v.gd", "shorte.st",
    "adf.ly", "bl.ink", "lnkd.in", "qrco.de",
}

# TLDs with disproportionately high abuse rates in public phishing reports, plus
# .zip/.mov which are easily confused with file names.
SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "kim",
    "work", "support", "rest", "fit", "loan", "cam", "icu", "monster", "cyou", "sbs",
    "buzz", "quest", "lol", "bond", "cfd",
}
FILENAME_LIKE_TLDS = {"zip", "mov"}

# Free hosting / tunnelling services where anyone can publish under a reputable domain.
FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "wixsite.com", "firebaseapp.com", "web.app",
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "glitch.me", "ngrok.io",
    "ngrok-free.app", "duckdns.org", "github.io", "blogspot.com", "herokuapp.com",
    "repl.co", "square.site", "godaddysites.com", "r2.dev", "ipfs.io",
}

PHISHING_KEYWORDS = {
    "login", "logon", "signin", "sign-in", "verify", "verification", "validate", "account",
    "accounts", "update", "secure", "security", "banking", "confirm", "password", "wallet",
    "unlock", "suspended", "suspend", "billing", "invoice", "webscr", "recover", "recovery",
    "authenticate", "auth", "support", "refund", "claim", "seed", "airdrop",
}

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk",
    ".iso", ".img", ".hta", ".lnk", ".dll",
}

_CONFUSABLES = str.maketrans({
    # Cyrillic / Greek / Armenian letters that render like Latin ones
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ѕ": "s", "ӏ": "l", "ο": "o", "α": "a",
    "ν": "v", "κ": "k",
    # Digits commonly substituted for letters
    "0": "o", "1": "l", "3": "e", "5": "s",
})


# --- Helpers ----------------------------------------------------------------

def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'paypa1' and 'pаypal' (Cyrillic а) compare as 'paypal'."""
    s = text.lower().translate(_CONFUSABLES)
    return s.replace("rn", "m").replace("vv", "w")


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def official_brand(p: ParsedURL) -> str | None:
    for brand, domains in BRANDS.items():
        if p.registrable_domain in domains:
            return brand
    return None


def _scripts(label: str) -> set[str]:
    scripts = set()
    for ch in label:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "UNKNOWN").split()[0])
    return scripts


# --- Checks -----------------------------------------------------------------
# Each check takes a ParsedURL and returns a list of Findings (usually 0 or 1).

def check_dangerous_scheme(p: ParsedURL) -> list[Finding]:
    if p.scheme in ("javascript", "vbscript", "data"):
        return [Finding(
            "dangerous_scheme", "high", f"'{p.scheme}:' URL",
            f"A '{p.scheme}:' link does not open a website. It runs code or renders content "
            "directly in your browser. Attackers use this to build fake login pages that have "
            "no domain you could check.",
            p.raw[:80],
        )]
    if p.scheme == "file":
        return [Finding(
            "file_scheme", "medium", "Link to a local or network file",
            "A 'file:' link opens a file on your computer or a network share instead of a website. "
            "Attackers can use it to trigger downloads or leak Windows credentials.",
            p.raw[:80],
        )]
    return []


def check_no_https(p: ParsedURL) -> list[Finding]:
    if p.scheme == "http" and not p.scheme_assumed:
        return [Finding(
            "no_https", "low", "Connection is not encrypted (HTTP)",
            "Anything you type on this page, such as passwords or card numbers, is sent unencrypted. "
            "Most legitimate login and payment pages use HTTPS. Note that HTTPS alone does NOT "
            "mean a site is safe, because phishing sites routinely use it too.",
            "scheme: http",
        )]
    return []


def check_ip_host(p: ParsedURL) -> list[Finding]:
    if p.ip_kind == "obfuscated":
        return [Finding(
            "obfuscated_ip", "high", "Disguised IP address used as host",
            "The host is an IP address written in decimal, hex or octal form so it doesn't look "
            "like an IP. Legitimate sites have no reason to do this. It is a deliberate "
            "obfuscation technique.",
            f"host: {p.host}",
        )]
    if p.ip_kind:
        return [Finding(
            "ip_host", "medium", "Raw IP address instead of a domain name",
            "Legitimate public websites almost always use a domain name. A bare IP address hides "
            "who operates the site and is common in short-lived phishing and malware hosts.",
            f"host: {p.host}",
        )]
    return []


def check_userinfo(p: ParsedURL) -> list[Finding]:
    if p.userinfo:
        return [Finding(
            "userinfo_trick", "high", "Misleading text before '@' in the address",
            "Browsers ignore everything before the '@' in the address part of a URL. "
            f"'{p.userinfo}' is NOT where this link goes. The real destination is '{p.host}'. "
            "This is a classic trick to make a link look like a trusted site.",
            f"ignored part: {p.userinfo!r}  real host: {p.host}",
        )]
    return []


def check_backslash(p: ParsedURL) -> list[Finding]:
    if "\\" in p.raw.split("?", 1)[0]:
        return [Finding(
            "backslash_in_url", "medium", "Backslash in the address",
            "Browsers treat '\\' as '/', but some security tools and people read it differently. "
            "It is used to make the real host look like something else.",
            f"real host: {p.host}",
        )]
    return []


def check_encoded_host(p: ParsedURL) -> list[Finding]:
    if p.host_was_encoded:
        return [Finding(
            "encoded_host", "high", "Percent-encoded characters in the domain",
            "The domain name is written with %-escapes, which hides the real name from a quick "
            "glance. Legitimate links never need this.",
            f"decoded host: {p.host}",
        )]
    return []


def check_idn(p: ParsedURL) -> list[Finding]:
    if not p.host or p.is_ip:
        return []
    labels = p.host_unicode.split(".")
    if not any(not label.isascii() for label in labels) and "xn--" not in p.host:
        return []
    mixed = [label for label in labels if len(_scripts(label)) > 1]
    if mixed:
        return [Finding(
            "mixed_script_domain", "high", "Domain mixes alphabets (homograph attack)",
            "The domain combines letters from different alphabets (for example Latin and "
            "Cyrillic) that look identical on screen. This is almost always done to impersonate "
            "another domain.",
            f"displayed as: {p.host_unicode}  actual: {p.host}  scripts: {', '.join(sorted(_scripts(mixed[0])))}",
        )]
    return [Finding(
        "idn_domain", "medium", "Internationalised (non-ASCII) domain name",
        "The domain uses non-Latin characters (stored as 'xn--' punycode). This is legitimate "
        "for many local-language sites, but is also used to create look-alike domains.",
        f"displayed as: {p.host_unicode}  actual: {p.host}",
    )]


def check_brand_impersonation(p: ParsedURL) -> list[Finding]:
    if not p.host or p.is_ip or official_brand(p):
        return []

    sld_raw = to_unicode(p.sld)
    sld = skeleton(sld_raw)
    sub = skeleton(p.subdomain)
    path_tokens = set(_tokens(skeleton(unquote(p.path + " " + p.query))))

    found: dict[str, Finding] = {}
    for brand, domains in BRANDS.items():
        b = skeleton(brand)
        official = ", ".join(sorted(domains))

        if sld == b and sld_raw.lower() != brand:
            found.setdefault("lookalike_domain", Finding(
                "lookalike_domain", "high", f"Look-alike of '{brand}'",
                f"'{sld_raw}' uses look-alike characters (such as 1 for l, 0 for o, or foreign letters) "
                f"to imitate '{brand}'. The real {brand} uses: {official}.",
                f"domain: {p.registrable_domain}",
            ))
        elif sld == b:
            found.setdefault("brand_unofficial_tld", Finding(
                "brand_unofficial_tld", "low", f"'{brand}' on an unlisted domain ending",
                f"The domain is '{brand}' but with an ending this tool does not know as official "
                f"({official}). Some brands own country-specific domains, so verify it.",
                f"domain: {p.registrable_domain}",
            ))
        elif len(b) >= 5 and levenshtein(sld, b) == 1:
            found.setdefault("typosquat_domain", Finding(
                "typosquat_domain", "high", f"Misspelling of '{brand}' (typosquatting)",
                f"'{p.sld}' is one character different from '{brand}'. Attackers register "
                f"misspelled domains hoping you won't notice. The real {brand} uses: {official}.",
                f"domain: {p.registrable_domain}",
            ))
        elif len(b) >= 5 and b in sld:
            found.setdefault("brand_in_domain", Finding(
                "brand_in_domain", "high", f"'{brand}' embedded in an unrelated domain",
                f"The domain contains '{brand}' but is not owned by {brand} (official: {official}). "
                f"Names like 'secure-{brand}-login' are a common phishing pattern.",
                f"domain: {p.registrable_domain}",
            ))
        elif (b in sub if len(b) >= 5 else b in _tokens(sub)):
            found.setdefault("brand_in_subdomain", Finding(
                "brand_in_subdomain", "high", f"'{brand}' used as a decoy subdomain",
                f"The address starts with '{brand}', but the domain that actually controls this "
                f"site is '{p.registrable_domain}'. Anyone can create subdomains of their own "
                f"domain, so '{brand}.something.{p.suffix}' is not {brand}.",
                f"host: {p.host}  real owner: {p.registrable_domain}",
            ))
        elif b in path_tokens:
            found.setdefault("brand_in_path", Finding(
                "brand_in_path", "medium", f"'{brand}' mentioned in the page path",
                f"The link refers to '{brand}' in its path, but the site belongs to "
                f"'{p.registrable_domain}', not {brand}.",
                f"path: {p.path[:80]}",
            ))
    return list(found.values())


def check_shortener(p: ParsedURL) -> list[Finding]:
    if p.registrable_domain in URL_SHORTENERS or p.host in URL_SHORTENERS:
        return [Finding(
            "url_shortener", "medium", "Shortened link hides the destination",
            "URL shorteners redirect to another address you can't see in advance. That address "
            "is what matters. Expand the link with the shortener's preview feature before visiting.",
            f"shortener: {p.host}",
        )]
    return []


def check_tld(p: ParsedURL) -> list[Finding]:
    tld = p.host.rsplit(".", 1)[-1] if p.host and not p.is_ip else ""
    if tld in FILENAME_LIKE_TLDS:
        return [Finding(
            "filename_like_tld", "medium", f"'.{tld}' domain looks like a file name",
            f"'.{tld}' is a real domain ending, so a link like 'update.{tld}' looks like a file "
            "but opens a website.",
            f"domain ending: .{tld}",
        )]
    if tld in SUSPICIOUS_TLDS:
        return [Finding(
            "suspicious_tld", "low", f"Domain ending '.{tld}' is frequently abused",
            f"'.{tld}' domains are cheap or free to register and appear disproportionately often "
            "in phishing reports. Many legitimate sites use it too, so treat this as weak evidence.",
            f"domain ending: .{tld}",
        )]
    return []


def check_free_hosting(p: ParsedURL) -> list[Finding]:
    if p.registrable_domain in FREE_HOSTING:
        return [Finding(
            "free_hosting", "low", "Hosted on a free / user-content platform",
            f"Anyone can publish a page under '{p.registrable_domain}'. The platform is "
            "legitimate, but its reputation tells you nothing about who made this specific page.",
            f"platform: {p.registrable_domain}  page: {p.host}",
        )]
    return []


def check_keywords(p: ParsedURL) -> list[Finding]:
    if official_brand(p):
        return []
    text = (p.subdomain + " " + p.sld + " " + unquote(p.path + " " + p.query)).lower()
    hits = sorted({k for k in PHISHING_KEYWORDS if k in _tokens(text) or (len(k) >= 6 and k in text)})
    if not hits:
        return []
    return [Finding(
        "phishing_keywords", "medium" if len(hits) >= 2 else "low",
        "Urgency / credential keywords in the URL",
        "Words like 'login', 'verify' or 'account' are used in phishing URLs to make the link "
        "look like an official account page. On their own they are weak evidence.",
        f"keywords: {', '.join(hits)}",
    )]


def check_misleading_tokens(p: ParsedURL) -> list[Finding]:
    host_tokens = _tokens(p.subdomain + "." + p.sld)
    hits = [t for t in host_tokens if t in ("http", "https", "www", "com")]
    # A leading 'www' subdomain is normal; flag it only when it appears elsewhere.
    if p.subdomain.split(".")[0] == "www" and hits[:1] == ["www"]:
        hits = hits[1:]
    if hits:
        return [Finding(
            "misleading_host_tokens", "medium", "Fake 'https', 'www' or '.com' inside the hostname",
            "The hostname contains pieces like 'https', 'www' or 'com' in the middle, "
            "e.g. 'paypal.com-secure.xyz'. These are there to make the address look familiar.",
            f"host: {p.host}",
        )]
    return []


def check_length(p: ParsedURL) -> list[Finding]:
    n = len(p.url)
    if n > 200:
        sev = "medium"
    elif n > 100:
        sev = "low"
    else:
        return []
    return [Finding(
        "long_url", sev, "Unusually long URL",
        "Very long URLs can push the real domain out of view in the address bar or hide "
        "tracking/redirect parameters.",
        f"{n} characters",
    )]


def check_subdomain_depth(p: ParsedURL) -> list[Finding]:
    depth = len(p.subdomain.split(".")) if p.subdomain else 0
    if depth >= 3:
        return [Finding(
            "deep_subdomains", "medium" if depth >= 4 else "low", "Many levels of subdomains",
            "Long chains of subdomains are used to push the real domain off-screen, especially on "
            "mobile, where only the start of the address is visible.",
            f"{depth} subdomain levels in {p.host}",
        )]
    return []


def check_hyphens_digits(p: ParsedURL) -> list[Finding]:
    findings = []
    if p.is_ip or not p.sld:
        return findings
    # Count on the decoded form so punycode's "xn--" prefix isn't mistaken for hyphens.
    if to_unicode(p.sld).count("-") >= 2 or p.host_unicode.count("-") >= 4:
        findings.append(Finding(
            "many_hyphens", "low", "Many hyphens in the domain",
            "Domains like 'secure-account-update-login' are typical of throwaway phishing domains.",
            f"host: {p.host}",
        ))
    digits = sum(c.isdigit() for c in p.sld)
    if len(p.sld) >= 6 and digits / len(p.sld) > 0.3:
        findings.append(Finding(
            "many_digits", "low", "Domain is mostly numbers",
            "Domain names with many digits are often automatically generated.",
            f"domain: {p.registrable_domain}",
        ))
    return findings


def check_random_domain(p: ParsedURL) -> list[Finding]:
    label = p.sld
    if len(label) >= 12 and "-" not in label and shannon_entropy(label) >= 3.6:
        return [Finding(
            "random_domain", "low", "Domain name looks randomly generated",
            "A long, random-looking domain is typical of automatically registered throwaway "
            "domains used for phishing and malware.",
            f"domain: {p.registrable_domain}  (entropy {shannon_entropy(label):.2f})",
        )]
    return []


def check_port(p: ParsedURL) -> list[Finding]:
    if p.port_invalid:
        return [Finding(
            "invalid_port", "high", "Malformed port number",
            "The address contains an invalid port, which suggests a deliberately malformed URL.",
            p.url[:80],
        )]
    if p.port is not None and p.port not in (80, 443, 8080, 8443):
        return [Finding(
            "nonstandard_port", "medium", "Unusual port number",
            "Normal websites use the default ports. A custom port often indicates a temporary or "
            "compromised server.",
            f"port: {p.port}",
        )]
    return []


def check_embedded_redirect(p: ParsedURL) -> list[Finding]:
    decoded = unquote(p.query + " " + p.path[1:])
    m = re.search(r"(https?:)?//[\w.-]+\.[a-z]{2,}", decoded, re.I)
    if m:
        return [Finding(
            "embedded_url", "medium", "Contains another URL (possible redirect)",
            "The link carries a second web address inside it. Attackers abuse redirect features "
            "on trusted sites so that the link starts with a familiar domain but ends up somewhere else.",
            f"embedded: {m.group(0)[:80]}",
        )]
    return []


def check_risky_download(p: ParsedURL) -> list[Finding]:
    path = p.path.lower()
    for ext in RISKY_EXTENSIONS:
        if path.endswith(ext):
            return [Finding(
                "executable_download", "medium", f"Links directly to a '{ext}' file",
                "This link downloads a program or script rather than opening a web page. "
                "Malware is commonly delivered this way.",
                f"path: {p.path[-60:]}",
            )]
    return []


ALL_CHECKS = [
    check_dangerous_scheme,
    check_no_https,
    check_ip_host,
    check_userinfo,
    check_backslash,
    check_encoded_host,
    check_idn,
    check_brand_impersonation,
    check_misleading_tokens,
    check_shortener,
    check_tld,
    check_free_hosting,
    check_keywords,
    check_length,
    check_subdomain_depth,
    check_hyphens_digits,
    check_random_domain,
    check_port,
    check_embedded_redirect,
    check_risky_download,
]


def run_heuristics(p: ParsedURL) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        if p.scheme in ("javascript", "vbscript", "data", "file") and check is not check_dangerous_scheme:
            continue
        findings.extend(check(p))
    return sorted(findings, key=lambda f: -f.weight)


def score(findings: list[Finding]) -> tuple[int, str]:
    """Return (0-100 score, level). Level is at least the most severe single finding."""
    total = min(100, sum(f.weight for f in findings))
    if total >= 50:
        level = "high"
    elif total >= 20:
        level = "medium"
    elif total > 0:
        level = "low"
    else:
        level = "none"
    worst = max((f.severity for f in findings), key=SEVERITY_ORDER.get, default="none")
    if SEVERITY_ORDER[worst] > SEVERITY_ORDER[level]:
        level = worst
    return total, level

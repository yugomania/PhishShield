"""Parse a pasted URL the way a browser would, so heuristics see the real destination."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

try:  # Optional: accurate registrable-domain detection via the Public Suffix List.
    import tldextract

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # bundled snapshot, no network
except ImportError:  # pragma: no cover - depends on environment
    _EXTRACT = None

# Fallback used when tldextract is not installed. Not exhaustive.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za",
    "com.ng", "org.ng", "gov.ng", "edu.ng", "com.gh", "co.ke",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk",
    "co.in", "co.jp", "co.kr", "com.sg", "com.my", "com.pk",
}

NO_HOST_SCHEMES = {"javascript", "data", "vbscript", "file", "blob", "about"}
_OBFUSCATED_IP = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$")


@dataclass(frozen=True)
class ParsedURL:
    raw: str              # exactly what the user pasted
    url: str              # what was parsed (scheme added if missing, tabs/newlines removed)
    scheme: str
    scheme_assumed: bool  # True if the user pasted no scheme and we assumed http://
    host: str             # lowercase ASCII (punycode) form, no port
    host_unicode: str     # human-readable form of internationalised hosts
    host_was_encoded: bool
    port: int | None
    port_invalid: bool
    userinfo: str         # anything before '@' in the authority
    path: str
    query: str
    registrable_domain: str  # e.g. "evil.co.uk" for "login.evil.co.uk"
    subdomain: str
    suffix: str
    ip_kind: str | None   # "ipv4", "ipv6", "obfuscated" or None

    @property
    def is_ip(self) -> bool:
        return self.ip_kind is not None

    @property
    def sld(self) -> str:
        """The registrable label without its suffix, e.g. "paypal" for "paypal.co.uk"."""
        return self.registrable_domain.split(".")[0] if self.registrable_domain else ""


def parse_url(raw: str) -> ParsedURL:
    text = re.sub(r"[\t\r\n]", "", raw.strip())  # browsers silently drop these
    if not text:
        raise ValueError("empty URL")

    scheme_assumed = False
    if "://" not in text and text.split(":", 1)[0].lower() not in NO_HOST_SCHEMES:
        text = "http://" + text
        scheme_assumed = True

    scheme = text.split(":", 1)[0].lower()
    if scheme in NO_HOST_SCHEMES:
        parts = urlsplit(text)
        return ParsedURL(
            raw=raw, url=text, scheme=scheme, scheme_assumed=False, host="", host_unicode="",
            host_was_encoded=False, port=None, port_invalid=False, userinfo="", path=parts.path,
            query=parts.query, registrable_domain="", subdomain="", suffix="", ip_kind=None,
        )

    # Browsers treat '\' as '/' in http(s) URLs. Python doesn't, so normalise first or
    # "http://evil.com\@paypal.com" would be mis-read as having host paypal.com.
    if scheme in ("http", "https"):
        text = text.replace("\\", "/")

    parts = urlsplit(text)
    netloc = parts.netloc
    userinfo = netloc.rpartition("@")[0] if "@" in netloc else ""

    host = (parts.hostname or "").rstrip(".")
    host_was_encoded = "%" in host
    if host_was_encoded:
        host = unquote(host).lower()
    if not host:
        raise ValueError("URL has no host")

    try:
        port, port_invalid = parts.port, False
    except ValueError:
        port, port_invalid = None, True

    host_ascii, host_unicode = _idna_forms(host)
    ip_kind = _ip_kind(host_ascii)

    if ip_kind:
        registrable, subdomain, suffix = host_ascii, "", ""
    else:
        registrable, subdomain, suffix = _split_domain(host_ascii)

    return ParsedURL(
        raw=raw, url=text, scheme=scheme, scheme_assumed=scheme_assumed, host=host_ascii,
        host_unicode=host_unicode, host_was_encoded=host_was_encoded, port=port,
        port_invalid=port_invalid, userinfo=userinfo, path=parts.path, query=parts.query,
        registrable_domain=registrable, subdomain=subdomain, suffix=suffix, ip_kind=ip_kind,
    )


def to_unicode(label: str) -> str:
    """Decode a punycode label/host for display; returns input unchanged on failure."""
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _idna_forms(host: str) -> tuple[str, str]:
    if host.isascii():
        return host, to_unicode(host)
    try:
        return host.encode("idna").decode("ascii"), host
    except UnicodeError:
        return host, host


def _ip_kind(host: str) -> str | None:
    try:
        return f"ipv{ipaddress.ip_address(host).version}"
    except ValueError:
        pass
    # Decimal (3232235777), hex (0xC0A80101) or octal/short dotted forms all resolve to IPs.
    if _OBFUSCATED_IP.match(host):
        return "obfuscated"
    return None


def _split_domain(host: str) -> tuple[str, str, str]:
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}", ext.subdomain, ext.suffix
        return host, "", ext.suffix

    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES else 2
    if len(labels) < n:
        return host, "", labels[-1] if len(labels) > 1 else ""
    return ".".join(labels[-n:]), ".".join(labels[:-n]), ".".join(labels[-(n - 1):])

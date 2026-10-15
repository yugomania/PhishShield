"""Threat-intelligence lookups: the ONLY source of "confirmed malicious" verdicts.

A match here means a curated feed or service has already identified the destination as
phishing/malware. "No match" only means it isn't listed (yet); it does not mean safe.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

from .parsing import ParsedURL, parse_url

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_BLOCKLIST = DATA_DIR / "blocklist.txt"  # hand-maintained by the team
DEFAULT_FEED = DATA_DIR / "openphish.txt"       # overwritten by update_feed()
OPENPHISH_FEED = "https://openphish.com/feed.txt"


@dataclass(frozen=True)
class IntelMatch:
    source: str
    matched: str  # the feed entry or threat type that matched
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntelResult:
    matches: list[IntelMatch] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.matches:
            return "match"
        if not self.sources_checked:
            return "not_checked"
        return "no_match"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "sources_checked": self.sources_checked,
            "matches": [m.to_dict() for m in self.matches],
            "errors": self.errors,
        }


class IntelSource(Protocol):
    name: str

    def check(self, p: ParsedURL) -> list[IntelMatch]: ...


def _url_key(p: ParsedURL) -> str:
    """Scheme-agnostic key: feeds list the same page under http and https."""
    key = p.host + (p.path.rstrip("/") or "")
    return key + ("?" + p.query if p.query else "")


class LocalBlocklist:
    """A newline-separated list of known-bad URLs and/or domains ('#' comments allowed).

    - Entries with a path (e.g. http://evil.example/login) match that exact page only, since
      phishing pages are often hosted on legitimate platforms we must not block wholesale.
    - Bare domains (e.g. evil.example) match the domain and all of its subdomains.
    """

    def __init__(self, entries: list[str], name: str = "Local blocklist"):
        self.name = name
        self.urls: dict[str, str] = {}
        self.domains: set[str] = set()
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                p = parse_url(entry)
            except ValueError:
                continue
            if p.path.strip("/") or p.query:
                self.urls[_url_key(p)] = entry
            else:
                self.domains.add(p.host)

    @classmethod
    def from_file(cls, path: str | Path, name: str | None = None) -> "LocalBlocklist":
        path = Path(path)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
        return cls(lines, name or f"Local blocklist ({path.name})")

    def __len__(self) -> int:
        return len(self.urls) + len(self.domains)

    def check(self, p: ParsedURL) -> list[IntelMatch]:
        if not p.host:
            return []
        key = _url_key(p)
        if key in self.urls:
            return [IntelMatch(self.name, self.urls[key], "Exact URL is listed as malicious")]
        labels = p.host.split(".")
        for i in range(len(labels) - 1):  # host and each parent domain, never a bare TLD
            candidate = ".".join(labels[i:])
            if candidate in self.domains:
                return [IntelMatch(self.name, candidate, "Domain is listed as malicious")]
        return []


class GoogleSafeBrowsing:
    """Google Safe Browsing Lookup API v4. Needs an API key; non-commercial use only per Google's terms."""

    name = "Google Safe Browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    def __init__(self, api_key: str, timeout: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout

    def check(self, p: ParsedURL) -> list[IntelMatch]:
        body = {
            "client": {"clientId": "url-risk-analyser", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": p.url}],
            },
        }
        req = urllib.request.Request(
            self.endpoint.format(key=self.api_key), data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.load(resp)
        return [
            IntelMatch(self.name, m.get("threatType", "UNKNOWN"),
                       f"Flagged as {m.get('threatType', 'a threat').replace('_', ' ').lower()}")
            for m in data.get("matches", [])
        ]


def default_sources(blocklist_path: str | Path | None = None) -> list[IntelSource]:
    sources: list[IntelSource] = [LocalBlocklist.from_file(blocklist_path or DEFAULT_BLOCKLIST)]
    if DEFAULT_FEED.exists():
        sources.append(LocalBlocklist.from_file(DEFAULT_FEED, "OpenPhish feed"))
    if key := os.environ.get("GSB_API_KEY"):
        sources.append(GoogleSafeBrowsing(key))
    return sources


def check_threat_intel(p: ParsedURL, sources: list[IntelSource]) -> IntelResult:
    result = IntelResult()
    for source in sources:
        try:
            matches = source.check(p)
        except Exception as exc:  # network/API failure must not break the analysis
            result.errors.append(f"{source.name}: {exc}")
            continue
        result.sources_checked.append(source.name)
        result.matches.extend(matches)
    return result


def update_feed(dest: str | Path = DEFAULT_FEED, url: str = OPENPHISH_FEED, timeout: float = 30) -> int:
    """Download a plain-text URL feed (OpenPhish community feed by default), replacing dest."""
    req = urllib.request.Request(url, headers={"User-Agent": "url-risk-analyser/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        lines = resp.read().decode("utf-8", errors="replace").splitlines()
    entries = [line.strip() for line in lines if line.strip().startswith(("http://", "https://"))]
    if not entries:
        raise RuntimeError(f"feed at {url} returned no URLs; keeping existing blocklist")

    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=dest.parent, delete=False, encoding="utf-8") as tmp:
        tmp.write(f"# Downloaded from {url}\n" + "\n".join(entries) + "\n")
    os.replace(tmp.name, dest)
    return len(entries)

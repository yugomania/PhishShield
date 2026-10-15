"""Combine threat intelligence (confirmed) and heuristics (risk indicators) into one report."""

from __future__ import annotations

from .heuristics import run_heuristics, score
from .parsing import parse_url
from .threat_intel import IntelSource, check_threat_intel, default_sources

HEURISTIC_DISCLAIMER = (
    "Heuristic findings are warning signs commonly seen in phishing URLs. They are NOT proof "
    "that this URL is malicious, and legitimate sites can trigger them. An empty list does not "
    "prove a URL is safe."
)

_default_sources: list[IntelSource] | None = None


def analyse(raw_url: str, sources: list[IntelSource] | None = None) -> dict:
    """Analyse a pasted URL. Raises ValueError if it can't be parsed as a URL."""
    global _default_sources
    if sources is None:
        if _default_sources is None:
            _default_sources = default_sources()
        sources = _default_sources

    p = parse_url(raw_url)
    intel = check_threat_intel(p, sources)
    findings = run_heuristics(p)
    risk_score, risk_level = score(findings)

    return {
        "input": raw_url,
        "analysed_url": p.url,
        "host": p.host,
        "host_display": p.host_unicode,
        "registrable_domain": p.registrable_domain,
        "verdict": _verdict(intel, findings, risk_level),
        "threat_intelligence": {
            **intel.to_dict(),
            "meaning": (
                "Confirmed: listed by a threat-intelligence source as a known malicious destination."
                if intel.matches else
                "Not on any list checked. Lists only contain threats already reported, so new "
                "phishing sites are often missing."
            ),
        },
        "heuristics": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "disclaimer": HEURISTIC_DISCLAIMER,
            "findings": [f.to_dict() for f in findings],
        },
        "notes": ["No scheme was given, so http:// was assumed for analysis."] if p.scheme_assumed else [],
    }


def _verdict(intel, findings, risk_level: str) -> dict:
    if intel.matches:
        sources = sorted({m.source for m in intel.matches})
        return {
            "category": "confirmed_malicious",
            "label": "Confirmed malicious",
            "summary": f"This destination is listed as malicious by: {', '.join(sources)}. Do not visit it "
                       "or enter any information.",
        }

    unchecked = " No threat-intelligence source could be checked." if intel.status == "not_checked" else ""
    if risk_level in ("medium", "high"):
        return {
            "category": "suspicious",
            "label": f"Suspicious ({risk_level} heuristic risk), not confirmed",
            "summary": f"Not found on any threat list, but shows {len(findings)} warning sign(s) typical "
                       "of phishing. Treat with caution and verify the site independently." + unchecked,
        }
    if risk_level == "low":
        return {
            "category": "low_risk_indicators",
            "label": "Minor warning signs, not confirmed",
            "summary": "Not found on any threat list. A few weak warning signs were found that are also "
                       "common on legitimate sites." + unchecked,
        }
    return {
        "category": "no_indicators",
        "label": "No known threats or warning signs",
        "summary": "Not found on any threat list and no suspicious characteristics detected. This is "
                   "not a guarantee of safety." + unchecked,
    }

# URL Risk Analyser

This is the URL-checking component of the phishing-protection Chrome extension. You paste a URL and get an explained report with **two clearly separated layers**:

| Layer | Question it answers | Can say "malicious"? |
|---|---|---|
| **1. Threat intelligence** | Has this exact destination already been *reported and confirmed* as phishing or malware? | **Yes**, this is the only layer that can |
| **2. Heuristic risk indicators** | Does the URL *look like* a phishing URL? | **No**. It gives warning signs and a 0–100 risk score, never a confirmation |

A URL can be confirmed malicious with no heuristic warnings (a well-disguised phish). A URL can also score 100/100 on heuristics without being confirmed (a brand-new phish that no feed has listed yet). The report always shows both layers separately.

The analyser uses only the Python standard library, so there are no required dependencies. It needs Python 3.10 or newer.

## Usage

```bash
pip install -e .                 # optional; gives you the `url-risk` command
url-risk "http://paypal.com.secure-login.xyz/verify"
python -m url_risk_analyser      # same thing without installing (prompts for a URL)
url-risk --json <url>            # machine-readable output
url-risk --update-feed           # download the latest OpenPhish feed (run daily via cron)
url-risk --serve                 # local API for the extension on http://127.0.0.1:8765
python -m unittest discover -s tests
```

## Verdict categories

| `verdict.category` | Meaning |
|---|---|
| `confirmed_malicious` | Matched a threat-intelligence source |
| `suspicious` | No match, but medium or high heuristic risk. Not confirmed |
| `low_risk_indicators` | No match, with only weak warning signs |
| `no_indicators` | No match and no warning signs. This is **not** a guarantee of safety |

## Heuristic checks

Each finding has an `id`, a `severity` (low=10, medium=25, high=40 points), a plain-language `explanation` of why it matters, and the specific `evidence` from the URL.

* **Deception:** text before `@` (userinfo trick), backslash tricks, percent-encoded host, homograph or mixed-alphabet domains, punycode.
* **Brand impersonation:** look-alike characters (`paypa1`), typosquats (`paypall`), brand embedded in an unrelated domain (`secure-netflix-billing.com`), brand used as a decoy subdomain (`paypal.com.evil.xyz`), brand in the path, and fake `https`/`www`/`com` inside the hostname.
* **Infrastructure:** raw or disguised IP address, unusual port, URL shortener, free hosting platform, frequently abused TLD, `.zip`/`.mov` TLDs.
* **Structure:** no HTTPS, very long URL, deep subdomains, many hyphens or digits, random-looking domain, embedded redirect URL, credential or urgency keywords, direct executable download, and `javascript:`/`data:` schemes.

The analyser parses URLs **the way a browser does**. For example, it treats `\` as `/` and ignores text before `@`. This means it judges the real destination, not the one the URL pretends to have.

## Threat-intelligence sources

* `url_risk_analyser/data/blocklist.txt` is a list the team maintains by hand. A bare domain blocks that domain and all its subdomains. A full URL blocks only that page, because many phishing pages sit on legitimate platforms.
* `url_risk_analyser/data/openphish.txt` comes from the [OpenPhish community feed](https://openphish.com/) via `--update-feed`.
* Google Safe Browsing is used if the `GSB_API_KEY` environment variable is set. Google's terms allow non-commercial use only.

You can add another source, such as URLhaus or PhishTank, by writing a class with a `name` attribute and a `check(parsed_url) -> list[IntelMatch]` method, then adding it in `threat_intel.default_sources()`. If a source fails, the error is reported in `threat_intelligence.errors` and the rest of the analysis still runs.

## Integration with the extension

Run `url-risk --serve`, then call it from the extension:

```js
const res = await fetch("http://127.0.0.1:8765/analyse", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url }),
});
const report = await res.json();
// report.verdict.category, report.threat_intelligence.matches, report.heuristics.findings[]
```

Add `"host_permissions": ["http://127.0.0.1:8765/*"]` to `manifest.json`. `GET /health` lists the active sources. Errors return `400` for a bad request body and `422` for an unparseable URL.

## Limitations

* Without `pip install tldextract` (the `psl` extra), the owner domain is found from a short built-in list of suffixes, so some unusual country suffixes may be mis-split.
* The brand list in `heuristics.BRANDS` is a starting set. Add the banks and services your users rely on.
* Heuristics only look at the URL text. They don't fetch the page, check domain age, or inspect certificates.

# PhishShield

A Chrome extension (Manifest V3) that adds an extra protection layer against phishing websites. It blocks known/configured phishing destinations using Chrome's `declarativeNetRequest` rules, shows a clear warning page when something is blocked, and reports its own status through a popup.

**Status:** Hackathon MVP in progress (12–16 Oct 2026). This README reflects what is actually implemented as of 15 Oct — see [What's implemented vs. not yet](#whats-implemented-vs-not-yet) below.

## Install (load unpacked)

1. Open Google Chrome and go to `chrome://extensions`.
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `PhishShield/` project folder (the one containing `manifest.json`).
4. Confirm the extension appears with **no errors** shown beneath its card.
5. Click the PhishShield icon in the toolbar — the badge should read **ON** (green) once installed.

No build step, no `npm install`, no external services are required for the core blocking feature to work.

## How it works

- `manifest.json` registers a static rule list (`rules.json`) via `declarative_net_request`. These rules block 15 pre-configured fake phishing domains (all on reserved `.test` / `.invalid` TLDs — see `docs/test-domains.md`) by redirecting navigation to `blocked/blocked.html` before the page loads.
- `background.js` is the service worker: it applies the saved protection ON/OFF setting, sets the toolbar badge, and (every 6 hours, plus on install) refreshes an additional *dynamic* rule set built from two live threat feeds (OpenPhish, CERT Polska) — see the note in [Known limitations](#known-limitations).
- `popup/` is the toolbar popup. Currently shows only a one-line protection status (`popup.css` already contains a fuller dashboard design that is not yet wired into `popup.html`).
- `blocked/` is the warning page shown when a site is blocked.
- `shared/storage.js` is a small wrapper around `chrome.storage.local` for settings and (planned) event history.
- `analyser/` is a standalone Python package (`url_risk_analyser`) that analyses a pasted URL for phishing risk indicators. It is **not yet connected** to the extension UI — see below.

## Running the test-domain checks

`docs/test-domains.md` has the full manual test plan (15 blocked domains + 8 safe control sites + step-by-step instructions). At minimum, before every demo run:

```bash
node scripts/validate-rules.js
```

This validates `rules.json` with no external dependencies — plain Node.js. It checks that every rule:
- has a unique `id` and `urlFilter`,
- redirects to exactly `/blocked/blocked.html`,
- targets `main_frame` only,
- and only blocks domains under the reserved `.test` / `.invalid` TLDs (so a misconfigured rule can never accidentally target a real website).

It exits with code `1` and a clear message on the first violation found, or prints `PASS` with a rule count when everything checks out.

## Running the URL risk analyser (optional, standalone)

```bash
cd analyser
pip install -e .                 # optional — gives you the `url-risk` command
url-risk "http://paypal.com.secure-login.xyz/verify"
python -m url_risk_analyser      # same thing without installing, prompts for a URL
url-risk --json <url>            # machine-readable output
url-risk --serve                 # local API on http://127.0.0.1:8765 for future extension integration
```

Requires Python 3.10+, standard library only. See `analyser/README.md` for the full usage guide, verdict categories, and heuristic checks. This component is **not yet called from the extension** — see below.

## What's implemented vs. not yet

| PRD feature | Status |
| --- | --- |
| F01 — Automatic website blocking | **Working.** 15 static test-domain rules block and redirect before page load. |
| F02 — Security warning page | **Partially working.** The page displays, but the static rules don't currently pass the blocked URL/reason as query parameters, so it shows a generic message instead of the specific domain/reason. |
| F03 — Protection popup/dashboard | **Not yet built.** Popup only shows a protection ON/OFF status line. The dashboard layout exists in `popup/popup.css` but isn't wired into `popup.html` yet, and no event counts are shown. |
| F04 — Manual URL risk analyser | **Backend only.** The Python analyser works standalone (CLI + local API) but has no UI in the extension yet. |
| F05 — Security history | **Not yet built.** `shared/storage.js` has an `addEvent()` helper, but nothing currently calls it, so no events are recorded. |

Known open items are tracked as a checklist in the team's QA doc.

## Known limitations

- The background service worker fetches two **live, real-world** phishing-domain feeds (OpenPhish, CERT Polska) on install and every 6 hours, in addition to the 15 static demo rules. This is a deliberate extra capability, but the team should confirm before the Friday demo whether it should be left on, since the PRD lists full external threat-intelligence integration as out of scope for this week.
- If a feed fetch fails (e.g. no internet), the extension logs the error and keeps whatever dynamic rules it already had — it does **not** fall back to blocking nothing. The 15 static demo rules are unaffected either way, since they live in a separate, independent rule set.
- Never collects passwords, OTPs, or page content. No full browsing history is ever sent anywhere. All settings and (future) event data stay in local extension storage only.

## Project structure

```
PhishShield/
├── manifest.json              Extension manifest (MV3)
├── background.js              Service worker: protection state, badge, feed refresh
├── rules.json                 Static declarativeNetRequest rules (15 demo domains)
├── blocking/feed.js           Builds dynamic rules from live threat feeds
├── shared/storage.js          chrome.storage.local wrapper (settings, events)
├── popup/                     Toolbar popup (status display)
├── blocked/                   Warning page shown on a blocked navigation
├── scripts/validate-rules.js  Standalone validator for rules.json
├── docs/test-domains.md       Manual QA test plan and domain reference
└── analyser/                  Standalone Python URL risk analyser (CLI + local API)
```
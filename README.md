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
- `background.js` is the service worker: it applies the saved protection ON/OFF setting, sets the toolbar badge, and schedules dynamic threat-feed refreshes.
- `popup/` is the toolbar popup. Currently shows only a one-line protection status (`popup.css` already contains a fuller dashboard design that is not yet wired into `popup.html`).
- `blocked/` is the warning page shown when a site is blocked. Static and dynamic rules pass the blocked address and a source or demo-pattern reason to it, and it records blocked-site events through `shared/storage.js`.
- `shared/storage.js` is a small wrapper around `chrome.storage.local` for settings and the 50 most recent blocked-site events.
- `analyser/` is a Python package (`url_risk_analyser`) that analyses pasted URLs. Its local API is called by the warning page's **Analyse this URL** control; start it with `python -m url_risk_analyser --serve` from `analyser/`.

## Running the test-domain checks

`docs/test-domains.md` has the full manual test plan (15 blocked domains + 8 safe control sites + step-by-step instructions). At minimum, before every demo run:

```bash
node scripts/validate-rules.js
node scripts/feed.test.cjs
```

The validator checks `rules.json` with no external dependencies — plain Node.js. It checks that every rule:
- has a unique `id` and `urlFilter`,
- redirects to `/blocked/blocked.html` with a `site` query parameter matching the blocked domain,
- targets `main_frame` only,
- and only blocks domains under the reserved `.test` / `.invalid` TLDs (so a misconfigured rule can never accidentally target a real website).

It exits with code `1` and a clear message on the first violation found, or prints `PASS` with a rule count when everything checks out.
The feed fixture checks source-specific redirect details, refresh intervals, failure retention, and rule restoration without making network requests.

## Running the URL risk analyser

```bash
cd analyser
pip install -e .                 # optional — gives you the `url-risk` command
url-risk "http://paypal.com.secure-login.xyz/verify"
python -m url_risk_analyser      # same thing without installing, prompts for a URL
url-risk --json <url>            # machine-readable output
url-risk --serve                 # local API on http://127.0.0.1:8765 for the warning-page analyser
```

Requires Python 3.10+, standard library only. Start the API before using **Analyse this URL** on the warning page. See `analyser/README.md` for verdict categories and heuristic checks.

## What's implemented vs. not yet

| PRD feature | Status |
| --- | --- |
| F01 — Automatic website blocking | **Working.** 15 static test-domain rules block and redirect before page load. |
| F02 — Security warning page | **Working.** Static and dynamic rules pass the blocked address and a source or demo-pattern reason to the warning page. |
| F03 — Protection popup/dashboard | **Not yet built.** Popup only shows a protection ON/OFF status line. The dashboard layout exists in `popup/popup.css` but isn't wired into `popup.html` yet, and no event counts are shown. |
| F04 — Manual URL risk analyser | **Partially integrated.** The warning page lets users enter a URL and view the local analyser report. The popup has no analyser UI. |
| F05 — Security history | **Partially working.** The warning page records blocked-site events locally; the popup does not yet show event history or counts. |

Current manual QA steps are documented in [test-domains.md](docs/test-domains.md), [test-cases.md](docs/test-cases.md), and [demo-script.md](docs/demo-script.md).

## Known limitations

- The background service worker checks the CERT Polska domain feed every 60 minutes and the OpenPhish URL feed every 12 hours, in addition to the 15 static demo rules.
- If a feed fetch fails (e.g. no internet), the extension logs the error and keeps that source's last known-good snapshot and dynamic rules. The 15 static demo rules are unaffected because they use a separate rule set.
- Never collects passwords, OTPs, or page content. No full browsing history is ever sent anywhere. Settings, feed snapshots, and blocked-site events stay in local extension storage only.

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
├── docs/test-cases.md         Manual extension and analyser checks
├── docs/demo-script.md        Presenter walkthrough
└── analyser/                  Standalone Python URL risk analyser (CLI + local API)
```

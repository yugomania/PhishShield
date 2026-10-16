# Demo Q&A Cheat Sheet

## 30-second pitch

PhishShield is a Chrome extension that adds an extra layer of protection against
phishing. It blocks sites from a list of reported phishing sources before the
page loads, shows a clear warning that explains what was blocked, keeps a local
history, and includes a URL checker for a second opinion.

## Words to use and avoid

- Say: "known", "reported", "extra layer", "suspicious", "indicators".
- Avoid: "safe", "100%", "detects all phishing", "AI-powered". None of these are true.

## Likely questions and honest answers

**How is this different from Chrome's built-in Safe Browsing?**
Chrome's protection is larger and more capable, and PhishShield does not replace
it. Ours is an extra layer that is transparent: it uses open public feeds, tells
the user exactly why a site was blocked, and keeps a local history.

**Does it detect brand new phishing sites?**
No. It blocks sites that have already been reported. Brand new sites will not be caught until they appear in a feed. The analyser's URL-pattern checks can flag
suspicious addresses, but they are indicators, not proof.

**How does blocking work?**
We register rules with Chrome's declarativeNetRequest API (The chrome.declarativeNetRequest API is the primary framework used to block or modify network requests in modern Google Chrome extensions (Manifest V3).). Chrome checks each
navigation against the rules before the page loads and redirects matches to our
warning page. Matching happens locally in the browser.

**Where does the blocklist come from?**
Three places: 15 reserved demo domains for testing, the OpenPhish community feed
(exact reported URLs, refreshed every 12 hours), and the CERT Polska domain list
(refreshed every 60 minutes). We keep up to 4,000 live rules, which stays inside
Chrome's limit for redirect rules.

**What about privacy?**
URLs you visit are matched locally and are not sent to a PhishShield server. We
store only settings and the 50 most recent blocked-site events, on your device.
The analyser runs on your own machine and only analyses text you submit. If a
Google Safe Browsing key were configured, submitted URLs would be sent to Google.

**Why does it ask for access to all websites?**
Redirect rules need host access, and the extension also downloads the feeds and
talks to the local analyser. It has no content scripts, so it does not read page
content. We would narrow this before any public release.

**What if a feed is down or the user is offline?**
A failed download never wipes the rules. The last good rules stay active, and
cached rules are restored after a restart.

**What about false positives?**
OpenPhish entries match exact reported URLs, which keeps false positives low. A
protected-host list stops the feed from blocking whole major sites. Domain-level
entries from the CERT list are blocked as a whole. If a block is wrong, the user
can use the warning page's **Proceed anyway** option after confirming the risk.
It allows that site for about 10 minutes, then blocks it again.

**Why a Python analyser if the extension is JavaScript?**
Extensions can only run JavaScript, so the analyser runs as a small local
service on the user's machine. It uses only the Python standard library, never
visits the URL, and only analyses the URL text. The extension still blocks
without it.

**Why not machine learning?**
With five days and no training data, rules and public feeds are more reliable and
easier to explain. ML is a possible future addition.

**Do the demo domains prove it works on real phishing?**
They prove the mechanism: detection, redirect, warning, history. We use reserved
`.test` domains so nobody opens a live phishing site during testing. Live feed
rules use the same mechanism, and the popup shows how many are loaded.

**Does it work on other browsers or phones?**
It is built for desktop Chrome. Other Chromium browsers may work but are untested.
It does not run on mobile Chrome.

**What is the biggest limitation?**
Coverage depends on the feeds. We rely on reports, so there is a delay between a
phishing site going live and it being listed.

**What would you build next?**
A temporary, user-confirmed allow option is available on the warning page. An
analyser inside the popup, automatic checks on suspicious URLs, user reporting,
and more feed sources with confirmed terms of use remain possible future work.

**Who built what?** (each member answers their own part)
Foundation and permissions, blocking engine, warning page, popup dashboard, URL
analyser, and integration and QA.

## If something goes wrong during the demo

- **Analyser not running:** the page shows "could not reach the analyser". Say so,
  start the service, and retry.
- **No internet:** the 15 static demo rules work offline.
- **Extension error:** switch to the recorded backup video.

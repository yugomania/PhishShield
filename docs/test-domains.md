# PhishShield – Test Domains Reference

## Blocked Fake Domains

All domains below use reserved, non-real TLDs (`.test` or `.invalid`). None are real websites. Each is designed to demonstrate a specific phishing technique that PhishShield's blocking engine targets.

| # | Domain | Rule ID | Phishing Pattern |
|---|--------|---------|-----------------|
| 1 | `paypa1-secure.test` | 1 | **Digit-for-letter swap** — `l → 1` in brand name |
| 2 | `micros0ft-login.test` | 2 | **Digit-for-letter swap** — `o → 0` in brand name |
| 3 | `goog1e-verify.test` | 3 | **Digit-for-letter swap** — `l → 1` in brand name |
| 4 | `secure.account-confirm.login.bankofamerica-update.test` | 4 | **Long suspicious subdomain chain** — stacks `secure`, `account-confirm`, `login` labels to bury a fake brand name |
| 5 | `signin.verify.update.appleid-support.test` | 5 | **Long suspicious subdomain chain** — mimics Apple ID with layered keyword subdomains |
| 6 | `amaz0n-order-confirm.test` | 6 | **Digit-for-letter swap + action keyword** — `o → 0` plus `order-confirm` urgency lure |
| 7 | `netfl1x-billing-update.test` | 7 | **Digit-for-letter swap + billing lure** — `i → 1`, billing update urgency |
| 8 | `login.secure-chase-alert.test` | 8 | **Lookalike brand + alert keyword subdomain** — `login.` prefix on fake Chase domain |
| 9 | `dropb0x-fileshare-login.test` | 9 | **Digit-for-letter swap + action keyword** — `o → 0` plus fileshare/login composite |
| 10 | `instagram-password-reset-verify.invalid` | 10 | **Full brand name + credential action chain** — `password-reset-verify` harvesting lure |
| 11 | `wellsfarg0-secure-signin.invalid` | 11 | **Digit-for-letter swap + signin keyword** — `o → 0` on banking brand |
| 12 | `update.account.linked1n-verify.test` | 12 | **Digit-for-letter swap + stacked action subdomains** — `i → 1` in LinkedIn with `update`, `account` prefixes |
| 13 | `ebay-account-suspended-action.invalid` | 13 | **Urgency / account-suspended lure** — suspension threat to provoke immediate action |
| 14 | `tw1tter-security-alert.test` | 14 | **Digit-for-letter swap + security alert lure** — `i → 1` in brand name |
| 15 | `secure.login.verify.auth.steam-support.test` | 15 | **Long suspicious subdomain chain + brand impersonation** — four keyword labels before fake Steam support domain |

---

## Safe Control Sites (Must NOT Be Blocked)

These sites are used to confirm there are no false positives. The extension must let all of these load normally.

| # | URL | Why It's Here |
|---|-----|--------------|
| 1 | `https://www.google.com` | Real Google — must never be blocked |
| 2 | `https://www.paypal.com` | Real PayPal — must never be blocked |
| 3 | `https://www.amazon.com` | Real Amazon — must never be blocked |
| 4 | `https://github.com` | Real GitHub — must never be blocked |
| 5 | `https://www.microsoft.com` | Real Microsoft — must never be blocked |
| 6 | `https://safe.test` | `.test` TLD intentionally absent from rules — must load normally |
| 7 | `https://devenv.test` | Another `.test` domain not in rules — must load normally |
| 8 | `https://localhost.test` | Local dev `.test` domain not in rules — must load normally |

---

## Manual Test Steps

### A — Testing a Blocked Domain (Redirect Confirms)

1. Open Google Chrome.
2. Go to `chrome://extensions`, enable **Developer mode**, then **Load unpacked** pointing at the `PhishShield/` directory.
3. Confirm the extension loads with **no errors** shown beneath it.
4. In the address bar, navigate to one of the blocked domains, for example:
   ```
   http://paypa1-secure.test/login
   ```
5. ✅ **Expected:** Chrome immediately redirects the tab to the extension page `/blocked/blocked.html`. You should NOT see any content from the fake domain.
   The warning page should display the matched domain and its rule-specific demo-pattern explanation.
6. Repeat with at least two more entries from the Blocked Fake Domains table (e.g. `http://micros0ft-login.test` and `http://secure.login.verify.auth.steam-support.test`).

### B — Testing a Safe Control Site (No False Positive)

1. With the extension loaded, navigate to:
   ```
   https://www.paypal.com
   ```
2. ✅ **Expected:** The real PayPal page loads normally. No redirect occurs.
3. Repeat with `https://safe.test` and `https://devenv.test`.
4. ✅ **Expected:** These `.test` domains are not in `rules.json`, so no redirect occurs (they may simply fail to resolve DNS — that is expected; what matters is that PhishShield does **not** redirect them).

---

> **Note for the manifest owner:** `rules.json` must be registered under `declarative_net_request.rule_resources` in `manifest.json`, and the `declarativeNetRequest` permission must be declared. `blocked/blocked.html` may need to be listed under `web_accessible_resources` for the redirect target to resolve correctly.

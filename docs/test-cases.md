# Manual Test Cases

Run the extension checks from the project root:

```bash
node scripts/validate-rules.js
node scripts/feed.test.cjs
```

For analyser cases, start the local API from `analyser/` with
`python3 -m url_risk_analyser --serve`.

| Case | Steps | Expected result |
| --- | --- | --- |
| Static warning | With the extension loaded, visit `http://paypa1-secure.test/`. | The extension redirects to the warning page and displays the matching demo-rule reason. |
| Demo-list analyser match | On the warning page, leave the prefilled URL or enter `http://paypa1-secure.test/`, then select **Analyse this URL**. | The report says **Demo rule match**, names the PhishShield demo source, and does not claim this reserved domain is a live malicious site. Heuristic findings remain a separate section. |
| Manual URL input | Replace the input with `https://www.wikipedia.org/` and analyse it. | The report is for the entered URL, not the blocked page's original URL. Do not require a fixed heuristic score. |
| Invalid URL | Send `{"url":"https://"}` to `POST /analyse`. | The API responds with HTTP 422 and a JSON error. |
| API unavailable | Stop the local API and press **Analyse this URL**. | The warning page shows a readable message that the analyser could not be reached. |
| Duplicate block event | Reload the same warning page within 10 seconds. | The event list does not gain a duplicate event for the same domain. |

The `.test` and `.invalid` domains are reserved demo values. Do not treat their
local-list matches as reports of real phishing sites.

# Manual Test Cases

Run the extension checks from the project root:

```bash
node scripts/validate-rules.js
node scripts/feed.test.cjs
```

For analyser cases, start the local API from `analyser/` with
`python3 -m url_risk_analyser --serve`.

| Case                     | Steps                                                                                                                                                        | Expected result                                                                                                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static warning           | With the extension loaded, visit `http://paypa1-secure.test/`.                                                                                               | The extension redirects to the warning page and displays the matching demo-rule reason.                                                                                                 |
| Demo-list analyser match | On the warning page, leave the prefilled URL or enter `http://paypa1-secure.test/`, then select **Analyse this URL**.                                        | The report says **Demo rule match**, names the PhishShield demo source, and does not claim this reserved domain is a live malicious site. Heuristic findings remain a separate section. |
| Manual URL input         | Replace the input with `https://www.wikipedia.org/` and analyse it.                                                                                          | The report is for the entered URL, not the blocked page's original URL. Do not require a fixed heuristic score.                                                                         |
| Invalid URL              | Send `{"url":"https://"}` to `POST /analyse`.                                                                                                                | The API responds with HTTP 422 and a JSON error.                                                                                                                                        |
| API unavailable          | Stop the local API and press **Analyse this URL**.                                                                                                           | The warning page shows a readable message that the analyser could not be reached.                                                                                                       |
| Popup URL analysis       | Start the local API. Open the popup, leave the active-tab URL or enter `http://paypa1-secure.test/`, then select **Analyse**.                                 | The popup displays the **Demo rule match** verdict, source, heuristic findings, and disclaimer without opening the URL.                                                                    |
| Popup analyser unavailable | Stop the local API, enter `https://example.com/` in the popup, and select **Analyse**.                                                                         | The popup shows a readable service-unavailable message and remains usable.                                                                                                               |
| Popup invalid URL        | Enter `javascript:alert(1)` in the popup and select **Analyse**.                                                                                              | The popup rejects it locally and sends no request to the analyser.                                                                                                                        |
| Duplicate block event    | Reload the same warning page within 10 seconds.                                                                                                              | The event list does not gain a duplicate event for the same domain.                                                                                                                     |
| Proceed confirmation    | On a warning page, select **Proceed anyway** without checking the confirmation box.                                                                          | **Continue to website** stays disabled. Selecting **Cancel** closes the confirmation.                                                                                                    |
| Temporary proceed       | On a `.test` warning page, confirm the risk and continue.                                                                                                    | The tab navigates to the requested host; Chrome may say the reserved demo domain cannot be reached. The host is allowed only for main-frame navigation and is blocked again after about 10 minutes. |
| Live feeds loaded        | Reload the extension, wait 30 seconds, open the service worker console and run the commands in **Live feed checks** below. Internet is needed on first load. | The dynamic rule count is greater than 0 and no more than 4000. `feedStatus` exists and shows update information.                                                                       |
| Popup matches Chrome     | Open the popup and compare **Dynamic feed rules** with the service worker console count.                                                                     | Both numbers match.                                                                                                                                                                     |
| Protection OFF           | Turn protection off in the popup, check the service worker console count, then visit `http://paypa1-secure.test/`.                                           | The dynamic rule count is 0, the demo domain does not redirect, and the toolbar icon shows its off state.                                                                               |
| Protection back ON       | Turn protection on again and wait a few seconds. Visit `http://paypa1-secure.test/`.                                                                         | The dynamic rule count returns above 0, the demo domain redirects to the warning page, and the icon shows its on state.                                                                 |
| Offline restart          | After a successful first load, disconnect the network, restart Chrome with protection ON, and check the service worker console count.                        | The dynamic rule count stays above 0 and the demo domain still redirects.                                                                                                               |
| Feed failure             | Run `node scripts/feed.test.cjs`.                                                                                                                            | All checks pass, including keeping old rules after a failed refresh.                                                                                                                    |
| Safe sites               | With protection ON, open the 8 safe control sites from `docs/test-domains.md`.                                                                               | Every site loads normally and none is blocked.                                                                                                                                          |
| History persists         | Block two different demo domains, close the popup and reopen it.                                                                                             | Both events appear with their domain and time.                                                                                                                                          |
| Small screen             | Open the warning page in a browser window about 360 px wide.                                                                                                 | The layout stays readable without horizontal scrolling, and all buttons remain usable.                                                                                                  |

## Live feed checks

Open `chrome://extensions`, click **service worker** on the PhishShield card,
then run these commands in its console:

```js
(await chrome.declarativeNetRequest.getDynamicRules()).length;
await chrome.storage.local.get(["feedStatus", "feedSourcesStatus"]);
```

## Testing safety

Never open URLs taken from the live feeds. They may be active phishing sites.
Test blocking only with the reserved `.test` and `.invalid` demo domains.

## Test run log

| Tester | Date | Case | Pass / Fail | Notes |
| ------ | ---- | ---- | ----------- | ----- |
|        |      |      |             |       |

The `.test` and `.invalid` domains are reserved demo values. Do not treat their
local-list matches as reports of real phishing sites.

# Demo Script

## Before the demo

1. From the project root, run `node scripts/validate-rules.js` and
   `node scripts/feed.test.cjs`.
2. Start the analyser in a terminal and leave it running:

   ```bash
   cd analyser
   python3 -m url_risk_analyser --serve
   ```

3. Load or reload the project as an unpacked extension in Chrome.

## Walkthrough

1. Visit `http://paypa1-secure.test/`. The static extension rule redirects to
   the PhishShield warning page without opening a live phishing site.
2. Show the blocked hostname and the rule-specific explanation.
3. In **Analyse this URL**, enter `http://paypa1-secure.test/` and select
   **Analyse this URL**. Explain that the report distinguishes the local demo
   rule match from heuristic indicators; this reserved test domain is not a
   confirmed live threat.
4. Replace it with `https://www.wikipedia.org/` and analyse it to demonstrate
   that the field accepts a URL other than the blocked address.
5. Open a regular web tab and open the PhishShield popup. Show that the URL
   field is prefilled with the active tab's address, then select **Analyse**.
   Explain that the popup checks URL text through the local analyser and does
   not open the submitted address.
6. Select **Proceed anyway**, tick **I understand the risk**, then select
   **Continue to website**. Explain that the reserved `.test` domain will show
   Chrome's “This site can’t be reached” message because it does not exist; the
   temporary allow rule lifts PhishShield's block for about 10 minutes.
7. If the local service is stopped, the page reports that it cannot reach the
   analyser. Restart the service to restore analysis.

The analyser evaluates the submitted URL text. It does not visit the URL or
inspect the destination page.

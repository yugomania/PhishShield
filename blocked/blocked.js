
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const urlElement = document.getElementById("blocked-url");
  const reasonElement = document.getElementById("block-reason");
  const riskElement = document.getElementById("risk-level");
  const noticeElement = document.getElementById("notice");
  const copyButton = document.getElementById("copy-url");
  const backButton = document.getElementById("go-back");
  const closeButton = document.getElementById("close-tab");
  const analyseButton = document.getElementById("analyse-url");
  const urlInput = document.getElementById("url-input");
  const analysisResult = document.getElementById("analysis-result");

  let blockedUrl = "";
  let returnUrl = "";

  function getSafeUrl(value) {
    if (typeof value !== "string" || !value.trim()) {
      return "";
    }

    try {
      const parsed = new URL(value);

      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return "";
      }

      return parsed.href;
    } catch {
      return "";
    }
  }

  function displayUrl(value) {
    blockedUrl = getSafeUrl(value);

    urlElement.textContent = blockedUrl || "Website address unavailable";
    copyButton.disabled = !blockedUrl;
    if (blockedUrl && !urlInput.value.trim()) {
      urlInput.value = blockedUrl;
    }
  }

  function showNotice(message) {
    noticeElement.textContent = message;
  }

  function loadBlockDetails() {
    const params = new URLSearchParams(window.location.search);
    // Support the original URL passed to the blocked page.
    const queryUrl =
      params.get("url") ||
      params.get("blockedUrl") ||
      params.get("blocked_url");
    const site = params.get("site");

    // Query-string values are display data, not proof of a real threat.
    displayUrl(queryUrl || (site ? `https://${site}/` : ""));

    let eventDomain = "";
    try {
      const parsed = new URL(queryUrl || (site ? `https://${site}/` : ""));
      if (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        !parsed.username &&
        !parsed.password
      ) {
        eventDomain = parsed.hostname;
      }
    } catch {
      // No usable site was passed to the warning page.
    }

    if (
      eventDomain &&
      typeof PhishStore !== "undefined" &&
      typeof PhishStore.addEvent === "function"
    ) {
      const reason = params.get("reason") || "The website matched a security rule.";
      PhishStore.addEvent({
        domain: eventDomain,
        url: blockedUrl,
        reason: reason.slice(0, 500),
      }).catch((err) => {
        console.error("PhishShield: could not record blocked-site event", err);
      });
    }

    const reason = params.get("reason");
    if (reason) {
      reasonElement.textContent = reason.slice(0, 500);
    }

    const level = params.get("risk");
    if (level && /^(low|medium|high|critical|suspicious|phishing)$/i.test(level)) {
      riskElement.textContent = level.toUpperCase();
    }

    // Chrome extension integrations can provide the blocked URL and
    // return destination through extension storage.
    if (typeof chrome !== "undefined" && chrome.storage?.local) {
      chrome.storage.local.get(
        ["blockedUrl", "blockReason", "riskLevel", "returnUrl"],
        (data) => {
          if (chrome.runtime?.lastError) {
            return;
          }

          if (data.blockedUrl) {
            displayUrl(data.blockedUrl);
          }

          if (typeof data.blockReason === "string" && data.blockReason.trim()) {
            reasonElement.textContent = data.blockReason.slice(0, 500);
          }

          if (
            typeof data.riskLevel === "string" &&
            /^(low|medium|high|critical|suspicious|phishing)$/i.test(data.riskLevel)
          ) {
            riskElement.textContent = data.riskLevel.toUpperCase();
          }

          returnUrl = getSafeUrl(data.returnUrl);
        }
      );
    }
  }

  copyButton.addEventListener("click", async () => {
    if (!blockedUrl) {
      showNotice("No valid website address is available to copy.");
      return;
    }

    try {
      await navigator.clipboard.writeText(blockedUrl);
      showNotice("Blocked website address copied.");
    } catch {
      // Clipboard access may be unavailable in some extension contexts.
      showNotice("Copy unavailable. You can select the website address manually.");
    }
  });

  backButton.addEventListener("click", () => {
    // Never send the user back to the blocked destination.
    if (returnUrl) {
      if (typeof chrome !== "undefined" && chrome.tabs?.create) {
        chrome.tabs.create({ url: returnUrl });
        return;
      }

      window.location.assign(returnUrl);
      return;
    }

    if (window.history.length > 1) {
      window.history.back();
      return;
    }

    showNotice(
      "No previous page is available. Use the browser's address bar to open a trusted website."
    );
  });

  closeButton.addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs?.getCurrent) {
      chrome.tabs.getCurrent((tab) => {
        if (tab?.id !== undefined) {
          chrome.tabs.remove(tab.id);
        } else {
          showNotice("Please close this tab using your browser controls.");
        }
      });
      return;
    }

    window.close();
    showNotice("If the tab remains open, close it using your browser controls.");
  });

  loadBlockDetails();

  function formatAnalysisReport(report) {
    const verdict = report.verdict;
    const intel = report.threat_intelligence;
    const heuristics = report.heuristics;

    const lines = [
      `Verdict: ${verdict.label}`,
      verdict.summary,
      "",
      `Threat intelligence: ${
        intel.matches.length
          ? intel.matches
              .map((match) => `${match.source}: ${match.detail}`)
              .join("\n")
          : "No threat-intelligence match."
      }`,
      "",
      `Heuristic risk: ${heuristics.risk_score}/100 (${heuristics.risk_level})`,
    ];

    if (heuristics.findings.length) {
      lines.push(
        "",
        ...heuristics.findings.map(
          (finding) => `• ${finding.title}: ${finding.explanation}`,
        ),
      );
    } else {
      lines.push("No heuristic warning signs were found.");
    }

    if (intel.errors.length) {
      lines.push("", `Source errors: ${intel.errors.join("; ")}`);
    }

    return lines.join("\n");
  }

  async function analyseBlockedUrl() {
    const urlToAnalyse = getSafeUrl(urlInput.value);
    if (!urlToAnalyse) {
      analysisResult.hidden = false;
      analysisResult.textContent = "Enter a valid HTTP or HTTPS URL to analyse.";
      return;
    }

    analyseButton.disabled = true;
    analyseButton.textContent = "Analysing…";
    analysisResult.hidden = false;
    analysisResult.textContent = "Checking the URL…";

    try {
      const response = await fetch("http://127.0.0.1:8765/analyse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToAnalyse }),
      });

      const report = await response.json();

      if (!response.ok) {
        throw new Error(
          report.error || `Analysis failed (${response.status}).`,
        );
      }

      analysisResult.textContent = formatAnalysisReport(report);
    } catch (error) {
      analysisResult.textContent =
        `Could not reach the analyser. Make sure its local service is running. ` +
        `${error.message}`;
    } finally {
      analyseButton.disabled = false;
      analyseButton.textContent = "Analyse this URL";
    }
  }

  analyseButton.addEventListener("click", analyseBlockedUrl);
});

const form = document.getElementById("scan-form");
const input = document.getElementById("url-input");
const button = document.getElementById("scan-button");
const result = document.getElementById("scan-result");

async function loadProtectionStatus() {
  const status = document.getElementById("status");
  const value = document.getElementById("protection-value");
  const count = document.getElementById("history-count");
  const pill = document.getElementById("protection-pill");

  try {
    const [settings, historyCount] = await Promise.all([
      PhishStore.getSettings(),
      PhishStore.getEventCount(),
    ]);
    const enabled = Boolean(settings.protectionEnabled);
    status.textContent = enabled ? "Protection on" : "Protection off";
    value.textContent = enabled ? "ON" : "OFF";
    count.textContent = String(historyCount);
    pill.dataset.enabled = String(enabled);
  } catch (error) {
    console.error("PhishShield: could not load protection status", error);
    status.textContent = "Status unavailable";
    value.textContent = "unavailable";
    count.textContent = "—";
  }
}

function showMessage(message, kind = "neutral") {
  result.className = `scan-result ${kind}`;
  result.replaceChildren();
  const paragraph = document.createElement("p");
  paragraph.className = "result-message";
  paragraph.textContent = message;
  result.append(paragraph);
}

function renderReport(report) {
  const verdict = report.verdict || {};
  const heuristics = report.heuristics || {};
  const intel = report.threat_intelligence || {};
  const category = verdict.category || "neutral";
  const kind = category === "confirmed_malicious" || category === "suspicious"
    ? "warning"
    : category === "demo_rule_match" ? "demo" : "safe";

  result.className = `scan-result ${kind}`;
  result.replaceChildren();

  const heading = document.createElement("h3");
  heading.textContent = verdict.label || "Analysis complete";
  result.append(heading);

  const summary = document.createElement("p");
  summary.className = "result-message";
  summary.textContent = verdict.summary || "No summary was returned.";
  result.append(summary);

  const details = document.createElement("p");
  details.className = "result-details";
  details.textContent = `Heuristic risk: ${heuristics.risk_score ?? "—"}/100 (${heuristics.risk_level || "unknown"}). Threat-list matches: ${Array.isArray(intel.matches) ? intel.matches.length : 0}.`;
  result.append(details);

  const findings = Array.isArray(heuristics.findings) ? heuristics.findings : [];
  if (findings.length) {
    const list = document.createElement("ul");
    list.className = "finding-list";
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = finding.explanation
        ? `${finding.title || "Warning sign"}: ${finding.explanation}`
        : finding.title || "Warning sign";
      list.append(item);
    }
    result.append(list);
  }

  const disclaimer = document.createElement("p");
  disclaimer.className = "result-disclaimer";
  disclaimer.textContent = "A low-risk result does not guarantee that a site is safe.";
  result.append(disclaimer);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) {
    showMessage("Enter a website address first.", "warning");
    return;
  }

  button.disabled = true;
  button.textContent = "Checking...";
  showMessage("Analysing the address...");

  try {
    const response = await fetch("http://127.0.0.1:8765/analyse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `The analyser returned error ${response.status}.`);
    }
    renderReport(payload);
  } catch (error) {
    console.error("PhishShield: URL analysis failed", error);
    showMessage(
      "Could not reach the local URL analyser. Start it from the analyser folder, then try again.",
      "warning",
    );
  } finally {
    button.disabled = false;
    button.textContent = "Check link";
  }
});

loadProtectionStatus();

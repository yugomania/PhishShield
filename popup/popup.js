const HISTORY_LIMIT = 5;
const ANALYSER_API_URL = "http://127.0.0.1:8765/analyse";
const ANALYSER_TIMEOUT_MS = 15_000;

const popupState = {
  settings: { protectionEnabled: true },
  history: [],
  feedStatus: null,
  feedSourcesStatus: {},
  activeTabUrl: "",
};

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = value;
}

function formatTimestamp(value, fallback = "—") {
  if (!Number.isFinite(value)) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(date);
}

function normalizeAnalyserUrl(value) {
  if (typeof value !== "string" || !value.trim()) return null;

  try {
    const url = new URL(value.trim());
    if (
      (url.protocol !== "http:" && url.protocol !== "https:") ||
      url.username ||
      url.password
    ) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}

function formatAnalysisReport(report) {
  const verdict = report?.verdict || {};
  const intel = report?.threat_intelligence || {};
  const heuristics = report?.heuristics || {};
  const matches = Array.isArray(intel.matches) ? intel.matches : [];
  const findings = Array.isArray(heuristics.findings) ? heuristics.findings : [];
  const lines = [
    `Verdict: ${verdict.label || "Result unavailable"}`,
    verdict.summary || "The analyser did not provide a verdict summary.",
    "",
    `Threat intelligence: ${matches.length
      ? matches.map((match) => {
          const details = [match.source, match.detail, match.matched]
            .filter((value) => typeof value === "string" && value)
            .join(" — ");
          return details || "Threat-intelligence match";
        }).join("\n")
      : "No threat-intelligence match."}`,
  ];

  if (typeof intel.meaning === "string" && intel.meaning) {
    lines.push(intel.meaning);
  }

  lines.push(
    "",
    `Heuristic risk: ${Number.isFinite(heuristics.risk_score) ? heuristics.risk_score : "—"}/100 (${heuristics.risk_level || "unknown"})`,
  );

  if (findings.length) {
    lines.push(
      "",
      ...findings.map((finding) =>
        `• ${finding.title || "Finding"}: ${finding.explanation || "Details unavailable."}`,
      ),
    );
  } else {
    lines.push("No heuristic warning signs were found.");
  }

  if (typeof heuristics.disclaimer === "string" && heuristics.disclaimer) {
    lines.push("", heuristics.disclaimer);
  }
  if (Array.isArray(intel.errors) && intel.errors.length) {
    lines.push("", `Source errors: ${intel.errors.join("; ")}`);
  }
  if (Array.isArray(report?.notes) && report.notes.length) {
    lines.push("", ...report.notes);
  }

  return lines.join("\n");
}

function setAnalyserStatus(message, state = "") {
  const status = byId("analyser-status");
  if (!status) return;
  status.textContent = message;
  status.classList.remove("is-error", "is-success");
  if (state) status.classList.add(`is-${state}`);
}

async function analyseUrlFromPopup(event) {
  event.preventDefault();
  const input = byId("analyser-url");
  const button = byId("analyser-submit");
  const result = byId("analyser-result");
  const url = normalizeAnalyserUrl(input.value);

  if (!url) {
    result.hidden = true;
    setAnalyserStatus("Enter a valid HTTP or HTTPS URL without a username or password.", "error");
    input.focus();
    return;
  }

  button.disabled = true;
  button.textContent = "Analysing…";
  result.hidden = true;
  result.textContent = "";
  setAnalyserStatus("Checking the URL text with the local analyser…");

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), ANALYSER_TIMEOUT_MS);
  try {
    const response = await fetch(ANALYSER_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    let report;
    try {
      report = await response.json();
    } catch {
      throw new Error(`The analyser returned an unreadable response (HTTP ${response.status}).`);
    }
    if (!response.ok) {
      throw new Error(report?.error || `Analysis failed (HTTP ${response.status}).`);
    }

    result.textContent = formatAnalysisReport(report);
    result.hidden = false;
    setAnalyserStatus("Analysis complete. Results are indicators, not a guarantee of safety.", "success");
  } catch (error) {
    const detail = error.name === "AbortError"
      ? "The analyser took too long to respond."
      : error.message;
    setAnalyserStatus(
      `Could not reach or use the local analyser. Make sure it is running, then try again. ${detail}`,
      "error",
    );
  } finally {
    clearTimeout(timeoutId);
    button.disabled = false;
    button.textContent = "Analyse";
  }
}

function renderProtection() {
  const enabled = popupState.settings.protectionEnabled !== false;
  const toggle = byId("protection-toggle");
  const connection = byId("connection-status");
  const card = document.querySelector(".protection-card");

  setText("status", enabled ? "Protection: ON" : "Protection: OFF");
  setText("connection-label", enabled ? "Protection active" : "Protection paused");
  setText("status-detail", enabled ? "Blocking rules are enabled" : "Blocking rules are disabled");

  if (toggle) {
    toggle.disabled = false;
    toggle.textContent = enabled ? "Turn protection off" : "Turn protection on";
    toggle.setAttribute("aria-pressed", String(enabled));
  }
  connection?.classList.toggle("is-disabled", !enabled);
  card?.classList.toggle("is-disabled", !enabled);
}

function renderHistory() {
  const events = Array.isArray(popupState.history) ? popupState.history : [];
  const list = byId("history-list");
  setText("stat-recent-blocks", String(events.length));
  setText(
    "stat-unique-domains",
    String(new Set(events.map((event) => String(event?.domain || "").toLowerCase()).filter(Boolean)).size),
  );
  setText("history-count", `${events.length} STORED`);
  if (!list) return;

  list.replaceChildren();
  if (events.length === 0) {
    const empty = document.createElement("li");
    empty.className = "history-empty";
    empty.textContent = "No blocked websites recorded yet.";
    list.append(empty);
    return;
  }

  for (const event of events.slice(0, HISTORY_LIMIT)) {
    const item = document.createElement("li");
    item.className = "history-item";

    const details = document.createElement("span");
    details.className = "history-details";
    const domain = document.createElement("strong");
    domain.className = "history-domain";
    domain.textContent = typeof event?.domain === "string" ? event.domain : "Unknown website";
    const reason = document.createElement("span");
    reason.className = "history-reason";
    reason.textContent = typeof event?.reason === "string" && event.reason
      ? event.reason
      : "Blocked by a configured protection rule";
    details.append(domain, reason);

    const time = document.createElement("time");
    time.className = "history-time";
    time.textContent = formatTimestamp(event?.timestamp, "Time unavailable");
    if (Number.isFinite(event?.timestamp)) {
      time.dateTime = new Date(event.timestamp).toISOString();
    }
    item.append(details, time);
    list.append(item);
  }
}

function getFeedSources() {
  const sourceStatus = popupState.feedStatus?.sources || popupState.feedSourcesStatus;
  return Object.values(sourceStatus || {});
}

function renderFeeds() {
  const feedStatus = popupState.feedStatus || {};
  const sources = getFeedSources();
  const readyCount = sources.filter((source) => source?.ok === true).length;
  const failedCount = sources.filter((source) => source?.ok === false).length;

  const activeRuleCount = popupState.settings.protectionEnabled === false
    ? 0
    : feedStatus.count;
  setText("stat-feed-rules", Number.isFinite(activeRuleCount) ? String(activeRuleCount) : "—");
  const lastUpdate = Number.isFinite(feedStatus.updatedAt)
    ? feedStatus.updatedAt
    : Math.max(0, ...sources.map((source) => source?.lastSuccess).filter(Number.isFinite));
  setText("stat-last-feed", lastUpdate ? formatTimestamp(lastUpdate, "Pending") : "Pending");

  let summary = "FEEDS PENDING";
  if (sources.length > 0) {
    summary = failedCount > 0
      ? `${readyCount}/${sources.length} FEEDS UPDATED`
      : `${readyCount}/${sources.length} FEEDS READY`;
    if (readyCount === 0 && failedCount > 0) summary = "FEED UPDATE FAILED";
  }
  setText("feed-summary", summary);
}

function renderCurrentSite() {
  const badge = byId("current-site-badge");
  let hostname = "";
  try {
    const url = new URL(popupState.activeTabUrl);
    if (url.protocol === "http:" || url.protocol === "https:") hostname = url.hostname;
  } catch {
    // Browser-internal and unavailable tab URLs are intentionally not shown.
  }

  setText("current-site", hostname || "Open a tab to see site status");
  setText("current-site-detail", hostname ? "Hostname of the active tab" : "No web address is available for this tab.");
  if (badge) {
    badge.textContent = popupState.settings.protectionEnabled === false
      ? "Protection paused"
      : "Protection active";
    badge.classList.toggle("is-disabled", popupState.settings.protectionEnabled === false);
  }
}

function render() {
  renderProtection();
  renderHistory();
  renderFeeds();
  renderCurrentSite();
  // Preserve a simple model for future popup features without exposing it in
  // markup or requiring another script to read browser storage directly.
  window.phishShieldPopupData = {
    history: popupState.history,
    historyCount: popupState.history.length,
    feedStatus: popupState.feedStatus,
    activeTabUrl: popupState.activeTabUrl,
  };
}

async function loadActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    popupState.activeTabUrl = typeof tab?.url === "string" ? tab.url : "";
    const input = byId("analyser-url");
    const tabUrl = normalizeAnalyserUrl(popupState.activeTabUrl);
    if (input && tabUrl && !input.value.trim()) input.value = tabUrl;
  } catch (error) {
    console.warn("PhishShield: could not read active tab", error);
    popupState.activeTabUrl = "";
  }
}

byId("analyser-form")?.addEventListener("submit", analyseUrlFromPopup);

async function loadPopupData() {
  const [settings, history, stored] = await Promise.all([
    PhishStore.getSettings(),
    PhishStore.getHistory(),
    chrome.storage.local.get(["feedStatus", "feedSourcesStatus"]),
  ]);
  popupState.settings = settings;
  popupState.history = Array.isArray(history) ? history : [];
  popupState.feedStatus = stored.feedStatus || null;
  popupState.feedSourcesStatus = stored.feedSourcesStatus || {};
  await loadActiveTab();
  render();
}

async function toggleProtection() {
  const toggle = byId("protection-toggle");
  if (toggle) toggle.disabled = true;
  const nextValue = popupState.settings.protectionEnabled === false;
  try {
    await PhishStore.setProtection(nextValue);
    popupState.settings = { ...popupState.settings, protectionEnabled: nextValue };
  } catch (error) {
    console.error("PhishShield: could not update protection setting", error);
  } finally {
    render();
  }
}

byId("protection-toggle")?.addEventListener("click", toggleProtection);

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.settings) {
    popupState.settings = changes.settings.newValue || { protectionEnabled: true };
  }
  if (changes.events) {
    popupState.history = Array.isArray(changes.events.newValue) ? changes.events.newValue : [];
  }
  if (changes.feedStatus) popupState.feedStatus = changes.feedStatus.newValue || null;
  if (changes.feedSourcesStatus) popupState.feedSourcesStatus = changes.feedSourcesStatus.newValue || {};
  render();
});

window.phishShieldPopupReady = loadPopupData().catch((error) => {
  console.error("PhishShield: could not load popup data", error);
  setText("status", "Status unavailable");
  setText("connection-label", "Could not read settings");
  setText("status-detail", "Close and reopen the popup to retry");
});

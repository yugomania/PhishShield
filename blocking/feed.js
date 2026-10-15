// OpenPhish publishes URL indicators; CERT Polska publishes active domains.
// The scheduler checks CERT every 5 minutes and OpenPhish every 12 hours.
const FEEDS = [
  {
    id: "openphish",
    name: "OpenPhish",
    url: "https://openphish.com/feed.txt",
    intervalMs: 12 * 60 * 60 * 1000,
    reason: "This URL is listed in the OpenPhish phishing feed.",
    parse: parseUrlFeed,
  },
  {
    id: "certPolska",
    name: "CERT Polska",
    url: "https://hole.cert.pl/domains/v2/domains.txt",
    intervalMs: 5 * 60 * 1000,
    reason: "This domain appears on the CERT Polska warning list.",
    parse: parseDomainFeed,
  },
];

const MAX_RULES = 4000;
const FEED_SNAPSHOTS_KEY = "feedSnapshots";
const FEED_ATTEMPTS_KEY = "feedAttempts";
const FEED_SOURCES_STATUS_KEY = "feedSourcesStatus";
const PROTECTED_HOSTS = [
  "google.com",
  "paypal.com",
  "microsoft.com",
  "amazon.com",
  "apple.com",
  "github.com",
];

let feedRefreshPromise = null;

function isProtected(host) {
  return PROTECTED_HOSTS.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function parseUrlFeed(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function parseDomainFeed(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function normalizeOpenPhishUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;

  const host = url.hostname.toLowerCase();
  if (!host || /[*|^]/.test(url.host + url.pathname + url.search)) return null;
  if (isProtected(host) && url.pathname === "/" && !url.search) return null;

  // Fragments are not sent in HTTP requests, so they cannot be DNR matches.
  url.hash = "";
  return {
    host,
    url: url.href,
    matchFilter: `||${url.host}${url.pathname}${url.search}|`,
  };
}

function normalizeCertDomain(value) {
  if (typeof value !== "string") return null;
  let url;
  try {
    url = new URL(`https://${value}/`);
  } catch {
    return null;
  }

  const host = url.hostname.toLowerCase();
  // CERT's text feed is domains-only; reject entries that parsed as URLs,
  // ports, or paths instead of broadening an unintended entry.
  if (host !== value.toLowerCase() || url.port || url.search || url.hash) return null;
  if (isProtected(host)) return null;
  return { host, matchFilter: `||${host}^` };
}

function normalizeFeedItems(feed, items) {
  const normalized = [];
  const seen = new Set();

  for (const item of items) {
    const target = feed.id === "certPolska"
      ? normalizeCertDomain(item)
      : normalizeOpenPhishUrl(item);
    if (!target || seen.has(target.matchFilter)) continue;
    seen.add(target.matchFilter);

    // Store only the source's canonical indicator. The host and match pattern
    // are derived when rules are rebuilt, keeping local snapshots compact.
    normalized.push(feed.id === "certPolska" ? { host: target.host } : { url: target.url });
  }

  return normalized.slice(0, MAX_RULES);
}

function buildRules(snapshots) {
  const seen = new Set();
  const rules = [];

  for (const feed of FEEDS) {
    const entries = Array.isArray(snapshots[feed.id]) ? snapshots[feed.id] : [];

    for (const entry of entries) {
      if (rules.length >= MAX_RULES) return rules;
      const target = feed.id === "certPolska"
        ? normalizeCertDomain(entry?.host)
        : normalizeOpenPhishUrl(entry?.url);
      if (!target || seen.has(target.matchFilter)) continue;
      seen.add(target.matchFilter);

      const query = new URLSearchParams({
        site: target.host,
        reason: feed.reason,
      });
      if (feed.id === "openphish") {
        query.set("url", target.url);
      }

      rules.push({
        id: rules.length + 1,
        priority: 1,
        action: {
          type: "redirect",
          redirect: {
            extensionPath: `/blocked/blocked.html?${query.toString()}`,
          },
        },
        condition: { urlFilter: target.matchFilter, resourceTypes: ["main_frame"] },
      });
    }
  }

  return rules;
}

async function fetchFeed(feed) {
  const response = await fetch(feed.url, { cache: "no-store" });
  if (!response.ok) throw new Error(`${feed.name} returned HTTP ${response.status}`);

  const items = feed.parse(await response.text());
  const normalized = normalizeFeedItems(feed, items);
  if (normalized.length === 0) throw new Error(`${feed.name} returned no usable entries`);
  return normalized;
}

async function refreshDueFeeds(forceApply = false) {
  if (feedRefreshPromise) return feedRefreshPromise;

  feedRefreshPromise = refreshDueFeedsInternal(forceApply).finally(() => {
    feedRefreshPromise = null;
  });
  return feedRefreshPromise;
}

async function refreshDueFeedsInternal(forceApply) {
  const state = await chrome.storage.local.get([
    "settings",
    FEED_SNAPSHOTS_KEY,
    FEED_ATTEMPTS_KEY,
    FEED_SOURCES_STATUS_KEY,
  ]);
  if (state.settings?.protectionEnabled === false) return;

  const snapshots = state[FEED_SNAPSHOTS_KEY] || {};
  const attempts = state[FEED_ATTEMPTS_KEY] || {};
  const sourceStatus = state[FEED_SOURCES_STATUS_KEY] || {};
  const now = Date.now();
  const dueFeeds = FEEDS.filter((feed) => {
    const lastAttempt = attempts[feed.id];
    return !Number.isFinite(lastAttempt) || now - lastAttempt >= feed.intervalMs;
  });

  if (dueFeeds.length === 0 && !forceApply) return;

  // Record attempts before fetching. Failures retain their prior snapshot and
  // are retried at that source's next scheduled interval.
  for (const feed of dueFeeds) attempts[feed.id] = now;
  if (dueFeeds.length > 0) {
    await chrome.storage.local.set({ [FEED_ATTEMPTS_KEY]: attempts });
  }

  const results = await Promise.allSettled(dueFeeds.map(fetchFeed));
  results.forEach((result, index) => {
    const feed = dueFeeds[index];
    if (result.status === "fulfilled") {
      snapshots[feed.id] = result.value;
      sourceStatus[feed.id] = {
        name: feed.name,
        ok: true,
        count: result.value.length,
        lastAttempt: now,
        lastSuccess: now,
      };
    } else {
      console.error(`PhishShield: ${feed.name} refresh failed`, result.reason);
      sourceStatus[feed.id] = {
        ...sourceStatus[feed.id],
        name: feed.name,
        ok: false,
        error: String(result.reason),
        lastAttempt: now,
        retainedCount: snapshots[feed.id]?.length || 0,
      };
    }
  });

  // Persist each successful source independently before rebuilding the union.
  await chrome.storage.local.set({
    [FEED_SNAPSHOTS_KEY]: snapshots,
    [FEED_SOURCES_STATUS_KEY]: sourceStatus,
  });

  const rules = buildRules(snapshots);
  if (rules.length === 0) {
    console.error("PhishShield: no usable feed rules; keeping existing rules");
    await chrome.storage.local.set({
      feedStatus: { ok: false, sources: sourceStatus, count: 0 },
    });
    return;
  }

  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: rules,
    });

    const anySourceFailed = Object.values(sourceStatus).some((status) => status.ok === false);
    await chrome.storage.local.set({
      feedStatus: {
        ok: !anySourceFailed,
        updatedAt: now,
        count: rules.length,
        limitReached: rules.length === MAX_RULES,
        sources: sourceStatus,
      },
    });
  } catch (err) {
    console.error("PhishShield: could not update dynamic rules; keeping existing rules", err);
    await chrome.storage.local.set({ feedStatus: { ok: false, sources: sourceStatus } });
  }
}

async function clearFeedRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: existing.map((rule) => rule.id),
  });
}

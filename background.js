importScripts("blocking/feed.js");

const RULESET_ID = "ruleset_1";
const ALLOW_ALARM_PREFIX = "allow-expiry-";

// Apply the saved ON/OFF state and switch the toolbar icon to match.
const PROTECTION_ICONS = {
  on: {
    16: "icons/phishshield-on-16.png",
    32: "icons/phishshield-on-32.png",
  },
  off: {
    16: "icons/phishshield-off-16.png",
    32: "icons/phishshield-off-32.png",
  },
};

async function applyProtection(enabled) {
  try {
    await chrome.action.setIcon({
      path: enabled ? PROTECTION_ICONS.on : PROTECTION_ICONS.off,
    });

    // Clear the ON/OFF text badge.
    await chrome.action.setBadgeText({ text: "" });
    await chrome.declarativeNetRequest.updateEnabledRulesets(
      enabled
        ? { enableRulesetIds: [RULESET_ID] }
        : { disableRulesetIds: [RULESET_ID] },
    );

    if (enabled) await refreshDueFeeds(true);
    else await clearFeedRules();
  } catch (err) {
    console.error("PhishShield: could not apply protection state", err);
  }
}

// Read the saved setting and make Chrome match it
async function syncFromStorage() {
  const { settings } = await chrome.storage.local.get("settings");
  await applyProtection(settings?.protectionEnabled ?? true);
}

function isTemporaryAllowRule(rule) {
  return (
    rule?.priority === 10 &&
    rule.action?.type === "allow" &&
    rule.condition?.resourceTypes?.length === 1 &&
    rule.condition.resourceTypes[0] === "main_frame" &&
    typeof rule.condition.urlFilter === "string" &&
    /^\|\|[a-z0-9.-]+\^$/i.test(rule.condition.urlFilter)
  );
}

async function clearTemporaryAllows() {
  const [{ allowed: storedAllows }, sessionRules] = await Promise.all([
    chrome.storage.local.get("allowed"),
    chrome.declarativeNetRequest.getSessionRules(),
  ]);
  const allowed =
    storedAllows && typeof storedAllows === "object" && !Array.isArray(storedAllows)
      ? storedAllows
      : {};
  const storedIds = Object.keys(allowed);
  const managedRules = sessionRules.filter(
    (rule) => storedIds.includes(String(rule.id)) || isTemporaryAllowRule(rule),
  );

  if (managedRules.length > 0) {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: managedRules.map((rule) => rule.id),
    });
  }

  const alarmIds = new Set([
    ...storedIds,
    ...managedRules.map((rule) => String(rule.id)),
  ]);
  await Promise.all(
    [...alarmIds].map((id) => chrome.alarms.clear(`${ALLOW_ALARM_PREFIX}${id}`)),
  );
  await chrome.storage.local.set({ allowed: {} });
}

async function pruneExpiredAllows() {
  const { allowed: storedAllows = {} } = await chrome.storage.local.get("allowed");
  const allowed =
    storedAllows && typeof storedAllows === "object" && !Array.isArray(storedAllows)
      ? { ...storedAllows }
      : {};
  const sessionRules = await chrome.declarativeNetRequest.getSessionRules();
  const managedRules = sessionRules.filter(isTemporaryAllowRule);
  const rulesById = new Map(managedRules.map((rule) => [rule.id, rule]));
  const now = Date.now();
  const removeRuleIds = new Set();
  const clearAlarmIds = new Set();
  let storageChanged = false;

  for (const [id, record] of Object.entries(allowed)) {
    const ruleId = Number(id);
    const validRecord =
      Number.isSafeInteger(ruleId) &&
      ruleId > 0 &&
      record &&
      Number.isFinite(record.expiresAt);
    const ruleExists = validRecord && rulesById.has(ruleId);

    if (!ruleExists || record.expiresAt <= now) {
      if (ruleExists) removeRuleIds.add(ruleId);
      clearAlarmIds.add(id);
      delete allowed[id];
      storageChanged = true;
      continue;
    }

    // Recreate a missing alarm, or an alarm that fired slightly early. The
    // stored deadline remains fixed, so this never extends the allow window.
    const alarmName = `${ALLOW_ALARM_PREFIX}${id}`;
    const alarm = await chrome.alarms.get(alarmName);
    if (!alarm) {
      await chrome.alarms.create(alarmName, {
        delayInMinutes: Math.max(0.5, (record.expiresAt - now) / 60_000),
      });
    }
  }

  // Remove any orphaned allow rules left behind if storage or an alarm failed.
  for (const rule of managedRules) {
    if (!Object.hasOwn(allowed, String(rule.id))) {
      removeRuleIds.add(rule.id);
      clearAlarmIds.add(String(rule.id));
    }
  }

  if (removeRuleIds.size > 0) {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [...removeRuleIds],
    });
  }
  await Promise.all(
    [...clearAlarmIds].map((id) => chrome.alarms.clear(`${ALLOW_ALARM_PREFIX}${id}`)),
  );
  if (storageChanged) {
    await chrome.storage.local.set({ allowed });
  }
}

async function handleStartup() {
  try {
    await clearTemporaryAllows();
  } catch (err) {
    console.error("PhishShield: could not clear temporary site allows", err);
  }
  await syncFromStorage();
}

// First install or update: remove any stale temporary allows, set defaults, then sync.
chrome.runtime.onInstalled.addListener(async () => {
  try {
    await clearTemporaryAllows();
  } catch (err) {
    console.error("PhishShield: could not clear temporary site allows", err);
  }
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) {
    await chrome.storage.local.set({
      settings: { protectionEnabled: true },
      events: [],
    });
  }
  await syncFromStorage();
});

// Browser restart: clear temporary exceptions and re-apply the saved state.
chrome.runtime.onStartup.addListener(handleStartup);

// Popup toggled the setting: apply it immediately
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local" || !changes.settings) return;
  await applyProtection(changes.settings.newValue?.protectionEnabled ?? true);
});

async function ensureFeedAlarm() {
  const alarm = await chrome.alarms.get("refresh-feed");
  if (!alarm || alarm.periodInMinutes !== 5) {
    chrome.alarms.create("refresh-feed", { periodInMinutes: 5 });
  }
}
ensureFeedAlarm();

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (typeof alarm?.name !== "string") return;
  if (alarm.name.startsWith(ALLOW_ALARM_PREFIX)) {
    try {
      await pruneExpiredAllows();
    } catch (err) {
      console.error("PhishShield: could not expire temporary site allows", err);
    }
    return;
  }
  if (alarm.name !== "refresh-feed") return;

  try {
    await pruneExpiredAllows();
  } catch (err) {
    console.error("PhishShield: could not prune temporary site allows", err);
  }
  const { settings } = await chrome.storage.local.get("settings");
  if (settings?.protectionEnabled ?? true) await refreshDueFeeds();
});

importScripts("blocking/feed.js");

const RULESET_ID = "ruleset_1";

// Apply the saved ON/OFF state to Chrome and show it on the toolbar badge
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
    // await chrome.action.setBadgeBackgroundColor({
    //   color: enabled ? "#15803d" : "#b91c1c",
    // });

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

// First install or update: set defaults, then sync
chrome.runtime.onInstalled.addListener(async () => {
  const { settings } = await chrome.storage.local.get("settings");
  if (!settings) {
    await chrome.storage.local.set({
      settings: { protectionEnabled: true },
      events: [],
    });
  }
  await syncFromStorage();
});

// Browser restart: Chrome may reset rulesets, so re-apply the saved state
chrome.runtime.onStartup.addListener(syncFromStorage);

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
  if (alarm.name !== "refresh-feed") return;
  const { settings } = await chrome.storage.local.get("settings");
  if (settings?.protectionEnabled ?? true) await refreshDueFeeds();
});

async function init() {
  const [settings, history, historyCount] = await Promise.all([
    PhishStore.getSettings(),
    PhishStore.getHistory(),
    PhishStore.getEventCount(),
  ]);

  document.getElementById("status").textContent = settings.protectionEnabled
    ? "Protection: ON"
    : "Protection: OFF";

  // Data model for a future popup history UI. The current placeholder HTML
  // does not render this data.
  window.phishShieldPopupData = { history, historyCount };
}

window.phishShieldPopupReady = init().catch((err) => {
  console.error("PhishShield: could not load popup data", err);
});

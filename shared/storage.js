const PhishStore = {
  async getSettings() {
    const { settings } = await chrome.storage.local.get("settings");
    return settings || { protectionEnabled: true };
  },

  async setProtection(enabled) {
    const settings = await this.getSettings();
    await chrome.storage.local.set({
      settings: { ...settings, protectionEnabled: enabled },
    });
  },

  async getEvents() {
    const { events } = await chrome.storage.local.get("events");
    return Array.isArray(events) ? events : [];
  },

  async getHistory() {
    return this.getEvents();
  },

  async getEventCount() {
    const events = await this.getEvents();
    return events.length;
  },

  async addEvent(event) {
    // Accept the former string argument so callers using addEvent(domain)
    // continue to work while new records include URL and reason details.
    const details = typeof event === "string" ? { domain: event } : event;
    if (!details || typeof details.domain !== "string" || !details.domain.trim()) {
      return;
    }

    const events = await this.getEvents();
    const record = {
      domain: details.domain.trim(),
      timestamp: Date.now(),
    };
    if (typeof details.url === "string" && details.url) {
      record.url = details.url;
    }
    if (typeof details.reason === "string" && details.reason) {
      record.reason = details.reason.slice(0, 500);
    }

    events.unshift(record);
    await chrome.storage.local.set({ events: events.slice(0, 50) });
  },
};

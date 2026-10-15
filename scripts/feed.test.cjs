const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const feedScript = fs.readFileSync(path.join(__dirname, "../blocking/feed.js"), "utf8");

function createHarness() {
  let now = 1_800_000_000_000;
  const localData = { settings: { protectionEnabled: true } };
  let dynamicRules = [];
  const calls = [];
  const responses = new Map();

  class TestDate extends Date {
    static now() {
      return now;
    }
  }

  const context = vm.createContext({
    URL,
    URLSearchParams,
    Date: TestDate,
    console: { error() {} },
    fetch: async (url) => {
      calls.push(url);
      const response = responses.get(url);
      if (response instanceof Error) throw response;
      return {
        ok: true,
        status: 200,
        text: async () => response,
      };
    },
    chrome: {
      storage: {
        local: {
          async get(keys) {
            if (Array.isArray(keys)) {
              return Object.fromEntries(keys.map((key) => [key, localData[key]]));
            }
            return { [keys]: localData[keys] };
          },
          async set(values) {
            Object.assign(localData, values);
          },
        },
      },
      declarativeNetRequest: {
        async getDynamicRules() {
          return dynamicRules;
        },
        async updateDynamicRules({ removeRuleIds = [], addRules = [] }) {
          const removed = new Set(removeRuleIds);
          dynamicRules = dynamicRules.filter((rule) => !removed.has(rule.id));
          dynamicRules.push(...addRules);
        },
      },
    },
  });

  vm.runInContext(feedScript, context, { filename: "blocking/feed.js" });
  const feeds = vm.runInContext("FEEDS", context);

  return {
    context,
    feeds,
    calls,
    localData,
    responses,
    get dynamicRules() {
      return dynamicRules;
    },
    advance(milliseconds) {
      now += milliseconds;
    },
    refresh() {
      return vm.runInContext("refreshDueFeeds()", context);
    },
  };
}

function queryFor(rule) {
  return new URL(`chrome-extension://test${rule.action.redirect.extensionPath}`).searchParams;
}

test("feed rules pass the OpenPhish URL and source-specific reasons", async () => {
  const harness = createHarness();
  const [openPhish, certPolska] = harness.feeds;
  const flaggedUrl = "https://phish.example/login?campaign=one&next=%2Flogin";
  harness.responses.set(openPhish.url, `${flaggedUrl}\n`);
  harness.responses.set(certPolska.url, "warning.example\n");

  await harness.refresh();

  assert.equal(harness.dynamicRules.length, 2);
  const openRule = harness.dynamicRules.find((rule) => queryFor(rule).has("url"));
  const certRule = harness.dynamicRules.find((rule) => !queryFor(rule).has("url"));
  assert.ok(openRule);
  assert.ok(certRule);
  assert.equal(queryFor(openRule).get("url"), flaggedUrl);
  assert.equal(queryFor(openRule).get("site"), "phish.example");
  assert.match(queryFor(openRule).get("reason"), /OpenPhish/);
  assert.equal(openRule.condition.urlFilter, "||phish.example/login?campaign=one&next=%2Flogin|");
  assert.equal(queryFor(certRule).get("site"), "warning.example");
  assert.match(queryFor(certRule).get("reason"), /CERT Polska/);
  assert.equal(certRule.condition.urlFilter, "||warning.example^");
});

test("feeds refresh on independent intervals and retain good snapshots on failure", async () => {
  const harness = createHarness();
  const [openPhish, certPolska] = harness.feeds;
  harness.responses.set(openPhish.url, "https://phish.example/a?x=1\n");
  harness.responses.set(certPolska.url, "warning.example\n");

  await harness.refresh();
  assert.equal(harness.calls.length, 2);

  harness.advance(5 * 60 * 1000);
  await harness.refresh();
  assert.deepEqual(harness.calls, [openPhish.url, certPolska.url]);

  harness.advance(55 * 60 * 1000);
  harness.responses.set(certPolska.url, new Error("temporary outage"));
  await harness.refresh();
  assert.deepEqual(harness.calls, [openPhish.url, certPolska.url, certPolska.url]);
  assert.equal(harness.dynamicRules.length, 2);
  assert.equal(harness.localData.feedSnapshots.certPolska.length, 1);
  assert.equal(harness.localData.feedSourcesStatus.certPolska.ok, false);

  harness.advance(11 * 60 * 60 * 1000);
  harness.responses.set(openPhish.url, new Error("temporary outage"));
  harness.responses.set(certPolska.url, "new-warning.example\n");
  await harness.refresh();

  assert.equal(harness.localData.feedSnapshots.openphish.length, 1);
  assert.equal(harness.localData.feedSnapshots.certPolska[0].host, "new-warning.example");
  assert.equal(harness.dynamicRules.length, 2);
  assert.ok(harness.dynamicRules.some((rule) => queryFor(rule).get("url") === "https://phish.example/a?x=1"));
  assert.ok(harness.dynamicRules.some((rule) => queryFor(rule).get("site") === "new-warning.example"));
});

test("cached feed rules are restored when protection is enabled again", async () => {
  const harness = createHarness();
  const [openPhish, certPolska] = harness.feeds;
  harness.responses.set(openPhish.url, "https://phish.example/login\n");
  harness.responses.set(certPolska.url, "warning.example\n");
  await harness.refresh();

  await vm.runInContext("clearFeedRules()", harness.context);
  assert.equal(harness.dynamicRules.length, 0);

  await harness.refresh();
  assert.equal(harness.calls.length, 2);
  assert.equal(harness.dynamicRules.length, 0);

  await vm.runInContext("refreshDueFeeds(true)", harness.context);
  assert.equal(harness.calls.length, 2);
  assert.equal(harness.dynamicRules.length, 2);
});

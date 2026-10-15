/**
 * PhishShield – rules.json Validator
 * Usage: node scripts/validate-rules.js
 * Exits with code 1 and a clear message on any violation.
 * No external dependencies — runs with plain Node.js.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rulesPath = resolve(__dirname, "../rules.json");

const REQUIRED_REDIRECT = "/blocked/blocked.html";
const ALLOWED_TLDS = [".test", ".invalid"];

// ── helpers ────────────────────────────────────────────────────────────────

function fail(msg) {
  console.error(`\n  FAIL  ${msg}\n`);
  process.exit(1);
}

function domainFromFilter(urlFilter) {
  // Strip the leading "||" domain anchor and any trailing "^" or path chars
  return urlFilter.replace(/^\|\|/, "").split(/[\^/]/)[0].toLowerCase();
}

function hasAllowedTld(domain) {
  return ALLOWED_TLDS.some((tld) => domain.endsWith(tld));
}

// ── load file ──────────────────────────────────────────────────────────────

let raw;
try {
  raw = readFileSync(rulesPath, "utf8");
} catch (e) {
  fail(`Cannot read rules.json at ${rulesPath}: ${e.message}`);
}

let rules;
try {
  rules = JSON.parse(raw);
} catch (e) {
  fail(`rules.json is not valid JSON: ${e.message}`);
}

if (!Array.isArray(rules)) {
  fail("rules.json must be a JSON array at the top level.");
}

if (rules.length === 0) {
  fail("rules.json is an empty array — no rules defined.");
}

// ── per-rule validation ────────────────────────────────────────────────────

const seenIds = new Set();
const seenFilters = new Set();

rules.forEach((rule, index) => {
  const pos = `Rule at index ${index}`;

  // Required top-level fields
  for (const field of ["id", "priority", "action", "condition"]) {
    if (!(field in rule)) {
      fail(`${pos} is missing required field "${field}".`);
    }
  }

  // id must be a positive integer
  if (!Number.isInteger(rule.id) || rule.id < 1) {
    fail(`${pos} has an invalid id: ${JSON.stringify(rule.id)}. Must be a positive integer.`);
  }

  // id must be unique
  if (seenIds.has(rule.id)) {
    fail(`Duplicate rule id detected: ${rule.id}.`);
  }
  seenIds.add(rule.id);

  // action.type must be "redirect"
  if (!rule.action || rule.action.type !== "redirect") {
    fail(`Rule id=${rule.id}: action.type must be "redirect", got ${JSON.stringify(rule.action?.type)}.`);
  }

  // condition must exist and have urlFilter
  if (!rule.condition || typeof rule.condition.urlFilter !== "string") {
    fail(`Rule id=${rule.id}: condition.urlFilter must be a string.`);
  }

  const filter = rule.condition.urlFilter;
  const domain = domainFromFilter(filter);

  // The warning page receives the matching domain and its demo explanation.
  const extensionPath = rule.action?.redirect?.extensionPath;
  let redirectUrl;
  try {
    redirectUrl = new URL(`chrome-extension://phishshield${extensionPath}`);
  } catch {
    fail(
      `Rule id=${rule.id}: redirect.extensionPath is not a valid extension path: ${JSON.stringify(extensionPath)}.`
    );
  }
  if (redirectUrl.pathname !== REQUIRED_REDIRECT) {
    fail(
      `Rule id=${rule.id}: redirect.extensionPath must target "${REQUIRED_REDIRECT}", got ${JSON.stringify(extensionPath)}.`
    );
  }
  if (redirectUrl.searchParams.get("site") !== domain) {
    fail(
      `Rule id=${rule.id}: redirect must pass site=${domain}, got ${JSON.stringify(redirectUrl.searchParams.get("site"))}.`
    );
  }
  if (!redirectUrl.searchParams.get("reason")?.trim()) {
    fail(`Rule id=${rule.id}: redirect must pass a non-empty reason parameter.`);
  }

  // urlFilter must be unique
  if (seenFilters.has(filter)) {
    fail(`Duplicate urlFilter detected: "${filter}".`);
  }
  seenFilters.add(filter);

  // resourceTypes must be exactly ["main_frame"]
  const rt = rule.condition.resourceTypes;
  if (
    !Array.isArray(rt) ||
    rt.length !== 1 ||
    rt[0] !== "main_frame"
  ) {
    fail(
      `Rule id=${rule.id}: condition.resourceTypes must be exactly ["main_frame"], got ${JSON.stringify(rt)}.`
    );
  }

  // domain must be under .test or .invalid
  if (!hasAllowedTld(domain)) {
    fail(
      `Rule id=${rule.id}: domain "${domain}" does not end with .test or .invalid. Only reserved TLDs are permitted.`
    );
  }
});

// ── summary ────────────────────────────────────────────────────────────────

console.log(`\n  PASS  rules.json is valid. ${rules.length} rule(s) checked — all good.\n`);

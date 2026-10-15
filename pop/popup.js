const form = document.querySelector("#scan-form");
const input = document.querySelector("#url-input");
const result = document.querySelector("#result");

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const enteredValue = input.value.trim();

  try {
    const url = new URL(
      enteredValue.includes("://") ? enteredValue : `https://${enteredValue}`
    );

    const warnings = [];
    const hostname = url.hostname.toLowerCase();

    if (url.protocol !== "https:") {
      warnings.push("The link does not use HTTPS.");
    }

    if (hostname.includes("xn--")) {
      warnings.push("The address contains an encoded hostname.");
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      warnings.push("The address uses a numeric IP instead of a domain name.");
    }

    if (hostname.split(".").length > 4) {
      warnings.push("The address has an unusually long chain of subdomains.");
    }

    if (/(login|verify|account|password|secure|update)/i.test(url.href)) {
      warnings.push("The address contains words often used in misleading links.");
    }

    result.className = "result";

    if (warnings.length > 0) {
      result.classList.add("warning");
      result.textContent = `Use caution:\n• ${warnings.join("\n• ")}`;
    } else {
      result.classList.add("safe");
      result.textContent =
        "No obvious warning signs were found. This does not guarantee the link is safe.";
    }
  } catch {
    result.className = "result warning";
    result.textContent = "That does not look like a valid website address. Check it and try again.";
  }
});
const net = require("node:net");

const SUSPICIOUS_EXTENSIONS = new Set(["apk", "bat", "cmd", "exe", "hta", "js", "msi", "scr", "vbs"]);
const TLD_POPULARITY = new Set(["com", "org", "net", "edu", "gov", "in", "co", "io", "ai"]);
const BRAND_TERMS = ["bank", "paypal", "pay", "crypto", "wallet"];

function extractUrlFeatures(inputUrl, report = {}) {
  const normalizedUrl = normalizeUrl(inputUrl);
  let parsed;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return {};
  }
  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".").filter(Boolean);
  const tld = labels.at(-1) || "";
  const domain = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  const path = parsed.pathname || "";
  const query = parsed.search || "";
  const urlText = normalizedUrl.toLowerCase();
  const letters = countMatches(normalizedUrl, /[a-z]/gi);
  const digits = countMatches(normalizedUrl, /\d/g);
  const special = countMatches(normalizedUrl, /[^a-z0-9]/gi);
  const obfuscated = countMatches(normalizedUrl, /%[0-9a-f]{2}/gi);
  const tokens = normalizedUrl.split(/[^a-z0-9]+/i).filter(Boolean);
  const ext = path.split(".").pop()?.toLowerCase() || "";

  return {
    url_length: normalizedUrl.length,
    URLLength: normalizedUrl.length,
    has_ip_address: net.isIP(host) ? 1 : 0,
    IsDomainIP: net.isIP(host) ? 1 : 0,
    dot_count: countMatches(host, /\./g),
    https_flag: parsed.protocol === "https:" ? 1 : 0,
    IsHTTPS: parsed.protocol === "https:" ? 1 : 0,
    url_entropy: entropy(normalizedUrl),
    token_count: tokens.length,
    subdomain_count: Math.max(0, labels.length - 2),
    NoOfSubDomain: Math.max(0, labels.length - 2),
    query_param_count: [...parsed.searchParams.keys()].length,
    tld_length: tld.length,
    TLDLength: tld.length,
    path_length: path.length,
    has_hyphen_in_domain: domain.includes("-") ? 1 : 0,
    number_of_digits: digits,
    NoOfDegitsInURL: digits,
    domain_name_length: domain.length,
    DomainLength: host.length,
    percentage_numeric_chars: normalizedUrl.length ? digits / normalizedUrl.length : 0,
    DegitRatioInURL: normalizedUrl.length ? digits / normalizedUrl.length : 0,
    NoOfLettersInURL: letters,
    LetterRatioInURL: normalizedUrl.length ? letters / normalizedUrl.length : 0,
    NoOfOtherSpecialCharsInURL: special,
    SpacialCharRatioInURL: normalizedUrl.length ? special / normalizedUrl.length : 0,
    tld_popularity: TLD_POPULARITY.has(tld) ? 1 : 0,
    suspicious_file_extension: SUSPICIOUS_EXTENSIONS.has(ext) ? 1 : 0,
    HasObfuscation: obfuscated > 0 ? 1 : 0,
    NoOfObfuscatedChar: obfuscated,
    ObfuscationRatio: normalizedUrl.length ? obfuscated / normalizedUrl.length : 0,
    NoOfEqualsInURL: countMatches(query, /=/g),
    NoOfQMarkInURL: countMatches(query, /\?/g) + (query ? 1 : 0),
    NoOfAmpersandInURL: countMatches(query, /&/g),
    NoOfURLRedirect: report.finalUrl && safeHost(report.finalUrl) !== host ? 1 : 0,
    NoOfSelfRedirect: report.finalUrl && safeHost(report.finalUrl) === host && report.finalUrl !== normalizedUrl ? 1 : 0,
    NoOfPopup: report.pageSignals?.popupCalls || 0,
    NoOfiFrame: report.pageSignals?.iframes || 0,
    HasExternalFormSubmit: report.pageSignals?.externalFormActions ? 1 : 0,
    HasHiddenFields: report.pageSignals?.hiddenInputs ? 1 : 0,
    HasPasswordField: report.pageSignals?.passwordInputs ? 1 : 0,
    Bank: urlText.includes("bank") ? 1 : 0,
    Pay: urlText.includes("pay") || urlText.includes("paypal") ? 1 : 0,
    Crypto: BRAND_TERMS.some((term) => urlText.includes(term) && ["crypto", "wallet"].includes(term)) ? 1 : 0
  };
}

function bucketFeature(name, rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "") return "missing";
  const value = Number(rawValue);
  if (!Number.isFinite(value)) return String(rawValue).toLowerCase();

  if (/flag|has_|ishttps|isdomainip|has[A-Z]|bank|pay|crypto|popularity/i.test(name)) {
    return value > 0 ? "1" : "0";
  }
  if (/ratio|percentage|entropy|prob|rate|index|score/i.test(name)) {
    if (value <= 0) return "0";
    if (value <= 0.05) return "0.01-0.05";
    if (value <= 0.15) return "0.06-0.15";
    if (value <= 0.35) return "0.16-0.35";
    if (value <= 0.65) return "0.36-0.65";
    return "0.66+";
  }
  if (/length|letters|degits|digits|char|line/i.test(name)) {
    if (value <= 0) return "0";
    if (value <= 20) return "1-20";
    if (value <= 50) return "21-50";
    if (value <= 80) return "51-80";
    if (value <= 120) return "81-120";
    return "121+";
  }
  if (value <= 0) return "0";
  if (value === 1) return "1";
  if (value <= 3) return "2-3";
  if (value <= 7) return "4-7";
  return "8+";
}

function normalizeUrl(input) {
  const value = String(input || "").trim();
  if (!value) return "";
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
}

function normalizeUrlForMatch(input) {
  try {
    const parsed = new URL(normalizeUrl(input));
    parsed.hostname = parsed.hostname.toLowerCase();
    if ((parsed.protocol === "https:" && parsed.port === "443") || (parsed.protocol === "http:" && parsed.port === "80")) {
      parsed.port = "";
    }
    parsed.hash = "";
    const text = parsed.toString();
    return text.endsWith("/") && parsed.pathname === "/" && !parsed.search ? text.slice(0, -1) : text;
  } catch {
    return String(input || "").trim().toLowerCase();
  }
}

function entropy(value) {
  const text = String(value || "");
  if (!text) return 0;
  const counts = [...text].reduce((map, char) => map.set(char, (map.get(char) || 0) + 1), new Map());
  return [...counts.values()].reduce((sum, count) => {
    const p = count / text.length;
    return sum - p * Math.log2(p);
  }, 0);
}

function safeHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function countMatches(text, pattern) {
  return (String(text || "").match(pattern) || []).length;
}

module.exports = {
  bucketFeature,
  extractUrlFeatures,
  normalizeUrlForMatch
};

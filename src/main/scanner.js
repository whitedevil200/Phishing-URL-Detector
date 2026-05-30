const dns = require("node:dns").promises;
const fs = require("node:fs");
const https = require("node:https");
const net = require("node:net");
const path = require("node:path");
const tls = require("node:tls");
const { evaluateLocalIntelligence } = require("./local-intelligence");
const PHISHING_FEATURE_PROFILE = require("../data/phishing-feature-profile.json");

const SUSPICIOUS_KEYWORDS = [
  "account",
  "alert",
  "auth",
  "bank",
  "billing",
  "confirm",
  "free",
  "gift",
  "invoice",
  "limited",
  "login",
  "password",
  "pay",
  "secure",
  "signin",
  "support",
  "suspend",
  "update",
  "verify",
  "wallet"
];

const SUSPICIOUS_TLDS = new Set([
  "biz",
  "cam",
  "click",
  "club",
  "download",
  "gq",
  "icu",
  "info",
  "loan",
  "mom",
  "monster",
  "mov",
  "party",
  "pw",
  "rest",
  "review",
  "ru",
  "support",
  "tk",
  "top",
  "work",
  "xyz",
  "zip"
]);

const SHORTENERS = new Set([
  "bit.ly",
  "buff.ly",
  "cutt.ly",
  "goo.gl",
  "is.gd",
  "lnkd.in",
  "ow.ly",
  "rebrand.ly",
  "s.id",
  "shorturl.at",
  "t.co",
  "tiny.cc",
  "tinyurl.com"
]);

const BRANDS = ["amazon", "apple", "binance", "facebook", "google", "instagram", "microsoft", "netflix", "paypal", "whatsapp", "yahoo"];

function normalizeUrl(input) {
  const value = String(input || "").trim();
  if (!value) return "";
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
}

async function scanUrl(inputUrl, options = {}) {
  const started = new Date().toISOString();
  const normalizedUrl = normalizeUrl(inputUrl);
  const report = {
    inputUrl,
    normalizedUrl,
    scannedAt: started,
    verdict: "Unknown",
    riskScore: 0,
    summary: "Scan started.",
    finalUrl: null,
    domain: null,
    ipAddresses: [],
    tls: {},
    http: {},
    whois: {},
    pageSignals: {},
    datasetProfile: {},
    localIntelligence: {},
    performance: {},
    findings: [],
    errors: []
  };

  let parsed;
  try {
    parsed = new URL(normalizedUrl);
    report.domain = parsed.hostname.toLowerCase();
  } catch {
    addFinding(report, "High", "Invalid URL", "The value could not be parsed as a normal URL.", 35);
    finalize(report);
    return report;
  }

  analyzeStructure(report, parsed);
  if (options.network !== false) {
    await resolveDns(report);
    await inspectTls(report);
    if (options.fetchSite !== false) {
      await inspectWebsite(report, normalizedUrl, options.timeoutMs || 9000);
    }
    await lookupWhois(report, options.timeoutMs || 9000);
  }
  const inferenceStarted = performance.now();
  const localResult = evaluateLocalIntelligence(report, parsed);
  report.localIntelligence = localResult.localIntelligence;
  report.performance.inferenceMs = Number((performance.now() - inferenceStarted).toFixed(2));
  for (const finding of localResult.findings) {
    addFinding(report, finding.severity, finding.title, finding.detail, finding.points);
  }
  report.datasetProfile = {
    source: report.localIntelligence.matchedDataset,
    totalRows: report.localIntelligence.counts?.activeDomains || 0,
    matchedFeatures: report.localIntelligence.matchedFeatures || [],
    averageRiskLift: report.localIntelligence.matchedFeatures?.length
      ? Number((report.localIntelligence.matchedFeatures.reduce((sum, item) => sum + (item.lift || 0), 0) / report.localIntelligence.matchedFeatures.length).toFixed(2))
      : 0
  };
  finalize(report);
  return report;
}

function addFinding(report, severity, title, detail, points) {
  report.findings.push({ severity, title, detail, points });
}

function analyzeStructure(report, parsed) {
  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".");
  const pathQuery = `${parsed.pathname || ""}${parsed.search || ""}`.toLowerCase();
  const urlText = `${host} ${pathQuery}`;

  if (parsed.protocol !== "https:") {
    addFinding(report, "High", "No HTTPS", "The URL does not use HTTPS.", 25);
  }
  if (report.normalizedUrl.length > 120) {
    addFinding(report, "Medium", "Very long URL", "Long URLs can hide the real destination.", 12);
  }
  if (report.normalizedUrl.includes("@")) {
    addFinding(report, "High", "Userinfo trick", "The URL contains '@', which can hide the true host.", 30);
  }
  if (labels.length >= 5) {
    addFinding(report, "Medium", "Many subdomains", "The host has many labels, often used for imitation.", 12);
  }
  if (net.isIP(host)) {
    addFinding(report, "High", "IP address host", "Legitimate sign-in flows rarely use a raw IP address.", 25);
  }
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    addFinding(report, "Medium", "Punycode domain", "Punycode can be used in homograph attacks.", 18);
  }
  if (/[^a-z0-9.-]/.test(host)) {
    addFinding(report, "Medium", "Unusual host characters", "The host contains characters outside conservative ASCII.", 14);
  }

  const tld = labels.at(-1) || "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    addFinding(report, "Low", "Risky top-level domain", `.${tld} is frequently abused in phishing campaigns.`, 7);
  }
  const registrable = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  if (SHORTENERS.has(registrable)) {
    addFinding(report, "Medium", "URL shortener", "Shortened links hide the final destination until opened.", 16);
  }
  if ((host.match(/-/g) || []).length >= 3) {
    addFinding(report, "Low", "Many hyphens", "Brand impersonation domains often include many hyphens.", 6);
  }
  if ((host.match(/\d/g) || []).length >= 5) {
    addFinding(report, "Low", "Many digits", "The host contains many digits, uncommon for major brands.", 6);
  }

  const keywords = SUSPICIOUS_KEYWORDS.filter((word) => urlText.includes(word));
  if (keywords.length >= 2) {
    addFinding(report, "Medium", "Credential-themed wording", `Found phishing-themed words: ${keywords.slice(0, 8).join(", ")}.`, Math.min(20, 6 + keywords.length * 3));
  }

  for (const brand of BRANDS) {
    if (host.includes(brand) && host !== `${brand}.com` && !host.endsWith(`.${brand}.com`)) {
      addFinding(report, "High", "Possible brand impersonation", `The host contains '${brand}' but is not the common primary domain.`, 22);
      break;
    }
  }

  if (entropy(host.replace(/\./g, "")) > 3.7 && host.length > 18) {
    addFinding(report, "Low", "High entropy domain", "The domain looks randomly generated.", 8);
  }
  if ((report.normalizedUrl.match(/%[0-9a-f]{2}/gi) || []).length >= 4) {
    addFinding(report, "Medium", "Heavy URL encoding", "Encoded characters can hide the readable destination.", 12);
  }
}

async function resolveDns(report) {
  if (!report.domain) return;
  try {
    const results = await dns.lookup(report.domain, { all: true });
    report.ipAddresses = [...new Set(results.map((item) => item.address))].sort();
    const special = report.ipAddresses.filter(isPrivateOrReservedIp);
    if (special.length) {
      addFinding(report, "High", "Private or reserved IP", `Resolved to ${special.join(", ")}.`, 25);
    }
  } catch (error) {
    report.errors.push(`DNS lookup failed: ${error.message}`);
    addFinding(report, "Medium", "DNS lookup failed", "The host did not resolve during the scan.", 14);
  }
}

async function inspectTls(report) {
  if (!report.domain) return;
  await new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: report.domain,
        port: 443,
        servername: report.domain,
        timeout: 8000,
        rejectUnauthorized: true
      },
      () => {
        const cert = socket.getPeerCertificate();
        report.tls = {
          valid: socket.authorized,
          issuer: cert.issuer || {},
          subject: cert.subject || {},
          validFrom: cert.valid_from || null,
          validTo: cert.valid_to || null,
          protocol: socket.getProtocol()
        };
        if (cert.valid_to) {
          const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
          report.tls.daysLeft = daysLeft;
          if (daysLeft < 7) {
            addFinding(report, "Medium", "TLS certificate expiring soon", `Certificate expires in ${daysLeft} days.`, 10);
          }
        }
        socket.end();
        resolve();
      }
    );
    socket.on("timeout", () => socket.destroy(new Error("TLS connection timed out")));
    socket.on("error", (error) => {
      report.tls = { valid: false, error: error.message };
      addFinding(report, "High", "TLS problem", `Certificate or TLS connection failed: ${error.message}`, 22);
      resolve();
    });
  });
}

async function inspectWebsite(report, url, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const started = performance.now();
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": "PhishingURLDetector/2.0 (+local-security-check)",
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });
    const finalUrl = response.url;
    const contentType = response.headers.get("content-type") || "";
    const headerMap = {};
    for (const key of ["content-security-policy", "location", "server", "strict-transport-security", "x-content-type-options", "x-frame-options"]) {
      const value = response.headers.get(key);
      if (value) headerMap[key] = value;
    }
    report.finalUrl = finalUrl;
    report.http = {
      status: response.status,
      ok: response.ok,
      contentType,
      elapsedSeconds: Number(((performance.now() - started) / 1000).toFixed(2)),
      headers: headerMap
    };
    analyzeHttp(report, url, finalUrl, contentType, response.headers);
    const body = await readLimited(response, 600_000);
    if (contentType.includes("text/html") || body.trimStart().startsWith("<!")) {
      analyzeHtml(report, body, new URL(finalUrl).hostname.toLowerCase());
    }
  } catch (error) {
    report.http = { error: error.name === "AbortError" ? "Website fetch timed out" : error.message };
    report.errors.push(`Website fetch failed: ${report.http.error}`);
    addFinding(report, "Low", "Website scan incomplete", "The site could not be fetched for page-level checks.", 5);
  } finally {
    clearTimeout(timeout);
  }
}

async function readLimited(response, limit) {
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (total < limit) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  return Buffer.concat(chunks, Math.min(total, limit)).toString("utf8");
}

function analyzeHttp(report, originalUrl, finalUrl, contentType, headers) {
  const originalHost = new URL(originalUrl).hostname;
  const finalHost = new URL(finalUrl).hostname;
  if (originalHost !== finalHost) {
    addFinding(report, "Medium", "Redirected to another host", `${originalHost} redirected to ${finalHost}.`, 14);
  }
  if (!contentType.toLowerCase().includes("text/html")) {
    addFinding(report, "Low", "Unexpected content type", `Content-Type is ${contentType || "unknown"}.`, 4);
  }
  if (!headers.get("strict-transport-security")) {
    addFinding(report, "Low", "Missing HSTS", "The server did not advertise HTTP Strict Transport Security.", 4);
  }
  if (!headers.get("content-security-policy")) {
    addFinding(report, "Low", "Missing CSP", "No Content-Security-Policy header was found.", 3);
  }
}

function analyzeHtml(report, html, host) {
  const forms = countMatches(html, /<form\b/gi);
  const passwordInputs = countMatches(html, /<input\b[^>]*type=["']?password/gi);
  const hiddenInputs = countMatches(html, /<input\b[^>]*type=["']?hidden/gi);
  const iframes = countMatches(html, /<iframe\b/gi);
  const mailLinks = countMatches(html, /mailto:/gi);
  const popupCalls = countMatches(html, /window\.open\s*\(/gi);
  const rightClickBlocks = countMatches(html, /oncontextmenu\s*=|event\.button\s*==\s*2|contextmenu/gi);
  const links = [...html.matchAll(/<a\b[^>]*href=["']([^"']+)["']/gi)].map((match) => match[1]);
  const scripts = [...html.matchAll(/<script\b[^>]*src=["']([^"']+)["']/gi)].map((match) => match[1]);
  const formActions = [...html.matchAll(/<form\b[^>]*action=["']([^"']*)["']/gi)].map((match) => match[1]);
  const title = (html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || "").trim().slice(0, 160);
  const externalLinks = links.filter((href) => isExternalUrl(href, host)).length;
  const externalScripts = scripts.filter((src) => isExternalUrl(src, host)).length;
  const externalFormActions = formActions.filter((action) => action && isExternalUrl(action, host)).length;
  const emptyFormActions = formActions.filter((action) => !action || action === "about:blank").length;
  const externalRatio = links.length ? externalLinks / links.length : 0;
  report.pageSignals = {
    title,
    forms,
    passwordInputs,
    hiddenInputs,
    iframes,
    mailLinks,
    popupCalls,
    rightClickBlocks,
    links: links.length,
    externalLinks,
    externalLinkRatio: Number(externalRatio.toFixed(2)),
    externalScripts,
    formActions: formActions.length,
    externalFormActions,
    emptyFormActions,
    downloadedBytes: Buffer.byteLength(html)
  };
  if (passwordInputs) addFinding(report, "High", "Password form detected", "The page asks for a password or credential input.", 22);
  if (forms >= 2 && hiddenInputs >= 5) addFinding(report, "Medium", "Complex form collection", "Multiple forms and hidden inputs can indicate credential capture.", 12);
  if (externalFormActions) addFinding(report, "High", "External form submission", "One or more forms submit data to another host.", 18);
  if (emptyFormActions && passwordInputs) addFinding(report, "Medium", "Blank credential form target", "A password form has no clear submission endpoint.", 10);
  if (mailLinks) addFinding(report, "Low", "Email collection link", "The page contains mailto links that are common in support-themed lure pages.", 4);
  if (popupCalls) addFinding(report, "Low", "Popup behavior", "The page attempts to open new windows with script.", 5);
  if (rightClickBlocks) addFinding(report, "Low", "Right-click blocking", "The page includes script associated with disabling context menus.", 5);
  if (iframes) addFinding(report, "Low", "Iframe usage", "The page includes iframe content, which can conceal third-party flows.", 5);
  if (links.length >= 10 && externalRatio > 0.7) addFinding(report, "Medium", "Mostly external links", "Most page links point away from the scanned host.", 10);
  if (externalScripts >= 8) addFinding(report, "Low", "Many external scripts", "The page loads many scripts from other hosts.", 6);
}

async function lookupWhois(report, timeoutMs) {
  if (!report.domain) return;
  if (net.isIP(report.domain)) {
    try {
      report.whois = await lookupIpWhois(report.domain, timeoutMs);
      return;
    } catch (error) {
      report.whois = { available: false, error: error.message, ipv4: report.domain.includes(".") ? [report.domain] : [], ipv6: report.domain.includes(":") ? [report.domain] : [] };
      report.errors.push(`IP WHOIS lookup failed: ${error.message}`);
      addFinding(report, "Low", "IP WHOIS unavailable", "IP registration information could not be collected.", 4);
      return;
    }
  }
  let lastError = null;
  const candidates = domainCandidates(report.domain);
  for (let index = 0; index < candidates.length; index += 1) {
    const domain = candidates[index];
    try {
      const result = await withTimeout(lookupWhoisDomain(domain, timeoutMs), timeoutMs + 1000, `WHOIS lookup timed out for ${domain}`);
      if (result.registered === false && index < candidates.length - 1) {
        continue;
      }
      report.whois = addResolvedIpGroups(result, report.ipAddresses);
      const domainAgeDays = report.whois.domainAgeDays;
      if (domainAgeDays !== null && domainAgeDays !== undefined && domainAgeDays < 30) {
        addFinding(report, "High", "Very new domain", `WHOIS suggests the domain is ${domainAgeDays} days old.`, 24);
      } else if (domainAgeDays !== null && domainAgeDays !== undefined && domainAgeDays < 180) {
        addFinding(report, "Medium", "Recently registered domain", `WHOIS suggests the domain is ${domainAgeDays} days old.`, 13);
      }
      return;
    } catch (error) {
      lastError = error;
    }
  }

  report.whois = addResolvedIpGroups({ available: false, error: lastError?.message || "WHOIS lookup failed" }, report.ipAddresses);
  report.errors.push(`WHOIS lookup failed: ${report.whois.error}`);
  addFinding(report, "Low", "WHOIS unavailable", "WHOIS information could not be collected.", 4);
}

async function lookupWhoisDomain(domain, timeoutMs) {
  const rawParts = [];
  const parseParts = [];
  let server = "whois.iana.org";
  let rdap = null;
  const whoisTimeoutMs = Math.min(timeoutMs, 4500);
  const rdapTimeoutMs = Math.min(timeoutMs, 5000);

  try {
    const iana = await queryWhois("whois.iana.org", domain, whoisTimeoutMs);
    rawParts.push(iana);
    server = firstMatch(iana, /^\s*whois:\s*(\S+)/im) || firstMatch(iana, /^\s*refer:\s*(\S+)/im) || server;
    if (server !== "whois.iana.org") {
      const registryRaw = await queryWhois(server, domain, whoisTimeoutMs);
      rawParts.push(registryRaw);
      parseParts.push(registryRaw);
      const registrarWhois = firstField(registryRaw, ["Registrar WHOIS Server", "Whois Server"]);
      if (registrarWhois && registrarWhois !== server && !isNoMatch(registryRaw)) {
        try {
          const registrarRaw = await queryWhois(registrarWhois, domain, whoisTimeoutMs);
          rawParts.push(registrarRaw);
          parseParts.push(registrarRaw);
          server = registrarWhois;
        } catch {
          // Registry WHOIS data is still usable.
        }
      }
    } else {
      parseParts.push(iana);
    }
  } catch (error) {
    rawParts.push(`WHOIS error: ${error.message}`);
  }

  try {
    rdap = await lookupRdap(domain, rdapTimeoutMs);
  } catch {
    rdap = null;
  }

  const raw = rawParts.filter(Boolean).join("\n\n");
  const parseRaw = parseParts.filter(Boolean).join("\n\n");
  const registered = rdap?.errorCode === 404 ? false : !isNoMatch(parseRaw || raw);
  const parsed = registered ? parseWhoisRaw(parseRaw || raw) : { nameservers: [], status: [] };
  const rdapParsed = rdap ? parseRdap(rdap) : {};
  const created = registered ? parsed.created || rdapParsed.created || "Not provided" : "Not registered";
  const updated = registered ? parsed.updated || rdapParsed.updated || "Not provided" : "Not registered";
  const expires = registered ? parsed.expires || rdapParsed.expires || "Not provided" : "Not registered";
  const parsedCreated = created && created !== "Not provided" ? parseLooseDate(created) : null;
  const domainAgeDays = parsedCreated ? Math.floor((Date.now() - parsedCreated.getTime()) / 86_400_000) : null;

  return {
    available: true,
    registered,
    domain,
    source: rdap ? "WHOIS + RDAP" : "WHOIS",
    server,
    domainName: parsed.domainName || rdapParsed.domainName || domain,
    registryDomainId: parsed.registryDomainId || rdapParsed.registryDomainId || "Not provided",
    registrarWhoisServer: parsed.registrarWhoisServer || server || "Not provided",
    registrar: parsed.registrar || rdapParsed.registrar || "Not provided",
    registrarIanaId: parsed.registrarIanaId || rdapParsed.registrarIanaId || "Not provided",
    created,
    updated,
    expires,
    domainAgeDays,
    registrantOrganization: parsed.registrantOrganization || rdapParsed.registrantOrganization || "Not provided",
    registrantStateProvince: parsed.registrantStateProvince || rdapParsed.registrantStateProvince || "Not provided",
    registrantCountry: parsed.registrantCountry || rdapParsed.registrantCountry || "Not provided",
    registrantEmail: parsed.registrantEmail || "Not provided",
    adminEmail: parsed.adminEmail || "Not provided",
    techEmail: parsed.techEmail || "Not provided",
    billingEmail: parsed.billingEmail || "Not provided",
    registrarAbuseContactEmail: parsed.registrarAbuseContactEmail || rdapParsed.registrarAbuseContactEmail || "Not provided",
    registrarAbuseContactPhone: parsed.registrarAbuseContactPhone || rdapParsed.registrarAbuseContactPhone || "Not provided",
    dnsSec: parsed.dnsSec || rdapParsed.dnsSec || "Not provided",
    nameservers: uniqueCaseInsensitive([...(parsed.nameservers || []), ...(rdapParsed.nameservers || [])]).slice(0, 10),
    status: uniqueCaseInsensitive([...(parsed.status || []), ...(rdapParsed.status || [])]).slice(0, 10),
    rawExcerpt: raw.slice(0, 2500),
    rdapExcerpt: rdap ? JSON.stringify(rdap).slice(0, 2500) : ""
  };
}

async function lookupIpWhois(ip, timeoutMs) {
  const rdap = await lookupRdapIp(ip, Math.min(timeoutMs, 5000));
  const events = Array.isArray(rdap?.events) ? rdap.events : [];
  const getEvent = (...actions) => events.find((event) => actions.includes(String(event.eventAction || "").toLowerCase()))?.eventDate;
  const networkEntity = (rdap?.entities || []).find((entity) => (entity.roles || []).includes("registrant")) || rdap?.entities?.[0];
  const ipv4 = ip.includes(".") ? [ip] : [];
  const ipv6 = ip.includes(":") ? [ip] : [];
  return {
    available: true,
    registered: true,
    domain: ip,
    source: "IP RDAP",
    server: "rdap.org",
    registrar: rdap?.name || entityDisplayName(networkEntity) || "Not provided",
    created: getEvent("registration", "created") || "Not provided",
    updated: getEvent("last changed", "last update of rdap database", "last update") || "Not provided",
    expires: "Not provided",
    domainAgeDays: null,
    nameservers: [],
    status: Array.isArray(rdap?.status) ? rdap.status : [],
    ipv4,
    ipv6,
    ipNetwork: {
      handle: rdap?.handle || "Not provided",
      name: rdap?.name || "Not provided",
      type: rdap?.type || "Not provided",
      country: rdap?.country || "Not provided",
      startAddress: rdap?.startAddress || ip,
      endAddress: rdap?.endAddress || ip
    },
    rawExcerpt: "",
    rdapExcerpt: JSON.stringify(rdap).slice(0, 2500)
  };
}

function queryWhois(server, query, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(43, server);
    let response = "";
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error(`WHOIS timeout from ${server}`));
    }, timeoutMs);
    socket.on("connect", () => socket.write(`${query}\r\n`));
    socket.on("data", (chunk) => {
      response += chunk.toString("utf8");
      if (response.length > 90_000) socket.end();
    });
    socket.on("end", () => {
      clearTimeout(timeout);
      resolve(response);
    });
    socket.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function withTimeout(promise, ms, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

async function lookupRdap(domain, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { accept: "application/rdap+json, application/json" }
    });
    const text = await response.text();
    let data = {};
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
    if (!response.ok && response.status !== 404) {
      throw new Error(`RDAP returned HTTP ${response.status}`);
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function lookupRdapIp(ip, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      signal: controller.signal,
      headers: { accept: "application/rdap+json, application/json" }
    });
    const text = await response.text();
    let data = {};
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
    if (!response.ok) {
      throw new Error(`IP RDAP returned HTTP ${response.status}`);
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function applyPhishingDatabaseProfile(report, parsed) {
  const matched = inferDatasetFeatureMatches(report, parsed)
    .map((feature) => {
      const profile = PHISHING_FEATURE_PROFILE.features?.[feature];
      return profile
        ? {
            feature,
            phishingRateWhenRisky: profile.phishingRateWhenRisky,
            lift: profile.lift,
            support: profile.support,
            pointWeight: profile.pointWeight
          }
        : null;
    })
    .filter(Boolean);
  const totalWeight = matched.reduce((sum, item) => sum + item.pointWeight, 0);
  const phishingLift = matched.length ? matched.reduce((sum, item) => sum + item.lift, 0) / matched.length : 0;
  report.datasetProfile = {
    source: PHISHING_FEATURE_PROFILE.source,
    totalRows: PHISHING_FEATURE_PROFILE.totalRows,
    phishingRows: PHISHING_FEATURE_PROFILE.phishingRows,
    legitimateRows: PHISHING_FEATURE_PROFILE.legitimateRows,
    baselinePhishingRate: PHISHING_FEATURE_PROFILE.baselinePhishingRate,
    matchedFeatures: matched,
    averageRiskLift: Number(phishingLift.toFixed(2))
  };
  const meaningful = matched.filter((item) => item.pointWeight >= 0.5);
  if (meaningful.length >= 2) {
    const points = Math.min(18, Math.max(4, Math.round(totalWeight * 1.4)));
    const severity = points >= 12 ? "High" : "Medium";
    addFinding(
      report,
      severity,
      "Offline phishing database match",
      `Matched ${meaningful.length} learned phishing indicators from ${PHISHING_FEATURE_PROFILE.totalRows.toLocaleString("en-US")} labeled URL records: ${meaningful
        .slice(0, 8)
        .map((item) => item.feature)
        .join(", ")}.`,
      points
    );
  }
}

function inferDatasetFeatureMatches(report, parsed) {
  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".");
  const registrable = registrableDomain(host);
  const pathAfterScheme = report.normalizedUrl.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const matched = [];
  const add = (condition, feature) => {
    if (condition) matched.push(feature);
  };

  add(Boolean(net.isIP(host)), "UsingIP");
  add(report.normalizedUrl.length >= 75, "LongURL");
  add(SHORTENERS.has(registrable), "ShortURL");
  add(report.normalizedUrl.includes("@"), "Symbol@");
  add(pathAfterScheme.includes("//"), "Redirecting//");
  add(registrable.includes("-"), "PrefixSuffix-");
  add(labels.length >= 4, "SubDomains");
  add(parsed.protocol !== "https:", "HTTPS");
  add(isShortRegistration(report.whois), "DomainRegLen");
  add(parsed.port && !["80", "443"].includes(parsed.port), "NonStdPort");
  add(host.includes("https"), "HTTPSDomainURL");
  add((report.pageSignals.externalLinkRatio || 0) >= 0.61 || (report.pageSignals.externalFormActions || 0) > 0, "RequestURL");
  add((report.pageSignals.externalLinkRatio || 0) >= 0.67, "AnchorURL");
  add((report.pageSignals.externalScripts || 0) >= 8, "LinksInScriptTags");
  add((report.pageSignals.externalFormActions || 0) > 0 || ((report.pageSignals.emptyFormActions || 0) > 0 && (report.pageSignals.passwordInputs || 0) > 0), "ServerFormHandler");
  add((report.pageSignals.mailLinks || 0) > 0, "InfoEmail");
  add(Boolean(report.finalUrl && new URL(report.finalUrl).hostname.toLowerCase() !== host), "WebsiteForwarding");
  add((report.pageSignals.rightClickBlocks || 0) > 0, "DisableRightClick");
  add((report.pageSignals.popupCalls || 0) > 0, "UsingPopupWindow");
  add((report.pageSignals.iframes || 0) > 0, "IframeRedirection");
  add(report.whois?.domainAgeDays !== null && report.whois?.domainAgeDays !== undefined && report.whois.domainAgeDays < 180, "AgeofDomain");
  add(report.whois?.registered === false || report.errors.some((error) => error.toLowerCase().includes("dns lookup failed")), "DNSRecording");

  return unique(matched);
}

function isShortRegistration(whois) {
  const created = parseLooseDate(whois?.created);
  const expires = parseLooseDate(whois?.expires);
  if (!created || !expires) return false;
  return Math.floor((expires.getTime() - created.getTime()) / 86_400_000) < 365;
}

function finalize(report) {
  const score = Math.max(0, Math.min(100, report.findings.reduce((sum, finding) => sum + finding.points, 0)));
  report.riskScore = score;
  if (score >= 65) {
    report.verdict = "Dangerous";
    report.summary = "Multiple strong phishing or trust-risk signals were detected. Do not enter credentials or payment details.";
  } else if (score >= 30) {
    report.verdict = "Suspicious";
    report.summary = "The URL has warning signs. Verify the source and use the official website directly.";
  } else {
    report.verdict = "Safe";
    report.summary = "No strong phishing indicators were found in this scan. This is not a guarantee of safety.";
  }
}

function exportReport(report, filePath, format) {
  if (format === "json") {
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2), "utf8");
    return;
  }
  const rows = report.findings
    .map((finding) => `<tr><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(finding.title)}</td><td>${escapeHtml(finding.detail)}</td><td>${finding.points}</td></tr>`)
    .join("");
  const whoisCards = [
    ["Registrar", report.whois?.registrar],
    ["Created", report.whois?.created],
    ["Expires", report.whois?.expires],
    ["Domain age", report.whois?.domainAgeDays === null || report.whois?.domainAgeDays === undefined ? "Not provided" : `${report.whois.domainAgeDays} days`],
    ["WHOIS server", report.whois?.server],
    ["Local database", report.localIntelligence?.blocklistMatch?.status === "none" ? "No local hit" : `${report.localIntelligence?.blocklistMatch?.status} ${report.localIntelligence?.blocklistMatch?.type}`],
    ["Trained model", report.localIntelligence?.trainedModelScore === undefined ? "Not available" : `${report.localIntelligence.trainedModelScore}/100`],
    ["Confidence", report.localIntelligence?.confidence || "Not available"]
  ]
    .map(([label, value]) => `<div class="card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value || "Not provided")}</strong></div>`)
    .join("");
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Phishing URL Report</title>
  <style>body{font-family:Segoe UI,Arial,sans-serif;background:#07111f;color:#e5eefb;margin:32px}.badge{display:inline-block;padding:8px 12px;border-radius:10px;font-weight:800}.Safe{background:#dcfce7;color:#166534}.Suspicious{background:#fef3c7;color:#92400e}.Dangerous{background:#fee2e2;color:#991b1b}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.16);border-radius:14px;padding:14px}.card span{display:block;color:#9fb0c7;font-size:12px}.card strong{display:block;margin-top:8px}table{width:100%;border-collapse:collapse;margin-top:18px}td,th{border:1px solid rgba(255,255,255,.16);padding:10px;text-align:left;vertical-align:top}pre{white-space:pre-wrap;background:rgba(255,255,255,.07);border-radius:14px;padding:16px}</style></head>
  <body><h1>Phishing URL Report</h1><p>${escapeHtml(report.normalizedUrl)}</p><p><span class="badge ${report.verdict}">${report.verdict}</span> Risk score: ${report.riskScore}/100</p><p>${escapeHtml(report.summary)}</p>
  <h2>WHOIS lookup</h2><div class="grid">${whoisCards}</div><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Points</th></tr>${rows || "<tr><td colspan='4'>No notable findings.</td></tr>"}</table>
  <h2>Full report</h2><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></body></html>`;
  fs.writeFileSync(filePath, html, "utf8");
}

function entropy(value) {
  const counts = [...value].reduce((map, char) => map.set(char, (map.get(char) || 0) + 1), new Map());
  return [...counts.values()].reduce((sum, count) => {
    const p = count / value.length;
    return sum - p * Math.log2(p);
  }, 0);
}

function isPrivateOrReservedIp(ip) {
  if (ip.includes(":")) return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80");
  const parts = ip.split(".").map(Number);
  return parts[0] === 10 || parts[0] === 127 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || parts[0] === 0;
}

function domainCandidates(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return [labels.join(".")];
  const candidates = [];
  for (let i = 0; i <= labels.length - 2; i += 1) {
    candidates.push(labels.slice(i).join("."));
  }
  return unique(candidates);
}

function registrableDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join(".") : labels.join(".");
}

function parseWhoisRaw(raw) {
  if (!raw) {
    return { nameservers: [], status: [] };
  }
  return {
    domainName: firstField(raw, ["Domain Name"]),
    registryDomainId: firstField(raw, ["Registry Domain ID"]),
    registrarWhoisServer: firstField(raw, ["Registrar WHOIS Server", "Whois Server"]),
    registrar: firstField(raw, ["Registrar", "Sponsoring Registrar", "registrar"]),
    registrarIanaId: firstField(raw, ["Registrar IANA ID"]),
    created: firstField(raw, ["Creation Date", "Created On", "created", "Registered On", "Domain Registration Date"]),
    updated: firstField(raw, ["Updated Date", "Last Updated On", "changed"]),
    expires: firstField(raw, ["Registry Expiry Date", "Expiration Date", "Registrar Registration Expiration Date", "expires"]),
    registrantOrganization: firstField(raw, ["Registrant Organization", "Registrant Org"]),
    registrantStateProvince: firstField(raw, ["Registrant State/Province", "Registrant State"]),
    registrantCountry: firstField(raw, ["Registrant Country"]),
    registrantEmail: firstField(raw, ["Registrant Email"]),
    adminEmail: firstField(raw, ["Admin Email"]),
    techEmail: firstField(raw, ["Tech Email"]),
    billingEmail: firstField(raw, ["Billing Email"]),
    registrarAbuseContactEmail: firstField(raw, ["Registrar Abuse Contact Email", "Abuse Contact Email"]),
    registrarAbuseContactPhone: firstField(raw, ["Registrar Abuse Contact Phone", "Abuse Contact Phone"]),
    dnsSec: firstField(raw, ["DNSSEC", "DNS Sec"]),
    nameservers: unique([...values(raw, "Name Server"), ...values(raw, "nserver")].map(cleanWhoisToken)),
    status: unique([...values(raw, "Domain Status"), ...values(raw, "status")].map(cleanWhoisToken))
  };
}

function parseRdap(data) {
  const events = Array.isArray(data?.events) ? data.events : [];
  const getEvent = (...actions) => events.find((event) => actions.includes(String(event.eventAction || "").toLowerCase()))?.eventDate;
  const registrarEntity = (data?.entities || []).find((entity) => (entity.roles || []).includes("registrar"));
  const registrantEntity = (data?.entities || []).find((entity) => (entity.roles || []).includes("registrant"));
  return {
    domainName: data?.ldhName || data?.unicodeName,
    registryDomainId: data?.handle,
    registrar: entityDisplayName(registrarEntity),
    registrarIanaId: entityPublicId(registrarEntity, "IANA Registrar ID"),
    registrantOrganization: entityDisplayName(registrantEntity),
    registrantStateProvince: entityAddressPart(registrantEntity, 4),
    registrantCountry: entityAddressPart(registrantEntity, 6),
    registrarAbuseContactEmail: entityLink(registrarEntity, "abuse") || entityEmail(registrarEntity),
    registrarAbuseContactPhone: entityPhone(registrarEntity),
    dnsSec: data?.secureDNS?.delegationSigned === true ? "signed" : data?.secureDNS?.delegationSigned === false ? "unsigned" : null,
    created: getEvent("registration", "created"),
    updated: getEvent("last changed", "last update of rdap database", "last update"),
    expires: getEvent("expiration", "expiry"),
    nameservers: (data?.nameservers || []).map((item) => item.ldhName || item.unicodeName).filter(Boolean),
    status: Array.isArray(data?.status) ? data.status : []
  };
}

function entityDisplayName(entity) {
  const entries = entity?.vcardArray?.[1];
  if (!Array.isArray(entries)) return null;
  const fn = entries.find((entry) => entry[0] === "fn")?.[3];
  const org = entries.find((entry) => entry[0] === "org")?.[3];
  return Array.isArray(org) ? org.filter(Boolean).join(" ") : org || fn || null;
}

function entityPublicId(entity, type) {
  return (entity?.publicIds || []).find((item) => String(item.type || "").toLowerCase() === type.toLowerCase())?.identifier || null;
}

function entityEmail(entity) {
  const entries = entity?.vcardArray?.[1];
  if (!Array.isArray(entries)) return null;
  return entries.find((entry) => entry[0] === "email")?.[3] || null;
}

function entityPhone(entity) {
  const entries = entity?.vcardArray?.[1];
  if (!Array.isArray(entries)) return null;
  return entries.find((entry) => entry[0] === "tel")?.[3] || null;
}

function entityAddressPart(entity, index) {
  const entries = entity?.vcardArray?.[1];
  if (!Array.isArray(entries)) return null;
  const address = entries.find((entry) => entry[0] === "adr")?.[3];
  return Array.isArray(address) ? address[index] || null : null;
}

function entityLink(entity, rel) {
  return (entity?.links || []).find((link) => String(link.rel || "").toLowerCase() === rel.toLowerCase())?.href || null;
}

function isNoMatch(raw) {
  return /(no match for|not found|no data found|no entries found|object does not exist|domain not found|status:\s*free)/i.test(raw || "");
}

function isExternalUrl(value, host) {
  try {
    const parsed = new URL(value, `https://${host}`);
    return parsed.hostname.toLowerCase() !== host.toLowerCase();
  } catch {
    return false;
  }
}

function countMatches(text, pattern) {
  return (text.match(pattern) || []).length;
}

function firstMatch(text, pattern) {
  return text.match(pattern)?.[1]?.trim() || null;
}

function values(text, key) {
  const pattern = new RegExp(`^\\s*${escapeRegExp(key)}:\\s*(.+)$`, "gim");
  return [...text.matchAll(pattern)].map((match) => match[1].trim()).filter(Boolean);
}

function firstField(text, keys) {
  for (const key of keys) {
    const found = values(text, key)[0];
    if (found) return found;
  }
  return null;
}

function cleanWhoisToken(value) {
  return String(value || "")
    .replace(/\s*\(https?:\/\/[^)]*\)/gi, "")
    .replace(/\s+https?:\/\/\S+/gi, "")
    .replace(/\s+\($/, "")
    .trim();
}

function addResolvedIpGroups(whois, addresses) {
  const ips = Array.isArray(addresses) ? addresses : [];
  return {
    ...whois,
    ipv4: unique(ips.filter((ip) => ip.includes("."))),
    ipv6: unique(ips.filter((ip) => ip.includes(":")))
  };
}

function unique(items) {
  return [...new Set(items.filter(Boolean).map((item) => String(item).trim()).filter(Boolean))];
}

function uniqueCaseInsensitive(items) {
  const seen = new Map();
  for (const item of items) {
    const cleaned = String(item || "").trim();
    if (!cleaned) continue;
    const key = cleaned.toLowerCase().replace(/[^a-z0-9:.-]/g, "");
    if (!seen.has(key)) seen.set(key, cleaned);
  }
  return [...seen.values()];
}

function parseLooseDate(value) {
  const iso = value.match(/\d{4}-\d{2}-\d{2}/)?.[0];
  const parsed = iso ? new Date(`${iso}T00:00:00Z`) : new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

module.exports = { scanUrl, exportReport };

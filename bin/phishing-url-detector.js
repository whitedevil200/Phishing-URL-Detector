#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");
const { exportReport, scanUrl } = require("../src/main/scanner");
const { evaluateThreatModel } = require("../src/main/evaluator");
const { getLocalIntelligenceStatus } = require("../src/main/local-intelligence");

async function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    return;
  }
  const explicitCommand = argv[2] && ["scan", "whois", "status", "evaluate", "help"].includes(argv[2]) ? argv[2] : null;
  const command = explicitCommand || "scan";
  const args = explicitCommand ? argv.slice(3) : argv.slice(2);

  if (["help", "--help", "-h"].includes(command)) {
    printHelp();
    return;
  }
  if (command === "status") {
    printStatus(getLocalIntelligenceStatus(), hasFlag(args, "--json"));
    return;
  }
  if (command === "evaluate") {
    const result = await evaluateThreatModel();
    if (hasFlag(args, "--json")) printJson(result);
    else printEvaluation(result);
    return;
  }
  if (command === "whois") {
    const url = readTarget(args);
    if (!url) {
      printHelp();
      process.exitCode = 1;
      return;
    }
    const report = await scanUrl(url, { fetchSite: false, network: true, timeoutMs: Number(readAnyOption(args, ["--timeout", "-t"]) || 9000) });
    if (hasAnyFlag(args, ["--json", "-j"])) printJson(report.whois || {});
    else printWhois(report);
    if (!report.whois?.available) process.exitCode = 1;
    return;
  }
  if (command !== "scan") {
    throw new Error(`Unknown command: ${command}`);
  }

  const url = readTarget(args);
  if (!url) {
    printHelp();
    process.exitCode = 1;
    return;
  }

  const options = {
    fetchSite: !hasFlag(args, "--no-site") && !hasAnyFlag(args, ["--fast", "-f"]),
    network: !hasFlag(args, "--no-network") && !hasAnyFlag(args, ["--fast", "-f"]),
    timeoutMs: Number(readAnyOption(args, ["--timeout", "-t"]) || 9000)
  };
  const report = await scanUrl(url, options);
  const outPath = readAnyOption(args, ["--out", "-o"]);
  const format = readOption(args, "--format") || (outPath?.toLowerCase().endsWith(".html") ? "html" : "json");

  if (outPath) {
    const target = path.resolve(outPath);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    exportReport(report, target, format === "html" ? "html" : "json");
  }

  if (hasAnyFlag(args, ["--json", "-j"])) printJson(report);
  else printSummary(report, outPath);

  if (report.verdict === "Dangerous") process.exitCode = 2;
  else if (report.verdict === "Suspicious") process.exitCode = 1;
}

function printSummary(report, outPath) {
  const local = report.localIntelligence || {};
  console.log("Phishing URL Detector");
  console.log("=====================");
  console.log(`Target          : ${report.normalizedUrl}`);
  console.log(`Verdict         : ${report.verdict}`);
  console.log(`Risk Score      : ${report.riskScore}/100`);
  console.log(`Confidence      : ${local.confidence || "n/a"}`);
  console.log(`Local Database  : ${formatBlocklist(local.blocklistMatch)}`);
  console.log(`Model Score     : ${local.trainedModelScore ?? "n/a"}/100`);
  console.log(`Inference Time  : ${report.performance?.inferenceMs ?? "n/a"} ms`);
  console.log(`Summary         : ${report.summary}`);
  printWhoisDetails(report, { compact: true });
  if (report.findings.length) {
    console.log("\nFindings:");
    for (const finding of report.findings.slice(0, 12)) {
      console.log(`- [${finding.severity}] ${finding.title}: ${finding.detail}`);
    }
  }
  if (outPath) console.log(`\nReport saved: ${path.resolve(outPath)}`);
}

function formatBlocklist(match) {
  if (!match || match.status === "none") return "none";
  return `${match.status} ${match.type}`;
}

function printWhois(report) {
  printWhoisDetails(report, { compact: false });
}

function printWhoisDetails(report, { compact }) {
  const whois = report.whois || {};
  console.log("\nWHOIS Lookup");
  console.log("============");
  if (!compact) console.log(`Target          : ${report.normalizedUrl || report.inputUrl}`);
  console.log(`Domain/IP       : ${report.domain || "n/a"}`);
  console.log(`Status          : ${whois.available ? "Found" : "Not available"}`);
  console.log(`Source          : ${whois.source || whois.server || "n/a"}`);
  console.log(`Registrar       : ${whois.registrar || "Not provided"}`);
  console.log(`IANA ID         : ${whois.registrarIanaId || "Not provided"}`);
  console.log(`Created         : ${whois.created || "Not provided"}`);
  console.log(`Updated         : ${whois.updated || "Not provided"}`);
  console.log(`Expires         : ${whois.expires || "Not provided"}`);
  console.log(`Domain Age      : ${whois.domainAgeDays === null || whois.domainAgeDays === undefined ? "Not provided" : `${whois.domainAgeDays} days`}`);
  console.log(`DNSSEC          : ${whois.dnsSec || "Not provided"}`);
  console.log(`Registrant      : ${whois.registrantOrganization || whois.registrantName || "Not provided"}`);
  console.log(`Country         : ${whois.registrantCountry || "Not provided"}`);
  console.log(`Abuse Email     : ${whois.registrarAbuseContactEmail || "Not provided"}`);
  console.log(`Abuse Phone     : ${whois.registrarAbuseContactPhone || "Not provided"}`);
  printList("Name Servers", whois.nameservers);
  printList("Domain Status", whois.status);
  printList("IPv4 Addresses", whois.ipv4);
  printList("IPv6 Addresses", whois.ipv6);
  if (whois.error) console.log(`Error           : ${whois.error}`);
}

function printList(label, items) {
  const values = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!values.length) {
    console.log(`${label.padEnd(16)}: Not provided`);
    return;
  }
  console.log(`${label.padEnd(16)}: ${values[0]}`);
  for (const value of values.slice(1)) console.log(`${"".padEnd(16)}  ${value}`);
}

function printEvaluation(result) {
  const metrics = result.metrics;
  console.log("Accuracy evaluation");
  console.log(`Precision: ${percent(metrics.precision)}`);
  console.log(`Recall: ${percent(metrics.recall)}`);
  console.log(`F1: ${percent(metrics.f1)}`);
  console.log(`False positive rate: ${percent(metrics.falsePositiveRate)}`);
  console.log(`ROC-AUC approximation: ${percent(metrics.rocAucApproximation)}`);
  console.log(`Average inference: ${metrics.averageInferenceMs} ms`);
}

function printStatus(status, asJson) {
  if (asJson) {
    printJson(status);
    return;
  }
  console.log(`Database version: ${status.databaseVersion || "missing"}`);
  console.log(`Generated: ${status.generatedAt || "not available"}`);
  for (const [name, count] of Object.entries(status.counts || {})) {
    console.log(`${name}: ${Number(count).toLocaleString("en-US")}`);
  }
  if (status.refreshFailures?.length) {
    console.log("\nRefresh warnings:");
    for (const failure of status.refreshFailures) {
      console.log(`- ${failure.source}: ${failure.message}`);
    }
  }
}

function printHelp() {
  console.log(`Phishing URL Detector CLI

Usage:
  phishing-url-detector -u <url> [options]
  phishing-url-detector whois -u <url> [options]
  phishing-url-detector scan <url> [--fast] [--json] [--out report.json|report.html] [--format json|html]
  phishing-url-detector status [--json]
  phishing-url-detector evaluate [--json]

Options:
  -u, --url <url>  Target URL or domain to scan.
  -f, --fast       Use local URL/model intelligence only; skip DNS, TLS, WHOIS, and page fetch.
  --no-network     Skip DNS, TLS, and WHOIS checks.
  --no-site        Skip website content fetch but keep DNS/TLS/WHOIS checks.
  -t, --timeout    Network timeout for full scans. Default: 9000.
  -j, --json       Print machine-readable JSON.
  -o, --out <file> Save report as JSON or HTML.

Examples:
  phishing-url-detector -u https://example.com
  phishing-url-detector whois -u https://example.com
  phishing-url-detector -u https://example.com -f
  phishing-url-detector -u https://example.com -o report.html --format html
`);
}

function hasFlag(args, flag) {
  return args.includes(flag);
}

function hasAnyFlag(args, flags) {
  return flags.some((flag) => args.includes(flag));
}

function readOption(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

function readAnyOption(args, names) {
  for (const name of names) {
    const value = readOption(args, name);
    if (value) return value;
  }
  return null;
}

function readTarget(args) {
  return readAnyOption(args, ["--url", "-u"]) || firstValue(args);
}

function firstValue(args) {
  const optionsWithValues = new Set(["--url", "-u", "--out", "-o", "--format", "--timeout", "-t"]);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (optionsWithValues.has(arg)) {
      index += 1;
      continue;
    }
    if (!arg.startsWith("-")) return arg;
  }
  return null;
}

function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

function percent(value) {
  return Number.isFinite(value) ? `${Math.round(value * 1000) / 10}%` : "n/a";
}

main(process.argv).catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exit(1);
});

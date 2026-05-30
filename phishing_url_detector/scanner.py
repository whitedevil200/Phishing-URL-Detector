from __future__ import annotations

import datetime as _dt
import html.parser
import ipaddress
import json
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Iterable


SUSPICIOUS_KEYWORDS = {
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
    "wallet",
}

SUSPICIOUS_TLDS = {
    "biz",
    "cam",
    "click",
    "club",
    "country",
    "download",
    "fit",
    "gq",
    "icu",
    "info",
    "kim",
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
    "zip",
}

KNOWN_SHORTENERS = {
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
    "tinyurl.com",
    "trib.al",
}

BRAND_TARGETS = {
    "amazon",
    "apple",
    "binance",
    "facebook",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "paypal",
    "whatsapp",
    "yahoo",
}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    points: int


@dataclass
class UrlReport:
    input_url: str
    normalized_url: str
    scanned_at: str
    verdict: str
    risk_score: int
    summary: str
    final_url: str | None = None
    domain: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    whois: dict = field(default_factory=dict)
    page_signals: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["findings"] = [asdict(finding) for finding in self.findings]
        return data


class _SignalParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.external_scripts = 0
        self.iframes = 0
        self.links = 0
        self.external_links = 0
        self.title = ""
        self._in_title = False
        self._base_host = ""

    def set_base_host(self, host: str) -> None:
        self._base_host = host

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self.forms += 1
        elif tag == "input":
            input_type = attrs_map.get("type", "").lower()
            if input_type == "password":
                self.password_inputs += 1
            if input_type == "hidden":
                self.hidden_inputs += 1
        elif tag == "iframe":
            self.iframes += 1
        elif tag == "script":
            src = attrs_map.get("src")
            if src and _is_external_url(src, self._base_host):
                self.external_scripts += 1
        elif tag == "a":
            self.links += 1
            href = attrs_map.get("href")
            if href and _is_external_url(href, self._base_host):
                self.external_links += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()[:200]


def scan_url(url: str, *, fetch_site: bool = True, timeout: float = 8.0) -> UrlReport:
    started = _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat()
    normalized = _normalize_url(url)
    report = UrlReport(
        input_url=url,
        normalized_url=normalized,
        scanned_at=started,
        verdict="Unknown",
        risk_score=0,
        summary="Scan started.",
    )

    parsed = urllib.parse.urlparse(normalized)
    host = (parsed.hostname or "").strip(".").lower()
    report.domain = host or None
    path_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path

    _analyze_url_structure(report, parsed, host, path_query)
    _resolve_dns(report, host, timeout)
    _inspect_tls(report, host, timeout)

    if fetch_site:
        _fetch_page(report, normalized, host, timeout)

    _lookup_whois(report, host, timeout)
    _finalize_verdict(report)
    return report


def export_json(report: UrlReport, path: str) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(report.to_dict(), file, indent=2, ensure_ascii=False)


def export_html(report: UrlReport, path: str) -> None:
    verdict_class = report.verdict.lower().replace(" ", "-")
    findings = "\n".join(
        f"<tr><td>{_escape(f.severity)}</td><td>{_escape(f.title)}</td>"
        f"<td>{_escape(f.detail)}</td><td>{f.points}</td></tr>"
        for f in report.findings
    )
    ips = ", ".join(report.ip_addresses) or "Not resolved"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Phishing URL Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #172033; }}
    .badge {{ display: inline-block; padding: 8px 12px; border-radius: 8px; font-weight: 700; }}
    .safe {{ background: #dcfce7; color: #166534; }}
    .suspicious {{ background: #fef3c7; color: #92400e; }}
    .dangerous {{ background: #fee2e2; color: #991b1b; }}
    .unknown {{ background: #e5e7eb; color: #374151; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
    td, th {{ border: 1px solid #d8dee9; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f8fafc; }}
    pre {{ background: #f8fafc; padding: 16px; overflow: auto; }}
  </style>
</head>
<body>
  <h1>Phishing URL Report</h1>
  <p><strong>URL:</strong> {_escape(report.normalized_url)}</p>
  <p><strong>Scanned:</strong> {_escape(report.scanned_at)}</p>
  <p><span class="badge {verdict_class}">{_escape(report.verdict)}</span>
  <strong>Risk score:</strong> {report.risk_score}/100</p>
  <p>{_escape(report.summary)}</p>
  <h2>Network</h2>
  <table>
    <tr><th>Domain</th><td>{_escape(report.domain or "Unknown")}</td></tr>
    <tr><th>Final URL</th><td>{_escape(report.final_url or "Not fetched")}</td></tr>
    <tr><th>IP Addresses</th><td>{_escape(ips)}</td></tr>
    <tr><th>TLS</th><td><pre>{_escape(json.dumps(report.tls, indent=2, ensure_ascii=False))}</pre></td></tr>
    <tr><th>HTTP</th><td><pre>{_escape(json.dumps(report.http, indent=2, ensure_ascii=False))}</pre></td></tr>
    <tr><th>WHOIS</th><td><pre>{_escape(json.dumps(report.whois, indent=2, ensure_ascii=False))}</pre></td></tr>
  </table>
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Points</th></tr>
    {findings or '<tr><td colspan="4">No notable findings.</td></tr>'}
  </table>
  <h2>Page Signals</h2>
  <pre>{_escape(json.dumps(report.page_signals, indent=2, ensure_ascii=False))}</pre>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as file:
        file.write(html)


def _normalize_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned:
        return ""
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    return cleaned


def _add(report: UrlReport, severity: str, title: str, detail: str, points: int) -> None:
    report.findings.append(Finding(severity, title, detail, points))


def _analyze_url_structure(
    report: UrlReport, parsed: urllib.parse.ParseResult, host: str, path_query: str
) -> None:
    if not parsed.scheme or not host:
        _add(report, "High", "Invalid URL", "The value could not be parsed as a normal URL.", 35)
        return

    if parsed.scheme != "https":
        _add(report, "High", "No HTTPS", "The URL does not use HTTPS.", 25)

    if len(report.normalized_url) > 120:
        _add(report, "Medium", "Very long URL", "Long URLs are commonly used to hide malicious destinations.", 12)

    if "@" in report.normalized_url:
        _add(report, "High", "Userinfo trick", "The URL contains '@', which can hide the real host.", 30)

    labels = host.split(".")
    if len(labels) >= 5:
        _add(report, "Medium", "Many subdomains", "The host has many labels, often used to imitate real brands.", 12)

    try:
        ipaddress.ip_address(host)
        _add(report, "High", "IP address host", "Legitimate public services rarely ask users to sign in through a raw IP.", 25)
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        _add(report, "Medium", "Punycode domain", "Punycode can be legitimate but is also used in homograph attacks.", 18)

    if re.search(r"[^a-z0-9.-]", host):
        _add(report, "Medium", "Unusual host characters", "The host contains characters outside a conservative ASCII set.", 14)

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        _add(report, "Low", "Risky top-level domain", f".{tld} is often abused in phishing campaigns.", 7)

    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if registrable in KNOWN_SHORTENERS:
        _add(report, "Medium", "URL shortener", "Shortened links hide the final destination until opened.", 16)

    hyphen_count = host.count("-")
    digit_count = sum(ch.isdigit() for ch in host)
    if hyphen_count >= 3:
        _add(report, "Low", "Many hyphens", "Brand impersonation domains often include many hyphens.", 6)
    if digit_count >= 5:
        _add(report, "Low", "Many digits", "The host contains many digits, which is uncommon for major brands.", 6)

    url_text = f"{host} {path_query}".lower()
    keyword_hits = sorted(word for word in SUSPICIOUS_KEYWORDS if word in url_text)
    if len(keyword_hits) >= 2:
        _add(
            report,
            "Medium",
            "Credential-themed wording",
            f"Found phishing-themed words: {', '.join(keyword_hits[:8])}.",
            min(20, 6 + len(keyword_hits) * 3),
        )

    brand_hits = sorted(brand for brand in BRAND_TARGETS if brand in host)
    if brand_hits:
        for brand in brand_hits:
            if not host.endswith(f"{brand}.com") and host != f"{brand}.com":
                _add(
                    report,
                    "High",
                    "Possible brand impersonation",
                    f"The host contains '{brand}' but is not the common primary domain.",
                    22,
                )
                break

    entropy = _shannon_entropy(host.replace(".", ""))
    if entropy > 3.7 and len(host) > 18:
        _add(report, "Low", "High entropy domain", "The domain looks randomly generated.", 8)

    encoded = re.findall(r"%[0-9a-fA-F]{2}", report.normalized_url)
    if len(encoded) >= 4:
        _add(report, "Medium", "Heavy URL encoding", "Encoded characters can hide the readable destination.", 12)


def _resolve_dns(report: UrlReport, host: str, timeout: float) -> None:
    if not host:
        return
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        addresses = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({item[4][0] for item in addresses})
        report.ip_addresses = ips
        private_ips = []
        for ip in ips:
            try:
                parsed_ip = ipaddress.ip_address(ip)
                if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_reserved:
                    private_ips.append(ip)
            except ValueError:
                continue
        if private_ips:
            _add(report, "High", "Private or reserved IP", f"Resolved to {', '.join(private_ips)}.", 25)
    except OSError as exc:
        report.errors.append(f"DNS lookup failed: {exc}")
        _add(report, "Medium", "DNS lookup failed", "The host did not resolve during the scan.", 14)
    finally:
        socket.setdefaulttimeout(old_timeout)


def _inspect_tls(report: UrlReport, host: str, timeout: float) -> None:
    if not host:
        return
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                not_after = cert.get("notAfter")
                issuer = _name_tuple_to_text(cert.get("issuer", ()))
                subject = _name_tuple_to_text(cert.get("subject", ()))
                report.tls = {
                    "valid": True,
                    "issuer": issuer,
                    "subject": subject,
                    "expires": not_after,
                    "version": tls_sock.version(),
                }
                if not_after:
                    expires = _parse_cert_time(not_after)
                    if expires:
                        days_left = (expires - _dt.datetime.now(_dt.UTC)).days
                        report.tls["days_left"] = days_left
                        if days_left < 7:
                            _add(report, "Medium", "TLS certificate expiring soon", f"Certificate expires in {days_left} days.", 10)
    except Exception as exc:  # noqa: BLE001 - certificate failures matter as a signal.
        report.tls = {"valid": False, "error": str(exc)}
        _add(report, "High", "TLS problem", f"Certificate or TLS connection failed: {exc}", 22)


def _fetch_page(report: UrlReport, url: str, host: str, timeout: float) -> None:
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PhishingURLDetector/1.0 (+local-security-check)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        method="GET",
    )
    start = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(600_000)
            final_url = response.geturl()
            elapsed = round(time.monotonic() - start, 2)
            content_type = response.headers.get("Content-Type", "")
            report.final_url = final_url
            report.http = {
                "status": getattr(response, "status", None),
                "content_type": content_type,
                "elapsed_seconds": elapsed,
                "headers": {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower()
                    in {
                        "content-security-policy",
                        "location",
                        "server",
                        "strict-transport-security",
                        "x-content-type-options",
                        "x-frame-options",
                    }
                },
            }
            _analyze_http(report, url, final_url, content_type, response.headers)
            if "text/html" in content_type.lower() or body.lstrip().startswith(b"<!"):
                _analyze_html(report, body, urllib.parse.urlparse(final_url).hostname or host)
    except urllib.error.HTTPError as exc:
        report.http = {"status": exc.code, "error": str(exc)}
        if exc.code in {401, 403}:
            _add(report, "Low", "Restricted response", f"Server returned HTTP {exc.code}.", 4)
        else:
            _add(report, "Medium", "HTTP error", f"Server returned HTTP {exc.code}.", 10)
    except Exception as exc:  # noqa: BLE001 - all fetch failures are useful to the report.
        report.http = {"error": str(exc)}
        report.errors.append(f"Website fetch failed: {exc}")
        _add(report, "Low", "Website scan incomplete", "The site could not be fetched for page-level checks.", 5)


def _analyze_http(
    report: UrlReport,
    original_url: str,
    final_url: str,
    content_type: str,
    headers: urllib.request._HeadersBase,
) -> None:
    original_host = urllib.parse.urlparse(original_url).hostname or ""
    final_host = urllib.parse.urlparse(final_url).hostname or ""
    if original_host and final_host and original_host != final_host:
        _add(report, "Medium", "Redirected to another host", f"{original_host} redirected to {final_host}.", 14)
    if "text/html" not in content_type.lower():
        _add(report, "Low", "Unexpected content type", f"Content-Type is {content_type or 'unknown'}.", 4)
    if not headers.get("Strict-Transport-Security"):
        _add(report, "Low", "Missing HSTS", "The server did not advertise HTTP Strict Transport Security.", 4)
    if not headers.get("Content-Security-Policy"):
        _add(report, "Low", "Missing CSP", "No Content-Security-Policy header was found.", 3)


def _analyze_html(report: UrlReport, body: bytes, host: str) -> None:
    text = body.decode("utf-8", errors="replace")
    parser = _SignalParser()
    parser.set_base_host(host)
    try:
        parser.feed(text)
    except html.parser.HTMLParseError:
        pass

    external_ratio = parser.external_links / parser.links if parser.links else 0
    report.page_signals = {
        "title": parser.title[:160],
        "forms": parser.forms,
        "password_inputs": parser.password_inputs,
        "hidden_inputs": parser.hidden_inputs,
        "iframes": parser.iframes,
        "links": parser.links,
        "external_links": parser.external_links,
        "external_link_ratio": round(external_ratio, 2),
        "external_scripts": parser.external_scripts,
        "downloaded_bytes": len(body),
    }

    if parser.password_inputs:
        _add(report, "High", "Password form detected", "The page asks for a password or credential input.", 22)
    if parser.forms >= 2 and parser.hidden_inputs >= 5:
        _add(report, "Medium", "Complex form collection", "Multiple forms and hidden inputs can indicate credential capture.", 12)
    if parser.iframes:
        _add(report, "Low", "Iframe usage", "The page includes iframe content, which can conceal third-party flows.", 5)
    if parser.links >= 10 and external_ratio > 0.7:
        _add(report, "Medium", "Mostly external links", "Most page links point away from the scanned host.", 10)
    if parser.external_scripts >= 8:
        _add(report, "Low", "Many external scripts", "The page loads many scripts from other hosts.", 6)


def _lookup_whois(report: UrlReport, host: str, timeout: float) -> None:
    if not host or _looks_like_ip(host):
        return
    try:
        iana = _query_whois("whois.iana.org", host, timeout)
        whois_server = _extract_first(iana, r"(?im)^whois:\s*(\S+)")
        registrar = _extract_first(iana, r"(?im)^refer:\s*(\S+)")
        raw = iana
        if whois_server:
            raw = _query_whois(whois_server, host, timeout)
        creation = _first_date(raw, ("Creation Date", "Created On", "created", "Registered On", "Domain Registration Date"))
        expiry = _first_date(raw, ("Registry Expiry Date", "Expiration Date", "Registrar Registration Expiration Date"))
        status = _all_values(raw, "Domain Status")[:8]
        registrar_name = _extract_first(raw, r"(?im)^Registrar:\s*(.+)$") or registrar
        report.whois = {
            "server": whois_server or "whois.iana.org",
            "registrar": registrar_name,
            "created": creation,
            "expires": expiry,
            "status": status,
            "raw_excerpt": raw[:2500],
        }
        if creation:
            created_at = _parse_loose_date(creation)
            if created_at:
                age_days = (_dt.datetime.now(_dt.UTC) - created_at).days
                report.whois["domain_age_days"] = age_days
                if age_days < 30:
                    _add(report, "High", "Very new domain", f"WHOIS suggests the domain is {age_days} days old.", 24)
                elif age_days < 180:
                    _add(report, "Medium", "Recently registered domain", f"WHOIS suggests the domain is {age_days} days old.", 13)
    except Exception as exc:  # noqa: BLE001 - WHOIS servers often throttle or vary formats.
        report.whois = {"error": str(exc)}
        report.errors.append(f"WHOIS lookup failed: {exc}")
        _add(report, "Low", "WHOIS unavailable", "WHOIS information could not be collected.", 4)


def _query_whois(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(chunk) for chunk in chunks) > 90_000:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def _finalize_verdict(report: UrlReport) -> None:
    score = max(0, min(100, sum(finding.points for finding in report.findings)))
    report.risk_score = score
    if score >= 65:
        report.verdict = "Dangerous"
        report.summary = "Multiple strong phishing or trust-risk signals were detected. Do not enter credentials or payment details."
    elif score >= 30:
        report.verdict = "Suspicious"
        report.summary = "The URL has warning signs. Verify the source and use the official website directly."
    else:
        report.verdict = "Safe"
        report.summary = "No strong phishing indicators were found in this scan. This is not a guarantee of safety."


def _is_external_url(value: str, base_host: str) -> bool:
    parsed = urllib.parse.urlparse(value)
    if not parsed.netloc:
        return False
    return (parsed.hostname or "").lower() != base_host.lower()


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value)) for char in set(value))


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _name_tuple_to_text(value: Iterable) -> str:
    parts = []
    for group in value:
        for key, text in group:
            parts.append(f"{key}={text}")
    return ", ".join(parts)


def _parse_cert_time(value: str) -> _dt.datetime | None:
    try:
        return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.UTC)
    except ValueError:
        return None


def _parse_loose_date(value: str) -> _dt.datetime | None:
    cleaned = value.strip()
    formats = (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d.%m.%Y",
        "%Y.%m.%d",
        "%Y/%m/%d",
    )
    for fmt in formats:
        try:
            return _dt.datetime.strptime(cleaned[:26], fmt).replace(tzinfo=_dt.UTC)
        except ValueError:
            continue
    match = re.search(r"\d{4}-\d{2}-\d{2}", cleaned)
    if match:
        return _parse_loose_date(match.group(0))
    return None


def _extract_first(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    if match:
        return match.group(1).strip()
    return None


def _all_values(text: str, key: str) -> list[str]:
    return [match.strip() for match in re.findall(rf"(?im)^{re.escape(key)}:\s*(.+)$", text)]


def _first_date(text: str, keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = _extract_first(text, rf"(?im)^{re.escape(key)}:\s*(.+)$")
        if value:
            return value.strip()
    return None


def _escape(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

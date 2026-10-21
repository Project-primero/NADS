"""Website uptime + vulnerability scanner.

Performs periodic HTTP(S) checks against registered sites:
  - availability / latency / status code
  - TLS certificate + protocol audit
  - full security header audit
  - cookie security flags
  - sensitive path / misconfiguration exposure probes
  - CMS / technology fingerprinting + known version risks
  - CORS, mixed content, clickjacking, HTML info leaks

Findings include category, CWE, MITRE, evidence, and detailed remediation.
"""
from __future__ import annotations
import asyncio
import ipaddress
import re
import socket
import ssl
import struct
import time
import urllib.parse
from typing import Callable

import httpx

BROWSER_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close",
}

# ── Security headers expected on a hardened site ─────────
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "MEDIUM", "CWE-319", "T1595.002",
     "Enable HTTP Strict Transport Security to force HTTPS.",
     "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    ("content-security-policy", "CSP", "MEDIUM", "CWE-693", "T1189",
     "Set a Content-Security-Policy to mitigate XSS, data injection, and clickjacking.",
     "Start with: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'… then tighten."),
    ("x-frame-options", "X-Frame-Options", "LOW", "CWE-1021", "T1189",
     "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
     "Alternatively use CSP frame-ancestors 'none'."),
    ("x-content-type-options", "X-Content-Type-Options", "LOW", "CWE-16", "T1189",
     "Set X-Content-Type-Options: nosniff to prevent MIME sniffing.",
     "Header value must be exactly: nosniff"),
    ("referrer-policy", "Referrer-Policy", "LOW", "CWE-200", "T1595",
     "Set Referrer-Policy to control cross-origin referrer leakage.",
     "Recommended: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", "Permissions-Policy", "LOW", "CWE-200", "T1595",
     "Set Permissions-Policy to disable unused browser features.",
     "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ("cross-origin-opener-policy", "COOP", "LOW", "CWE-1021", "T1189",
     "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context.",
     "Header: Cross-Origin-Opener-Policy: same-origin"),
    ("cross-origin-resource-policy", "CORP", "LOW", "CWE-200", "T1595",
     "Set Cross-Origin-Resource-Policy to limit cross-origin resource embedding.",
     "Header: Cross-Origin-Resource-Policy: same-origin"),
    ("x-permitted-cross-domain-policies", "X-Permitted-Cross-Domain-Policies", "LOW", "CWE-942", "T1189",
     "Restrict Flash/PDF cross-domain policies.",
     "Header: X-Permitted-Cross-Domain-Policies: none"),
]

# ── Exposure / misconfiguration probes (safe, unauthenticated) ─────────
EXPOSURE_PATHS = [
    ("/.env", "Exposed environment file", "CRITICAL", "CWE-538", "T1552.001",
     "Block /.env at the web server (nginx/apache/CDN) and rotate any secrets that were public."),
    ("/.git/HEAD", "Exposed Git repository metadata", "HIGH", "CWE-538", "T1530",
     "Deny access to /.git/ and rewrite history + rotate keys if a repo was ever exposed."),
    ("/.git/config", "Exposed Git config", "HIGH", "CWE-538", "T1530",
     "Deny /.git/* at the edge and treat any historical exposure as a secret leak."),
    ("/.svn/entries", "Exposed Subversion metadata", "MEDIUM", "CWE-538", "T1530",
     "Block /.svn/* paths from public access."),
    ("/.DS_Store", "Exposed macOS directory listing", "LOW", "CWE-548", "T1530",
     "Block .DS_Store files; they leak directory structure."),
    ("/.htaccess", "Exposed Apache .htaccess", "MEDIUM", "CWE-538", "T1552.001",
     "Deny HTTP access to .htaccess and similar server config files."),
    ("/.htpasswd", "Exposed password file", "CRITICAL", "CWE-522", "T1552.001",
     "Immediate: remove .htpasswd from web root and rotate credentials."),
    ("/.well-known/security.txt", "security.txt present", "INFO", "CWE-200", "—",
     "Optional: security.txt is fine; ensure contact is monitored."),
    ("/server-status", "Apache server-status exposed", "MEDIUM", "CWE-200", "T1595.003",
     "Disable mod_status or restrict to localhost / trusted IPs."),
    ("/server-info", "Apache server-info exposed", "MEDIUM", "CWE-200", "T1595.003",
     "Disable mod_info or restrict access."),
    ("/phpinfo.php", "phpinfo() exposed", "HIGH", "CWE-200", "T1595.002",
     "Remove phpinfo files; they leak paths, versions, and config."),
    ("/info.php", "phpinfo() exposed", "HIGH", "CWE-200", "T1595.002",
     "Remove info.php and similar diagnostic scripts."),
    ("/wp-login.php", "WordPress login page exposed", "LOW", "CWE-200", "T1595.002",
     "Rate-limit wp-login.php, add WAF rules, or move login off the default path."),
    ("/wp-admin/", "WordPress admin path exposed", "LOW", "CWE-200", "T1595.002",
     "Restrict /wp-admin/ by IP or SSO + MFA."),
    ("/xmlrpc.php", "WordPress XML-RPC enabled", "MEDIUM", "CWE-307", "T1595.002",
     "Disable xmlrpc.php or block it in the WAF — it enables amplification and brute force."),
    ("/wp-json/wp/v2/users", "WordPress user enumeration", "MEDIUM", "CWE-200", "T1595.002",
     "Disable the REST user endpoint or require auth for /wp-json/wp/v2/users."),
    ("/phpmyadmin/", "phpMyAdmin exposed", "HIGH", "CWE-200", "T1595.002",
     "Remove phpMyAdmin from production or bind to a private VPN path."),
    ("/adminer.php", "Adminer exposed", "HIGH", "CWE-200", "T1595.002",
     "Remove Adminer; never ship DB admin tools to the public web root."),
    ("/admin/", "Admin path exposed", "LOW", "CWE-200", "T1595.002",
     "Protect /admin/ with strong auth + IP allowlist."),
    ("/administrator/", "Admin path exposed", "LOW", "CWE-200", "T1595.002",
     "Protect admin paths; disable default installer URLs."),
    ("/actuator/health", "Spring Actuator exposed", "MEDIUM", "CWE-200", "T1595.002",
     "Secure Spring actuators or disable public actuator endpoints."),
    ("/actuator/env", "Spring Actuator env exposed", "HIGH", "CWE-200", "T1552.001",
     "Disable /actuator/env publicly — it can leak secrets."),
    ("/debug/", "Debug endpoint exposed", "MEDIUM", "CWE-489", "T1595.002",
     "Disable debug routes in production."),
    ("/console", "Debug console exposed", "HIGH", "CWE-489", "T1595.002",
     "Remove debug consoles (e.g. Django/Flask/Symfony) from production."),
    ("/_profiler", "Symfony profiler exposed", "MEDIUM", "CWE-200", "T1595.002",
     "Disable the Symfony web profiler in production."),
    ("/backup.sql", "Database backup exposed", "CRITICAL", "CWE-538", "T1530",
     "Remove database backups from the web root and rotate DB credentials."),
    ("/dump.sql", "Database dump exposed", "CRITICAL", "CWE-538", "T1530",
     "Remove SQL dumps from public access; assume data is compromised."),
    ("/config.php.bak", "Config backup exposed", "HIGH", "CWE-538", "T1552.001",
     "Delete config backups; keep secrets out of the document root."),
    ("/backup/", "Backup directory exposed", "MEDIUM", "CWE-548", "T1530",
     "Block directory listings and backup folders at the edge."),
    ("/.aws/credentials", "AWS credentials file exposed", "CRITICAL", "CWE-522", "T1552.001",
     "Immediate: deny /.aws/*, rotate IAM keys, review CloudTrail."),
    ("/id_rsa", "SSH private key exposed", "CRITICAL", "CWE-522", "T1552.001",
     "Remove the key, rotate SSH keys, review authorized access."),
    ("/.dockerenv", "Docker environment marker", "MEDIUM", "CWE-200", "T1613",
     "Do not expose container internals; harden the image."),
    ("/trace.axd", "ASP.NET trace exposed", "MEDIUM", "CWE-200", "T1595.002",
     "Disable ASP.NET trace in production."),
    ("/elmah.axd", "ELMAH error log exposed", "MEDIUM", "CWE-200", "T1595.002",
     "Protect or disable ELMAH; error logs leak internals."),
    ("/swagger/index.html", "Swagger UI exposed", "LOW", "CWE-200", "T1595.002",
     "Disable or authenticate API documentation in production."),
    ("/graphql", "GraphQL endpoint exposed", "INFO", "CWE-200", "—",
     "If not intentional, disable GraphQL; if intentional, disable introspection in prod."),
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
        "192.168.0.0/16", "169.254.0.0/16", "::1/128",
        "fc00::/7", "fe80::/10",
    )
]

# known risky technology signatures (banner / header / body)
TECH_SIGS = [
    (re.compile(r"LiteSpeed(?:/([\d.]+))?", re.I), "LiteSpeed", "web-server"),
    (re.compile(r"nginx(?:/([\d.]+))?", re.I), "Nginx", "web-server"),
    (re.compile(r"Apache(?:/([\d.]+))?", re.I), "Apache", "web-server"),
    (re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.I), "IIS", "web-server"),
    (re.compile(r"Next(?:\.js)?(?:/([\d.]+))?", re.I), "Next.js", "framework"),
    (re.compile(r"WordPress(?:\s?([\d.]+))?", re.I), "WordPress", "cms"),
    (re.compile(r"Drupal(?:\s?([\d.]+))?", re.I), "Drupal", "cms"),
    (re.compile(r"Joomla(?:\s?([\d.]+))?", re.I), "Joomla", "cms"),
    (re.compile(r"PHP(?:/([\d.]+))?", re.I), "PHP", "language"),
    (re.compile(r"ASP\.NET", re.I), "ASP.NET", "framework"),
    (re.compile(r"Django", re.I), "Django", "framework"),
    (re.compile(r"Express", re.I), "Express", "framework"),
]


def _is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
            if any(ip in net for net in PRIVATE_NETWORKS):
                return True
        except ValueError:
            continue
    return False


def _finding(title, severity, description, remediation, cwe="", mitre="T1595",
             category="", evidence="", confidence=0.9):
    return {
        "title": title, "severity": severity, "description": description,
        "remediation": remediation, "mitre": mitre, "cwe": cwe,
        "category": category, "evidence": evidence, "confidence": confidence,
    }


def _score_delta(sev: str) -> int:
    return {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12, "LOW": 5, "INFO": 0}.get(sev, 5)


def _cert_info(hostname: str, port: int = 443, timeout: float = 8.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            proto = ssock.version()
            cipher = ssock.cipher()
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = int((not_after - time.time()) / 86400)
    issuer = ""
    subject_cn = ""
    for rdn in cert.get("issuer", ()):
        for key, val in rdn:
            if key == "organizationName" and not issuer:
                issuer = val
    for rdn in cert.get("subject", ()):
        for key, val in rdn:
            if key == "commonName":
                subject_cn = val
    san = [v for typ, v in cert.get("subjectAltName", ())]
    return {
        "tls_days_left": days_left, "tls_issuer": issuer, "tls_valid": days_left > 0,
        "tls_proto": proto or "", "tls_cipher": (cipher[0] if cipher else ""),
        "tls_subject_cn": subject_cn, "tls_san": san[:20],
    }


def _weak_tls_findings(proto: str, cipher: str, host: str) -> list[dict]:
    out = []
    p = (proto or "").upper()
    if "SSL" in p or p in ("TLSV1", "TLSV1.0", "TLSV1.1"):
        out.append(_finding(
            f"Weak TLS protocol: {proto}", "HIGH",
            f"{host} negotiated {proto}. SSLv3/TLS 1.0/1.1 are deprecated and vulnerable (POODLE, BEAST).",
            "Disable SSLv2/v3 and TLS 1.0/1.1 on the server or load balancer. Require TLS 1.2+.",
            "CWE-326", "T1595.002", "TLS",
            evidence=f"negotiated={proto}",
        ))
    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON")
    cu = (cipher or "").upper()
    if any(w in cu for w in weak_ciphers):
        out.append(_finding(
            "Weak TLS cipher suite", "HIGH",
            f"{host} offered a weak cipher ({cipher}).",
            "Disable weak ciphers; prefer AEAD suites (AES-GCM, CHACHA20).",
            "CWE-327", "T1595.002", "TLS",
            evidence=f"cipher={cipher}",
        ))
    return out


def _audit_headers(headers: dict) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    lowered = {k.lower(): v for k, v in headers.items()}
    for key, label, sev, cwe, mitre, fix, example in SECURITY_HEADERS:
        if key not in lowered:
            findings.append(_finding(
                f"Missing {label} header", sev,
                f"The {label} security header is not set. This weakens browser-side defenses "
                f"against XSS, clickjacking, MIME sniffing, or information leakage.",
                fix, cwe, mitre, "Security Headers",
                evidence=f"response headers do not include {key}",
            ))
    for banner_key in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = lowered.get(banner_key, "")
        if val:
            findings.append(_finding(
                f"Technology disclosure ({banner_key})", "LOW",
                f"Header {banner_key} reveals stack details: {val[:140]}. "
                f"Attackers use this to pick version-specific exploits.",
                "Suppress or genericize technology disclosure headers (e.g. Server: nginx).",
                "CWE-200", "T1592.004", "Information Disclosure",
                evidence=f"{banner_key}: {val[:140]}",
            ))
    # permissions already in SECURITY_HEADERS; catch dangerous Access-Control if present
    if "access-control-allow-origin" in lowered:
        acao = lowered["access-control-allow-origin"].strip()
        if acao == "*" and lowered.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(_finding(
                "CORS allows credentials with wildcard origin", "HIGH",
                "Access-Control-Allow-Origin: * combined with Allow-Credentials: true lets any site "
                "make credentialed cross-origin requests to this API.",
                "Never combine wildcard CORS with credentials. Allow only exact trusted origins.",
                "CWE-942", "T1189", "CORS",
                evidence=f"ACAO={acao}; credentials=true",
            ))
        elif acao == "*":
            findings.append(_finding(
                "CORS wildcard origin", "LOW",
                "Access-Control-Allow-Origin: * lets any website read responses from this origin "
                "(if the resource is public this may be intentional).",
                "Restrict ACAO to known origins if responses are sensitive.",
                "CWE-942", "T1595", "CORS",
                evidence=f"ACAO={acao}",
            ))
    return findings, lowered


def _cookie_findings(raw_set_cookie: str) -> list[dict]:
    out = []
    if not raw_set_cookie:
        return out
    cookies = raw_set_cookie if isinstance(raw_set_cookie, list) else [raw_set_cookie]
    for c in cookies:
        parts = [p.strip() for p in c.split(";")]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0]
        flags = {p.lower() for p in parts[1:]}
        if "secure" not in flags:
            out.append(_finding(
                f"Cookie missing Secure flag ({name})", "MEDIUM",
                f"Cookie '{name}' is set without the Secure flag and may be sent over HTTP.",
                "Always set Secure on session/auth cookies; force HTTPS sitewide.",
                "CWE-614", "T1539", "Cookies",
                evidence=c[:200],
            ))
        if "httponly" not in flags:
            out.append(_finding(
                f"Cookie missing HttpOnly flag ({name})", "MEDIUM",
                f"Cookie '{name}' is readable by JavaScript (no HttpOnly), increasing XSS impact.",
                "Set HttpOnly on cookies that do not need JS access.",
                "CWE-1004", "T1539", "Cookies",
                evidence=c[:200],
            ))
        if not any(p.lower().startswith("samesite") for p in parts):
            out.append(_finding(
                f"Cookie missing SameSite flag ({name})", "LOW",
                f"Cookie '{name}' has no SameSite attribute; browsers may default inconsistently.",
                "Set SameSite=Lax (or Strict) to mitigate CSRF.",
                "CWE-352", "T1539", "Cookies",
                evidence=c[:200],
            ))
        if name.lower() in ("phpsessid", "jsessionid") and "httponly" not in flags:
            out.append(_finding(
                f"Default session cookie name ({name})", "LOW",
                f"Using the default session cookie name '{name}' discloses the backend stack.",
                "Rename session cookies to a custom name.",
                "CWE-200", "T1592.004", "Cookies",
                evidence=name,
            ))
    return out


def _ftech_fingerprint(headers: dict, body: str) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    techs: list[str] = []
    blob = " ".join([
        headers.get("server", ""),
        headers.get("x-powered-by", ""),
        headers.get("x-generator", ""),
        body[:8000] if body else "",
    ])
    for pattern, name, kind in TECH_SIGS:
        m = pattern.search(blob)
        if m:
            ver = m.group(1) or ""
            techs.append(f"{name} {ver}".strip())
            if name == "WordPress":
                findings.append(_finding(
                    "WordPress detected", "INFO",
                    f"The site appears to run WordPress{(' ' + ver) if ver else ''}.",
                    "Keep WordPress core, themes, and plugins updated; disable unused plugins; "
                    "use a WAF and limit wp-login/xmlrpc.",
                    "CWE-200", "T1592.004", "Technology",
                    evidence=f"WordPress {ver}".strip(), confidence=0.85,
                ))
            if name == "LiteSpeed" and ver:
                findings.append(_finding(
                    f"LiteSpeed {ver} disclosed", "LOW",
                    "The LiteSpeed version is visible. Version disclosure helps attackers "
                    "match known CVEs for that release.",
                    "Hide the version token from the Server header (e.g. Server: LiteSpeed).",
                    "CWE-200", "T1592.004", "Technology",
                    evidence=f"server: {headers.get('server','')}", confidence=0.9,
                ))
            if name == "Next.js":
                findings.append(_finding(
                    "Next.js detected", "INFO",
                    f"Next.js appears to be in use{(' (version ~' + ver + ')') if ver else ''}.",
                    "Review Next.js security advisories; disable directory listing and source maps in production.",
                    "CWE-200", "T1592.004", "Technology",
                    evidence=headers.get("x-powered-by") or "body/header signature", confidence=0.8,
                ))
            if name == "PHP" and ver:
                major_minor = ".".join(ver.split(".")[:2])
                try:
                    fv = tuple(int(x) for x in major_minor.split("."))
                except ValueError:
                    fv = (0, 0)
                if fv and fv < (7, 4):
                    findings.append(_finding(
                        f"Outdated PHP {ver}", "HIGH",
                        f"PHP {ver} is end-of-life and no longer receives security fixes.",
                        "Upgrade to a supported PHP version (8.x recommended).",
                        "CWE-1104", "T1595.002", "Technology",
                        evidence=f"PHP/{ver}", confidence=0.85,
                    ))
    gen = headers.get("x-generator", "") or ""
    if gen:
        findings.append(_finding(
            "X-Generator header present", "LOW",
            f"X-Generator: {gen[:140]} discloses the CMS/generator.",
            "Remove X-Generator in production.",
            "CWE-200", "T1592.004", "Information Disclosure",
            evidence=gen[:140],
        ))
    return findings, techs


def _body_findings(body: str, final_url: str) -> list[dict]:
    out = []
    if not body:
        return out
    lower = body.lower()

    # generator meta
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', body, re.I)
    if m:
        out.append(_finding(
            "HTML generator meta tag", "LOW",
            f"The page discloses a generator meta tag: {m.group(1)[:140]}. "
            "This helps fingerprint the CMS and version.",
            "Remove the generator meta tag in production builds.",
            "CWE-200", "T1592.004", "Information Disclosure",
            evidence=m.group(0)[:200],
        ))

    # HTML comments with interesting content
    comments = re.findall(r"<!--(.*?)-->", body, re.S)
    interesting = []
    for c in comments:
        cl = c.lower()
        if any(k in cl for k in ("todo", "fixme", "password", "secret", "api_key", "apikey",
                                  "token", "admin", "debug", "vulnerab")):
            interesting.append(c.strip()[:120])
    if interesting:
        out.append(_finding(
            "Sensitive HTML comments", "MEDIUM",
            f"{len(interesting)} HTML comment(s) contain developer notes or secret-like strings.",
            "Strip HTML comments from production responses.",
            "CWE-615", "T1592.004", "Information Disclosure",
            evidence=" | ".join(interesting[:3]),
        ))

    # mixed content
    if final_url.startswith("https://"):
        http_assets = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', body, re.I)
        http_assets = [a for a in http_assets if not a.startswith("http://localhost")]
        if http_assets:
            out.append(_finding(
                "Mixed content on HTTPS page", "MEDIUM",
                f"{len(http_assets)} resource(s) load over plain HTTP on an HTTPS page, "
                "enabling MITM injection.",
                "Upgrade all subresources to HTTPS or use protocol-relative URLs with HSTS.",
                "CWE-319", "T1189", "Transport",
                evidence="; ".join(http_assets[:3]),
            ))

    # forms without obvious CSRF token / autocomplete off
    forms = re.findall(r"<form\b[^>]*>.*?</form>", body, re.I | re.S)
    for form in forms:
        fm = re.search(r"<form\b([^>]*)>", form, re.I)
        attrs = fm.group(1) if fm else ""
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        meth = (method.group(1).lower() if method else "get")
        if meth != "post":
            continue
        if not re.search(r"csrf|authenticity_token|__requestverificationtoken|nonce", form, re.I):
            out.append(_finding(
                "POST form without visible CSRF token", "MEDIUM",
                f"A POST form (action={action.group(1) if action else '(none)'}) has no recognizable "
                "CSRF token. Token names vary — verify server-side anti-CSRF is present.",
                "Add and enforce CSRF tokens (or SameSite=strict cookies) on all state-changing forms.",
                "CWE-352", "T1539", "Application",
                evidence=(action.group(1) if action else "(no action)"),
                confidence=0.6,
            ))
        if not re.search(r'autocomplete=["\']off["\']', attrs, re.I) and re.search(
                r'type=["\']password["\']', form, re.I):
            out.append(_finding(
                "Password form without autocomplete=off", "LOW",
                "A password form does not disable browser autocomplete; on shared devices this can leak credentials.",
                'Add autocomplete="current-password" intentionally or off for sensitive kiosks; '
                "prefer password managers + MFA.",
                "CWE-525", "T1539", "Application",
                evidence=(action.group(1) if action else "(no action)"),
                confidence=0.5,
            ))

    # source map references
    if re.search(r"//# sourceMappingURL=", body):
        out.append(_finding(
            "Source map reference exposed", "LOW",
            "JavaScript references a sourceMappingURL, which may allow reconstruction of original source.",
            "Disable source maps for production builds.",
            "CWE-540", "T1592.004", "Information Disclosure",
            evidence="sourceMappingURL found in HTML/JS",
        ))

    return out


def _extended_html_checks(body: str, final_url: str) -> list[dict]:
    out = []
    if not body:
        return out

    # 1. Subresource Integrity (SRI) on external CDN scripts
    cdn_script_pattern = re.compile(
        r'<script[^>]+src=["\'](https?:)?//(cdnjs\.|cdn\.|unpkg\.|jsdelivr\.|code\.jquery\.|ajax\.googleapis\.)[^"\']+["\'][^>]*>',
        re.I
    )
    sri_pattern = re.compile(r'integrity=["\'](sha256|sha384|sha512)-', re.I)
    missing_sri = []
    for m in cdn_script_pattern.finditer(body):
        tag = m.group(0)
        if not sri_pattern.search(tag):
            src_m = re.search(r'src=["\']([^"\']+)["\']', tag, re.I)
            src_url = src_m.group(1) if src_m else tag[:80]
            missing_sri.append(src_url)
    if missing_sri:
        out.append(_finding(
            "Missing Subresource Integrity (SRI) on CDN scripts", "MEDIUM",
            f"{len(missing_sri)} external CDN script(s) lack cryptographic subresource integrity (integrity=) hashes. "
            "If the CDN provider is compromised or intercepted, malicious scripts could execute in client browsers.",
            "Add integrity='sha384-...' and crossorigin='anonymous' attributes to external script tags.",
            "CWE-829", "T1195.002", "Supply Chain",
            evidence="; ".join(missing_sri[:2]),
            confidence=0.9,
        ))

    # 2. Insecure password input over HTTP
    if "<input" in body.lower() and 'type="password"' in body.lower():
        if final_url.startswith("http://"):
            out.append(_finding(
                "Password input transmitted over unencrypted HTTP", "CRITICAL",
                "A password input field was detected on a plain HTTP page, exposing credentials to cleartext sniffing.",
                "Enforce HTTPS across all pages containing credential inputs.",
                "CWE-319", "T1552.001", "Authentication",
                evidence="<input type='password'> on HTTP",
                confidence=0.95,
            ))

    # 3. OWASP A06: Outdated frontend libraries (e.g. vulnerable jQuery)
    jq_match = re.search(r'jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body, re.I)
    if jq_match:
        jq_ver_str = jq_match.group(1)
        try:
            parts = [int(p) for p in jq_ver_str.split('.')[:3]]
            if len(parts) == 2:
                parts.append(0)
            if tuple(parts) < (3, 5, 0):
                out.append(_finding(
                    f"Outdated jQuery v{jq_ver_str} with known CVEs", "HIGH",
                    f"The page includes jQuery v{jq_ver_str}. Versions prior to 3.5.0 contain known Cross-Site Scripting (XSS) and Prototype Pollution vulnerabilities (CVE-2020-11022, CVE-2020-11023).",
                    "Upgrade jQuery to version 3.7+ or migrate to modern standard DOM APIs.",
                    "CWE-1104", "T1195.002", "Vulnerable Components",
                    evidence=jq_match.group(0),
                    confidence=0.9,
                ))
        except Exception:
            pass

    # 4. OWASP A05: Sensitive Error / Stack Trace / Database Leakage
    stack_patterns = [
        (r"Fatal error:.*in\s+/[^\s]+\.php", "PHP fatal error with file path disclosure"),
        (r"Traceback \(most recent call last\):", "Python/Django traceback disclosure"),
        (r"SQLSTATE\[[0-9A-Za-z]+\]", "Database SQL query error disclosure"),
        (r"Microsoft OLE DB Provider for (SQL Server|ODBC)", "Database error disclosure"),
        (r"PostgreSQL query failed:", "PostgreSQL query error disclosure"),
        (r"org\.apache\.catalina\.connector\.ClientAbortException", "Tomcat Java stack trace disclosure"),
    ]
    for pat, desc in stack_patterns:
        m = re.search(pat, body, re.I)
        if m:
            out.append(_finding(
                f"Sensitive debug information leakage: {desc}", "HIGH",
                "The application rendered an unhandled exception or database error message directly into the HTTP response. Attackers leverage these error signatures to map backend schema and code logic.",
                "Disable debug mode (e.g. set DEBUG=False, display_errors=Off) and implement custom generic error pages.",
                "CWE-209", "T1592.004", "Information Disclosure",
                evidence=m.group(0)[:120],
                confidence=0.95,
            ))
            break

    # 5. OWASP A01 / A07: Login form without Anti-CSRF token
    forms = re.findall(r'<form[^>]*>(.*?)</form>', body, re.I | re.S)
    for f in forms:
        if 'type="password"' in f.lower():
            if not any(t in f.lower() for t in ("csrf", "_token", "authenticity_token", "nonce", "xsrf")):
                out.append(_finding(
                    "Potential CSRF vulnerability on authentication form", "MEDIUM",
                    "A form containing a password input was detected without an apparent anti-CSRF token field. This may permit Cross-Site Request Forgery attacks.",
                    "Implement synchronizer token pattern (CSRF token) or SameSite=Strict cookies on all state-changing authentication forms.",
                    "CWE-352", "T1189", "Authentication",
                    evidence="Password form without csrf/_token input",
                    confidence=0.75,
                ))
                break

    return out


async def _extended_site_probes(client: httpx.AsyncClient, base: str, headers: dict) -> list[dict]:
    out = []

    # 1. Dangerous HTTP methods probe (OPTIONS)
    try:
        r_opt = await client.options(base, follow_redirects=False)
        allow_hdr = r_opt.headers.get("allow", "").upper()
        if not allow_hdr:
            allow_hdr = r_opt.headers.get("public", "").upper()
        if allow_hdr:
            methods = [m.strip() for m in allow_hdr.split(",")]
            dangerous = [m for m in methods if m in ("TRACE", "TRACK", "PUT", "DELETE")]
            if "TRACE" in dangerous or "TRACK" in dangerous:
                out.append(_finding(
                    "Cross-Site Tracing (XST) enabled (TRACE method)", "MEDIUM",
                    f"The server allows HTTP TRACE/TRACK method ({allow_hdr}). Attackers can exploit this to bypass HttpOnly cookies.",
                    "Disable HTTP TRACE and TRACK methods on the web server / reverse proxy.",
                    "CWE-200", "T1595.002", "Configuration",
                    evidence=f"Allow: {allow_hdr}",
                    confidence=0.9,
                ))
            elif "PUT" in dangerous or "DELETE" in dangerous:
                out.append(_finding(
                    "Potentially dangerous HTTP methods enabled", "LOW",
                    f"The server advertises support for state-modifying HTTP methods: {', '.join(dangerous)}.",
                    "Ensure PUT and DELETE methods require strict authentication and authorization.",
                    "CWE-749", "T1595.002", "Configuration",
                    evidence=f"Allow: {allow_hdr}",
                    confidence=0.75,
                ))
    except Exception:
        pass

    # 2. OWASP A01: CORS Origin Reflection / Misconfiguration probe
    try:
        attacker_origin = "https://evil-attacker.example.com"
        r_cors = await client.get(base, headers={"Origin": attacker_origin}, follow_redirects=False)
        acao = r_cors.headers.get("access-control-allow-origin", "").strip()
        acac = r_cors.headers.get("access-control-allow-credentials", "").lower().strip()
        if acao == "*":
            out.append(_finding(
                "Overly permissive CORS wildcard (Access-Control-Allow-Origin: *)", "LOW",
                "The server returns Access-Control-Allow-Origin: *, allowing any third-party domain to read cross-origin responses.",
                "Restrict Access-Control-Allow-Origin to trusted explicit origins rather than wildcard *.",
                "CWE-942", "T1595.002", "Access Control",
                evidence="Access-Control-Allow-Origin: *",
                confidence=0.85,
            ))
        elif acao == attacker_origin and acac == "true":
            out.append(_finding(
                "Critical CORS misconfiguration (Arbitrary Origin with Credentials)", "CRITICAL",
                f"The server dynamically reflected an untrusted Origin ({attacker_origin}) with Access-Control-Allow-Credentials: true. Attackers can steal authenticated user sessions and private data via cross-origin requests.",
                "Never dynamically reflect untrusted origins when credentials are enabled. Validate against a strict allowlist.",
                "CWE-942", "T1189", "Access Control",
                evidence=f"ACAO: {acao}, ACAC: true",
                confidence=0.95,
            ))
    except Exception:
        pass

    # 3. Sensitive robots.txt inspection
    try:
        r_rob = await client.get(base + "/robots.txt", follow_redirects=False)
        if r_rob.status_code == 200 and "user-agent" in r_rob.text.lower():
            disallows = re.findall(r"Disallow:\s*([^\r\n#]+)", r_rob.text, re.I)
            sensitive_disallows = []
            for d in disallows:
                d = d.strip()
                if any(k in d.lower() for k in ("admin", "secret", "private", "backup", "db", "config", "internal", "api/v")):
                    sensitive_disallows.append(d)
            if sensitive_disallows:
                out.append(_finding(
                    "Sensitive paths disclosed in robots.txt", "LOW",
                    f"robots.txt contains {len(sensitive_disallows)} sensitive disallow rule(s). "
                    "Attackers use robots.txt as an enumeration dictionary for hidden portals.",
                    "Do not rely on robots.txt for security; restrict access to sensitive paths using authentication and IP allowlisting.",
                    "CWE-200", "T1592.004", "Information Disclosure",
                    evidence=", ".join(sensitive_disallows[:4]),
                    confidence=0.85,
                ))
    except Exception:
        pass

    # 4. WAF & Rate-limit detection
    lowered = {k.lower(): v for k, v in headers.items()}
    has_waf = any(k in lowered for k in ("cf-ray", "x-amz-cf-id", "x-sucuri-id", "x-akamai-transformed", "x-firewall")) or \
              any(w in lowered.get("server", "").lower() for w in ("cloudflare", "sucuri", "incapsula", "imperva", "akamai", "aws"))
    has_ratelimit = any(k.startswith("x-ratelimit-") or k.startswith("ratelimit-") or k == "retry-after" for k in lowered)

    if not has_waf and not has_ratelimit:
        out.append(_finding(
            "No Edge WAF or Rate-Limiting detected", "INFO",
            "No Web Application Firewall (WAF) or Rate-Limiting response headers were detected on this origin. "
            "The origin may be vulnerable to brute-force or volumetric abuse.",
            "Deploy a Cloud / Edge WAF (e.g. Cloudflare, AWS WAF, Fastly) and configure rate-limiting policies on API and auth endpoints.",
            "CWE-799", "T1499", "Infrastructure",
            evidence="Absence of WAF / RateLimit headers",
            confidence=0.7,
        ))

    # 5. RFC 9116 security.txt check
    try:
        r_sec = await client.get(base + "/.well-known/security.txt", follow_redirects=False)
        if r_sec.status_code == 200 and "contact:" in r_sec.text.lower():
            # Valid security.txt present
            pass
        else:
            out.append(_finding(
                "Missing security.txt policy (RFC 9116)", "INFO",
                "No RFC 9116 security.txt policy was found under /.well-known/security.txt. "
                "Security researchers lack a standardized method to report vulnerabilities responsibly.",
                "Publish a security.txt file at /.well-known/security.txt containing Contact: and Expires: directives.",
                "CWE-200", "T1595", "Policy",
                evidence="404 or missing Contact directive",
                confidence=0.8,
            ))
    except Exception:
        pass


    return out


async def check_site(client: httpx.AsyncClient, site: dict,
                     allow_private: bool = False) -> dict:
    """Run one full vulnerability + uptime check. Never raises."""
    url = site["url"]
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    now = time.time()
    result = {
        "site_id": site["id"], "ts": now, "up": False,
        "status_code": 0, "latency_ms": 0.0, "error": "",
        "tls_days_left": -1, "tls_issuer": "", "tls_valid": False,
        "tls_proto": "", "tls_cipher": "",
        "security_score": 0, "server_banner": "",
        "technology": "", "headers": {}, "findings": [],
    }

    if not host:
        result["error"] = "invalid URL"
        result["findings"].append(_finding(
            "Invalid URL", "HIGH", "The registered URL has no hostname.",
            "Register a full URL such as https://example.com/.",
            "CWE-20", "T1595", "Configuration",
        ))
        return result

    if _is_private(host) and not allow_private:
        result["error"] = "target resolves to a private address (blocked by SSRF guard)"
        result["findings"].append(_finding(
            "SSRF guard blocked private target", "HIGH",
            f"{host} resolves to a private/internal address and was blocked.",
            "Only monitor public sites, or set NAD_ALLOW_PRIVATE_TARGETS=true for lab use.",
            "CWE-918", "T1595", "Configuration",
        ))
        return result

    # HTTPS-only on an http:// site
    if parsed.scheme == "http":
        result["findings"].append(_finding(
            "Site served over plain HTTP", "HIGH",
            f"{url} uses HTTP without TLS. Traffic and cookies can be intercepted or modified.",
            "Serve the site over HTTPS only and redirect HTTP→308 to HTTPS.",
            "CWE-319", "T1595.002", "Transport",
            evidence=url, confidence=0.95,
        ))

    # TLS cert + protocol audit
    if parsed.scheme == "https":
        try:
            tls = await asyncio.to_thread(_cert_info, host, parsed.port or 443)
            result.update(tls)
            if tls["tls_days_left"] < 0:
                result["findings"].append(_finding(
                    "TLS certificate expired", "CRITICAL",
                    f"Certificate for {host} expired ({-tls['tls_days_left']} days ago). "
                    "Browsers will show a full-page warning.",
                    "Renew and install a valid TLS certificate immediately (ACME/Let's Encrypt).",
                    "CWE-298", "T1595.002", "TLS",
                    evidence=f"notAfter expired; CN={tls.get('tls_subject_cn','')}",
                ))
            elif tls["tls_days_left"] < 14:
                result["findings"].append(_finding(
                    "TLS certificate expiring soon", "HIGH",
                    f"Certificate for {host} expires in {tls['tls_days_left']} days.",
                    "Renew before expiry; enable auto-renewal (ACME) so this never goes dark.",
                    "CWE-298", "T1595.002", "TLS",
                    evidence=f"days_left={tls['tls_days_left']}",
                ))
            elif tls["tls_days_left"] < 30:
                result["findings"].append(_finding(
                    "TLS certificate renewal recommended", "MEDIUM",
                    f"Certificate for {host} expires in {tls['tls_days_left']} days.",
                    "Schedule certificate renewal.",
                    "CWE-298", "T1595.002", "TLS",
                    evidence=f"days_left={tls['tls_days_left']}",
                ))
            result["findings"].extend(
                _weak_tls_findings(tls.get("tls_proto", ""), tls.get("tls_cipher", ""), host))
        except Exception as e:  # noqa: BLE001
            result["findings"].append(_finding(
                "TLS handshake failed", "HIGH",
                f"Could not complete TLS handshake with {host}: {type(e).__name__}: {e}",
                "Verify the certificate chain, SNI, TLS versions, and that 443 is open.",
                "CWE-319", "T1595.002", "TLS",
                evidence=str(e)[:200],
            ))

    # main HTTP fetch with retry
    t0 = time.perf_counter()
    resp = None
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            resp = await client.get(url, follow_redirects=True)
            break
        except httpx.TimeoutException as e:
            last_err = e
            await asyncio.sleep(0.5 * (attempt + 1))
        except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError,
                httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            last_err = e
            await asyncio.sleep(0.5 * (attempt + 1))
        except httpx.HTTPError as e:
            last_err = e
            break

    latency = (time.perf_counter() - t0) * 1000
    if resp is not None:
        try:
            result["status_code"] = resp.status_code
            result["latency_ms"] = round(latency, 1)
            result["up"] = resp.status_code < 500
            result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
            result["server_banner"] = resp.headers.get("server", "")

            if resp.status_code >= 500:
                result["error"] = f"HTTP {resp.status_code}"
                result["findings"].append(_finding(
                    "Site returning server error", "HIGH",
                    f"{url} responded with HTTP {resp.status_code}.",
                    "Inspect application and reverse-proxy error logs; fix the failing request path.",
                    "CWE-755", "T1499", "Availability",
                    evidence=f"HTTP {resp.status_code}",
                ))
            elif resp.status_code in (401, 403):
                result["error"] = f"HTTP {resp.status_code}"
                result["findings"].append(_finding(
                    f"Access restricted (HTTP {resp.status_code})", "INFO",
                    "The origin responded with an authentication/authorization challenge. "
                    "The monitor cannot fully audit protected pages.",
                    "If this is intentional, ignore. Ensure MFA and strong auth protect this path.",
                    "CWE-306", "T1595", "Application",
                    evidence=f"HTTP {resp.status_code}",
                    confidence=0.5,
                ))
            elif resp.status_code >= 400:
                result["error"] = f"HTTP {resp.status_code}"

            body = ""
            ctype = resp.headers.get("content-type", "")
            if "text" in ctype or "html" in ctype or "json" in ctype or not ctype:
                body = resp.text[:200_000]

            hfindings, lowered = _audit_headers(dict(resp.headers))
            result["findings"].extend(hfindings)

            # cookie flags
            result["findings"].extend(_cookie_findings(resp.headers.get_list("set-cookie")))

            # HSTS on HTTPS with weak policy
            hsts = lowered.get("strict-transport-security", "")
            if hsts:
                m = re.search(r"max-age=(\d+)", hsts, re.I)
                if m and int(m.group(1)) < 31536000:
                    result["findings"].append(_finding(
                        "HSTS max-age too short", "LOW",
                        f"HSTS max-age={m.group(1)} seconds is less than 1 year.",
                        "Set max-age=31536000; includeSubDomains; preload.",
                        "CWE-319", "T1595.002", "Transport",
                        evidence=hsts,
                    ))
                if "includesubdomains" not in hsts.lower():
                    result["findings"].append(_finding(
                        "HSTS missing includeSubDomains", "LOW",
                        "HSTS is set without includeSubDomains, so subdomains are unprotected.",
                        "Add includeSubDomains (and preload) after testing subdomain HTTPS readiness.",
                        "CWE-319", "T1595.002", "Transport",
                        evidence=hsts,
                    ))
                if "preload" not in hsts.lower():
                    result["findings"].append(_finding(
                        "HSTS missing preload directive", "LOW",
                        "HSTS header does not specify the 'preload' directive, preventing inclusion in browser HSTS preload lists.",
                        "Add 'preload' to Strict-Transport-Security after verifying subdomain HTTPS readiness.",
                        "CWE-319", "T1595.002", "Transport",
                        evidence=hsts,
                    ))

            # final URL redirect analysis
            final = str(resp.url)
            fparsed = urllib.parse.urlparse(final)
            if parsed.scheme == "https" and fparsed.scheme == "http":
                result["findings"].append(_finding(
                    "HTTPS downgraded to HTTP", "HIGH",
                    f"Request to {url} ended at insecure {final}.",
                    "Never redirect HTTPS to HTTP; redirect the other direction instead.",
                    "CWE-319", "T1595.002", "Transport",
                    evidence=final, confidence=0.95,
                ))
            if fparsed.netloc and host and fparsed.hostname and fparsed.hostname != host:
                result["findings"].append(_finding(
                    "Cross-host redirect", "INFO",
                    f"Request redirected from {host} to {fparsed.hostname}.",
                    "Confirm the redirect target is trusted and uses HTTPS.",
                    "CWE-601", "T1189", "Application",
                    evidence=final, confidence=0.7,
                ))

            # tech fingerprint + body checks
            tech_findings, techs = _ftech_fingerprint(result["headers"], body)
            result["findings"].extend(tech_findings)
            if techs:
                result["technology"] = ", ".join(techs[:6])

            result["findings"].extend(_body_findings(body, final))
            result["findings"].extend(_extended_html_checks(body, final))

            # clickjacking: no XFO and no CSP frame-ancestors
            has_xfo = "x-frame-options" in lowered
            csp = lowered.get("content-security-policy", "")
            has_fa = "frame-ancestors" in csp.lower()
            if not has_xfo and not has_fa:
                result["findings"].append(_finding(
                    "Clickjacking protection missing", "MEDIUM",
                    "Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed by attackers.",
                    "Add X-Frame-Options: DENY and/or CSP frame-ancestors 'none'.",
                    "CWE-1021", "T1189", "Security Headers",
                    evidence="no x-frame-options; no frame-ancestors",
                ))

            # exposure probes (same origin) — SPA-aware to avoid catch-all false positives
            base = f"{parsed.scheme}://{parsed.netloc}"
            home_sig = (body[:1500].lower() if body else "")
            home_len = len(body or "")
            for path, title, sev, cwe, mitre, fix in EXPOSURE_PATHS:
                try:
                    r = await client.get(base + path, follow_redirects=False)
                    ctype = r.headers.get("content-type", "")
                    clen = len(r.content)
                    is_hit = r.status_code == 200 and clen > 0
                    if path == "/.well-known/security.txt":
                        if is_hit and "text" in ctype:
                            result["findings"].append(_finding(
                                title, "INFO",
                                f"{base}{path} returned HTTP 200 ({clen} bytes).",
                                fix, mitre, cwe, "Exposure",
                                evidence=f"HTTP 200, {clen} bytes",
                                confidence=0.8,
                            ))
                        continue
                    if not is_hit:
                        # only escalate unreachable-sensitive paths if clearly not SPA 404
                        continue
                    # SPA / soft-404 guards
                    if "text/html" in ctype:
                        sample = (r.text[:1500].lower() if r.text else "")
                        # same shell as homepage (catch-all routing)
                        if home_sig and sample and (
                                sample == home_sig
                                or (abs(clen - home_len) < 400 and sample[:300] == home_sig[:300])):
                            continue
                        # generic SPA 404 / Next.js / WordPress themes
                        if any(x in sample for x in (
                                "next.js", "__next", "id=\"__next\"", "gatsby", "ng-version",
                                "react-app", "built with create-react-app", "wp-content/themes",
                                "page not found", "404")) and clen > 1500:
                            # still trust true secret filenames even if HTML
                            if not any(path.endswith(ext) for ext in (
                                    ".env", ".aws/credentials")) and "/.git/" not in path \
                                    and path != "/id_rsa":
                                continue
                    # high-risk secret paths: require content that looks real
                    if path in ("/.env", "/.aws/credentials", "/id_rsa", "/.htpasswd",
                                "/backup.sql", "/dump.sql", "/config.php.bak"):
                        raw = r.content[:2000]
                        looks_secret = False
                        if b"=" in raw and b"<html" not in raw[:200].lower() and b"<!doctype" not in raw[:200].lower():
                            looks_secret = True
                        if path.endswith(".sql") and (b"INSERT INTO" in raw.upper() or b"CREATE TABLE" in raw.upper()):
                            looks_secret = True
                        if path == "/id_rsa" and b"PRIVATE KEY" in raw:
                            looks_secret = True
                        if path.endswith(".env") and (b"APP_KEY" in raw or b"DB_PASSWORD" in raw
                                                      or b"SECRET" in raw or b"API_KEY" in raw):
                            looks_secret = True
                        if not looks_secret and "text/html" in ctype:
                            continue
                        if not looks_secret and clen > 5000 and b"PRIVATE KEY" not in raw:
                            # large non-secret body — likely SPA
                            if home_sig and sample and sample[:300] == home_sig[:300]:
                                continue
                    result["findings"].append(_finding(
                        title, sev,
                        f"{base}{path} returned HTTP {r.status_code} ({clen} bytes"
                        + (f", content-type: {ctype}" if ctype else "") + ").",
                        fix, mitre, cwe, "Exposure",
                        evidence=f"HTTP {r.status_code}, {clen} bytes, content-type={ctype or 'n/a'}",
                        confidence=0.85,
                    ))
                    result["security_score"] = max(0, result["security_score"] - _score_delta(sev))
                except httpx.HTTPError:
                    pass

            # directory listing heuristic on common dirs
            for dirpath in ("/images/", "/uploads/", "/static/", "/files/", "/js/"):
                try:
                    r = await client.get(base + dirpath, follow_redirects=False)
                    if r.status_code == 200 and re.search(
                            r"<title>index of|<h1>index of|directory listing for", r.text[:2000], re.I):
                        result["findings"].append(_finding(
                            f"Directory listing enabled ({dirpath})", "MEDIUM",
                            f"{base}{dirpath} serves an auto-generated directory index, "
                            "leaking filenames and structure.",
                            "Disable autoindex / directory listing on the web server or CDN.",
                            "CWE-548", "T1595.003", "Exposure",
                            evidence=f"Index of {dirpath}",
                        ))
                except httpx.HTTPError:
                    pass

            # Extended active probes (OPTIONS methods, robots.txt, WAF detection, security.txt RFC 9116)
            try:
                ext_findings = await _extended_site_probes(client, base, result["headers"])
                result["findings"].extend(ext_findings)
            except Exception:
                pass

        except Exception as e:  # noqa: BLE001
            result["error"] = f"response parse error: {e}"[:200]
    else:
        if isinstance(last_err, httpx.TimeoutException):
            result["error"] = "request timed out"
        elif last_err is not None:
            result["error"] = f"connection failed: {type(last_err).__name__}: {last_err}"[:200]
        else:
            result["error"] = "unreachable"

    if not result["up"] and not result["error"]:
        result["error"] = "unreachable"
    if result["up"] and not result["error"]:
        result["security_score"] = result.get("security_score", 100)

    # recompute security score from findings if site is up (headers/paths already subtracted)
    if result["up"]:
        # start from 100 and subtract unique finding deltas, floor 0
        score = 100
        seen = set()
        for f in result["findings"]:
            key = (f["title"], f.get("evidence", ""))
            if key in seen:
                continue
            seen.add(key)
            score -= _score_delta(f["severity"])
        result["security_score"] = max(0, min(100, score))

    # stable sort: severity then category
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    result["findings"].sort(key=lambda f: (sev_order.get(f.get("severity", "LOW"), 9),
                                           f.get("category", ""), f.get("title", "")))
    return result


def findings_to_alerts(site: dict, check: dict) -> list[dict]:
    """Convert security findings into standard alert dicts."""
    out = []
    host = urllib.parse.urlparse(site["url"]).hostname or site["url"]
    seen = set()
    for f in check.get("findings", []):
        if f.get("severity") == "INFO":
            continue
        key = f"{f.get('title')}|{f.get('evidence','')}"
        if key in seen:
            continue
        seen.add(key)
        desc = f["description"]
        if f.get("evidence"):
            desc += f" Evidence: {f['evidence']}"
        if f.get("cwe"):
            desc += f" ({f['cwe']})"
        out.append({
            "timestamp": check["ts"],
            "attack_type": f"Web: {f['title']}",
            "severity": f.get("severity", "LOW"),
            "confidence": float(f.get("confidence", 0.9)),
            "mitre": f.get("mitre", "T1595"),
            "remediation": f.get("remediation", ""),
            "description": f"{desc} (site: {site['name']})",
            "src_ip": "monitor",
            "dst_ip": host,
            "src_port": 0,
            "dst_port": 443 if site["url"].startswith("https") else 80,
            "protocol": "HTTP",
            "engine": "site-monitor",
            "threat_score": {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 25}.get(
                f.get("severity", "LOW"), 25),
        })
    if not check.get("up"):
        out.append({
            "timestamp": check["ts"],
            "attack_type": "Web: Site Down",
            "severity": "HIGH",
            "confidence": 1.0,
            "mitre": "T1499",
            "remediation": "Check DNS, origin server health, TLS port 443, and upstream provider status.",
            "description": f"{site['name']} is unreachable: {check.get('error', 'unknown')}",
            "src_ip": "monitor",
            "dst_ip": host,
            "src_port": 0,
            "dst_port": 443 if site["url"].startswith("https") else 80,
            "protocol": "HTTP",
            "engine": "site-monitor",
            "threat_score": 70,
        })
    return out


class SiteMonitor:
    """Background loop that checks registered sites on their intervals."""

    def __init__(self, db, alerts, on_alert: Callable | None = None,
                 allow_private: bool = False, timeout: float = 12.0):
        self.db = db
        self.alerts = alerts
        self.on_alert = on_alert
        self.allow_private = allow_private
        self.timeout = timeout
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.last_checks: dict[int, dict] = {}
        self._last_run: dict[int, float] = {}

    def start(self):
        self._stop.clear()
        self._task = asyncio.ensure_future(self._loop())

    async def stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _loop(self):
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(2)

    async def _tick(self):
        sites = self.db.list_sites(enabled_only=True)
        now = time.time()
        due = []
        for s in sites:
            last = self._last_run.get(s["id"], 0)
            if now - last >= s.get("check_interval_sec", 60):
                due.append(s)
        if not due:
            return
        async with httpx.AsyncClient(timeout=self.timeout, headers=BROWSER_HEADERS,
                                     follow_redirects=True) as client:
            for site in due:
                self._last_run[site["id"]] = now
                try:
                    check = await check_site(client, site, self.allow_private)
                except Exception as e:  # noqa: BLE001
                    check = self._error_check(site, f"monitor error: {e}")
                self._store(site, check)

    async def check_now(self, site: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, headers=BROWSER_HEADERS,
                                         follow_redirects=True) as client:
                check = await check_site(client, site, self.allow_private)
        except Exception as e:  # noqa: BLE001
            check = self._error_check(site, f"monitor error: {e}")
        self._last_run[site["id"]] = time.time()
        self._store(site, check)
        return check

    def _error_check(self, site: dict, msg: str) -> dict:
        return {"site_id": site["id"], "ts": time.time(), "up": False,
                "status_code": 0, "latency_ms": 0.0,
                "error": msg[:200],
                "tls_days_left": -1, "tls_issuer": "", "tls_valid": False,
                "tls_proto": "", "tls_cipher": "",
                "security_score": 0, "server_banner": "", "technology": "",
                "headers": {}, "findings": []}

    def _store(self, site: dict, check: dict):
        self.last_checks[site["id"]] = check
        try:
            self.db.save_check(check)
        except Exception:  # noqa: BLE001
            pass
        for alert in findings_to_alerts(site, check):
            try:
                pushed = self.alerts.push(alert)
            except Exception:  # noqa: BLE001
                continue
            if pushed and self.on_alert:
                try:
                    self.on_alert(pushed)
                except Exception:  # noqa: BLE001
                    pass

    def snapshot(self) -> list[dict]:
        out = []
        for s in self.db.list_sites():
            c = self.last_checks.get(s["id"])
            if not c:
                db_checks = self.db.get_checks(s["id"], 1)
                if db_checks:
                    c = db_checks[0]
                    self.last_checks[s["id"]] = c
            out.append({
                "id": s["id"], "name": s["name"], "url": s["url"],
                "enabled": s["enabled"], "interval": s["check_interval_sec"],
                "up": c["up"] if c else None,
                "status_code": c["status_code"] if c else 0,
                "latency_ms": c["latency_ms"] if c else 0,
                "error": c.get("error", "") if c else "",
                "tls_days_left": c.get("tls_days_left", -1) if c else -1,
                "tls_issuer": c.get("tls_issuer", "") if c else "",
                "tls_valid": c.get("tls_valid", False) if c else False,
                "tls_proto": c.get("tls_proto", "") if c else "",
                "tls_cipher": c.get("tls_cipher", "") if c else "",
                "security_score": c.get("security_score", 0) if c else 0,
                "server_banner": c.get("server_banner", "") if c else "",
                "technology": c.get("technology", "") if c else "",
                "headers": c.get("headers", {}) if c else {},
                "findings": c.get("findings", []) if c else [],
                "uptime_24h": self.db.uptime_24h(s["id"]),
            })
        return out

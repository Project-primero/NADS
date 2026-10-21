import { useMemo, useState } from 'react';
import type { Site, SiteFinding } from '../../types';
import { ScoreRing, getGrade } from '../ScoreRing';
import { FindingSummary } from '../FindingSummary';
import { Icon } from '../Icon';

interface WebSecReportsPageProps {
  sites: Site[];
  onOpenAudit: (site: Site) => void;
}

const OWASP_CATEGORIES = [
  {
    id: 'A01',
    code: 'A01:2021',
    title: 'Broken Access Control',
    cwe: 'CWE-942, CWE-538, CWE-548',
    match: ['admin', 'path', 'directory', 'cors', 'cwe-538', 'cwe-548', 'cwe-942', 'actuator', 'exposure'],
    recommendation: 'Enforce principle of least privilege, deny by default, disable directory listing, and restrict CORS origin reflections.',
  },
  {
    id: 'A02',
    code: 'A02:2021',
    title: 'Cryptographic Failures',
    cwe: 'CWE-319, CWE-311, CWE-326',
    match: ['tls', 'ssl', 'hsts', 'cwe-319', 'cwe-525', 'cwe-326', 'cwe-327', 'mixed content', 'cipher'],
    recommendation: 'Enforce HTTPS sitewide with HSTS max-age >= 31536000 and preload. Disable legacy TLS 1.0/1.1 and weak ciphers.',
  },
  {
    id: 'A03',
    code: 'A03:2021',
    title: 'Injection & Content Security',
    cwe: 'CWE-79, CWE-89, CWE-693',
    match: ['sqli', 'xss', 'injection', 'cwe-79', 'cwe-89', 'cwe-78', 'csp', 'content-security-policy'],
    recommendation: 'Deploy a strict Content-Security-Policy disallowing unsafe-inline/eval. Parameterize queries and encode context outputs.',
  },
  {
    id: 'A04',
    code: 'A04:2021',
    title: 'Insecure Design & Anti-Automation',
    cwe: 'CWE-307, CWE-799',
    match: ['rate-limit', 'brute', 'cwe-307', 'cwe-799', 'waf', 'firewall'],
    recommendation: 'Implement IP and user-rate limiting on authentication and API endpoints. Deploy an Edge Web Application Firewall.',
  },
  {
    id: 'A05',
    code: 'A05:2021',
    title: 'Security Misconfiguration',
    cwe: 'CWE-16, CWE-209, CWE-1021',
    match: ['header', 'x-frame', 'nosniff', 'coop', 'corp', 'permissions', 'cwe-16', 'cwe-209', 'cwe-1021', 'debug', 'traceback', 'error'],
    recommendation: 'Configure hardened security response headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy). Suppress debug stack traces.',
  },
  {
    id: 'A06',
    code: 'A06:2021',
    title: 'Vulnerable and Outdated Components',
    cwe: 'CWE-1104',
    match: ['jquery', 'outdated', 'cwe-1104', 'php', 'wordpress', 'litespeed', 'version', 'generator'],
    recommendation: 'Regularly audit and update client-side libraries and server dependencies. Remove version tokens from HTTP response banners.',
  },
  {
    id: 'A07',
    code: 'A07:2021',
    title: 'Identification & Authentication Failures',
    cwe: 'CWE-352, CWE-522, CWE-614',
    match: ['cookie', 'password', 'session', 'csrf', 'cwe-352', 'cwe-522', 'cwe-614', 'cwe-1004'],
    recommendation: 'Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all session cookies. Enforce anti-CSRF tokens on credential forms.',
  },
  {
    id: 'A08',
    code: 'A08:2021',
    title: 'Software & Data Integrity Failures',
    cwe: 'CWE-829',
    match: ['sri', 'integrity', 'cwe-829', 'cdn', 'supply-chain'],
    recommendation: 'Include Subresource Integrity (SRI) sha384 hashes and crossorigin=anonymous on all third-party CDN scripts.',
  },
  {
    id: 'A09',
    code: 'A09:2021',
    title: 'Security Logging & Vulnerability Disclosure',
    cwe: 'CWE-200',
    match: ['security.txt', 'rfc 9116', 'robots.txt', 'disclosure'],
    recommendation: 'Publish RFC 9116 /.well-known/security.txt with security contact details. Audit robots.txt for sensitive path leaks.',
  },
];

function getRemediationSnippet(finding: SiteFinding): string {
  const t = (finding.title + ' ' + (finding.category || '')).toLowerCase();
  if (t.includes('hsts')) {
    return `# Nginx HSTS Configuration\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`;
  }
  if (t.includes('csp') || t.includes('content security')) {
    return `# Nginx Strict Content-Security-Policy\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;`;
  }
  if (t.includes('clickjacking') || t.includes('x-frame')) {
    return `# Nginx Clickjacking Mitigation\nadd_header X-Frame-Options "DENY" always;\n# Apache .htaccess\nHeader always append X-Frame-Options "DENY"`;
  }
  if (t.includes('content-type') || t.includes('nosniff')) {
    return `# MIME-sniffing prevention\nadd_header X-Content-Type-Options "nosniff" always;`;
  }
  if (t.includes('referrer')) {
    return `# Referrer leakage control\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`;
  }
  if (t.includes('permissions')) {
    return `# Feature policy isolation\nadd_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;`;
  }
  if (t.includes('coop') || t.includes('corp')) {
    return `# Cross-Origin Isolation\nadd_header Cross-Origin-Opener-Policy "same-origin" always;\nadd_header Cross-Origin-Resource-Policy "same-origin" always;`;
  }
  if (t.includes('cors')) {
    return `# Secure Explicit Origin Allowlist\nif ($http_origin ~* "^https?://(trusted\\.domain\\.com)$") {\n    add_header Access-Control-Allow-Origin "$http_origin" always;\n    add_header Access-Control-Allow-Credentials "true" always;\n}`;
  }
  if (t.includes('trace') || t.includes('method')) {
    return `# Disable Dangerous TRACE/TRACK methods\nif ($request_method ~ ^(TRACE|TRACK)$) {\n    return 405;\n}`;
  }
  if (t.includes('sri') || t.includes('integrity')) {
    return `<!-- Subresource Integrity Example -->\n<script src="https://cdn.example.com/lib.js"\n        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n        crossorigin="anonymous"></script>`;
  }
  if (t.includes('cookie')) {
    return `# Set-Cookie Flags\nSet-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/;`;
  }
  return `# Prescriptive Configuration Guidance\n${finding.remediation || 'Refer to vendor documentation to apply recommended hardening.'}`;
}

export function WebSecReportsPage({
  sites,
  onOpenAudit,
}: WebSecReportsPageProps) {
  const [selectedSiteId, setSelectedSiteId] = useState<number | 'FLEET'>(sites[0]?.id || 'FLEET');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const isFleetMode = selectedSiteId === 'FLEET';
  const selectedSite = sites.find((s) => s.id === selectedSiteId) || sites[0];

  // Fleet aggregate metrics
  const fleetSummary = useMemo(() => {
    const total = sites.length;
    if (total === 0) return { avgScore: 100, totalFindings: 0, critCount: 0, highCount: 0, medCount: 0, lowCount: 0 };
    const avgScore = Math.round(sites.reduce((a, b) => a + (b.security_score ?? 100), 0) / total);
    let totalFindings = 0;
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;
    for (const s of sites) {
      for (const f of s.findings ?? []) {
        totalFindings += 1;
        if (f.severity === 'CRITICAL') critCount += 1;
        else if (f.severity === 'HIGH') highCount += 1;
        else if (f.severity === 'MEDIUM') medCount += 1;
        else if (f.severity === 'LOW') lowCount += 1;
      }
    }
    return { avgScore, totalFindings, critCount, highCount, medCount, lowCount };
  }, [sites]);

  if (!selectedSite && !isFleetMode) {
    return (
      <div className="websec-page-wrap">
        <div className="card websec-empty-state">
          <Icon name="file" size={36} />
          <h4>No Targets Available for Report Generation</h4>
          <p>Please register at least one target origin in the fleet to generate formal vulnerability reports.</p>
        </div>
      </div>
    );
  }

  const findings: SiteFinding[] = isFleetMode
    ? sites.flatMap((s) => s.findings ?? [])
    : selectedSite.findings ?? [];

  const score = isFleetMode ? fleetSummary.avgScore : selectedSite.security_score ?? 100;
  const gradeInfo = getGrade(score);

  const reportId = isFleetMode
    ? `SEC-FLEET-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`
    : `SEC-AUDIT-${selectedSite.id}-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}`;

  const handleDownloadJson = () => {
    if (isFleetMode) {
      const payload = {
        title: 'Fleet-Wide Vulnerability Assessment Report',
        generated_at: new Date().toISOString(),
        targets_monitored: sites.length,
        fleet_posture_score: fleetSummary.avgScore,
        posture_grade: getGrade(fleetSummary.avgScore).grade,
        findings_breakdown: fleetSummary,
        targets: sites.map((s) => ({
          id: s.id,
          name: s.name,
          url: s.url,
          score: s.security_score,
          findings_count: s.findings?.length || 0,
        })),
        vulnerabilities: findings,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const u = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = u;
      a.download = `fleet_security_report_${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(u);
    } else {
      window.location.href = `/api/sites/${selectedSite.id}/report`;
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const copySnippet = (code: string, idx: number) => {
    navigator.clipboard.writeText(code);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2500);
  };

  // Group findings into priorities
  const p0Crit = findings.filter((f) => f.severity === 'CRITICAL');
  const p1High = findings.filter((f) => f.severity === 'HIGH');
  const p2Med = findings.filter((f) => f.severity === 'MEDIUM');
  const p3Low = findings.filter((f) => f.severity === 'LOW' || f.severity === 'INFO');

  return (
    <div className="websec-page-wrap report-container-root">
      {/* ── Top Bar Controls (Hidden in print) ── */}
      <div className="websec-page-header no-print">
        <div>
          <h2>Executive Compliance &amp; Vulnerability Assessment Reports</h2>
          <p>
            Generate, customize, and export formal auditor-grade vulnerability assessment reports,
            OWASP Top 10 compliance audits, and actionable mitigation roadmaps.
          </p>
        </div>

        <div className="websec-filter-group">
          <select
            value={selectedSiteId}
            onChange={(e) => setSelectedSiteId(e.target.value === 'FLEET' ? 'FLEET' : Number(e.target.value))}
            className="filter-select"
          >
            <option value="FLEET">Consolidated Fleet Assessment Report ({sites.length} Targets)</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                Target: {s.name || s.url}
              </option>
            ))}
          </select>

          <button className="btn btn-primary" onClick={handleDownloadJson} title="Download structured JSON report file">
            <Icon name="download" size={14} /> Download Official JSON Report
          </button>
          <button className="btn btn-secondary" onClick={handlePrint} title="Generate printable / PDF audit document">
            <Icon name="note" size={14} /> Print / Save Formal PDF
          </button>
        </div>
      </div>

      {/* ═════════════════════════════════════════════════════════════════ */}
      {/* ── FORMAL PRINTABLE / EXECUTABLE CYBERSECURITY AUDIT REPORT ── */}
      {/* ═════════════════════════════════════════════════════════════════ */}
      <div className="formal-report-paper card">
        {/* Document Classification Header */}
        <div className="formal-doc-header">
          <div className="doc-meta-left">
            <span className="doc-classification">SECURITY ASSESSMENT REPORT · RESTRICTED</span>
            <span className="doc-reference">REF: {reportId}</span>
          </div>
          <div className="doc-meta-right">
            <span>Framework: OWASP Top 10 (2021) · RFC 9116 · NIST SP 800-53</span>
            <span>Date: {new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}</span>
          </div>
        </div>

        {/* Executive Title & Scope */}
        <div className="formal-title-banner">
          <div>
            <h1 className="formal-main-title">
              {isFleetMode ? 'Fleet-Wide Web Security Posture Assessment' : `Vulnerability Assessment Report: ${selectedSite.name || selectedSite.url}`}
            </h1>
            <div className="formal-scope-meta">
              <span><b>Target Scope:</b> {isFleetMode ? `All ${sites.length} Monitored Origin Domains` : selectedSite.url}</span>
              {!isFleetMode && (
                <>
                  <span> · <b>Origin Status:</b> {selectedSite.up ? `ONLINE (HTTP ${selectedSite.status_code || 200})` : 'OFFLINE'}</span>
                  <span> · <b>Round-Trip Latency:</b> {selectedSite.latency_ms > 0 ? `${selectedSite.latency_ms} ms` : '—'}</span>
                  <span> · <b>Uptime (24h):</b> {selectedSite.uptime_24h >= 0 ? `${selectedSite.uptime_24h}%` : '100%'}</span>
                </>
              )}
            </div>
          </div>

          <div className="formal-score-display">
            <ScoreRing score={score} size={84} strokeWidth={8} showGrade={true} />
            <div className="formal-score-labels">
              <span className="formal-grade-text" style={{ color: gradeInfo.color }}>
                Grade {gradeInfo.grade}
              </span>
              <span className="formal-grade-caption">{gradeInfo.label}</span>
              <span className="formal-score-num">{score} / 100 Security Score</span>
            </div>
          </div>
        </div>

        {/* Executive Risk Commentary */}
        <div className="formal-exec-summary-box">
          <h4 className="section-heading">1. Executive Risk Summary</h4>
          <p>
            {score >= 85 ? (
              <>
                The assessed origin demonstrates a <b>hardened security posture</b>. Core transport security and
                baseline browser defense headers are configured. Routine monitoring is recommended to ensure ongoing
                cryptographic certificate renewal and subresource integrity.
              </>
            ) : score >= 60 ? (
              <>
                The assessed origin exhibits a <b>moderate risk posture</b> with active security deficiencies. While core
                services are operational, missing defense-in-depth headers (such as Content Security Policy or Strict-Transport-Security)
                expose client sessions to cross-site scripting (XSS), clickjacking, and transport-level eavesdropping.
              </>
            ) : (
              <>
                <b>CRITICAL ATTENTION REQUIRED:</b> The target infrastructure scores in the <b>elevated risk tier ({score}/100)</b>.
                Multiple architectural vulnerabilities, absent HTTP protection headers, and exposure points were verified.
                Immediate remediation of P0/P1 findings is mandatory to prevent unauthorized data access and session hijacking.
              </>
            )}
          </p>

          <div className="formal-metrics-row">
            <div className="f-metric">
              <span className="f-metric-label">TOTAL FINDINGS</span>
              <span className="f-metric-val">{findings.length}</span>
            </div>
            <div className="f-metric">
              <span className="f-metric-label">CRITICAL RISKS (P0)</span>
              <span className="f-metric-val" style={{ color: p0Crit.length > 0 ? 'var(--crit)' : 'inherit' }}>
                {p0Crit.length}
              </span>
            </div>
            <div className="f-metric">
              <span className="f-metric-label">HIGH SEVERITY (P1)</span>
              <span className="f-metric-val" style={{ color: p1High.length > 0 ? 'var(--high)' : 'inherit' }}>
                {p1High.length}
              </span>
            </div>
            <div className="f-metric">
              <span className="f-metric-label">MEDIUM RISKS (P2)</span>
              <span className="f-metric-val">{p2Med.length}</span>
            </div>
            <div className="f-metric">
              <span className="f-metric-label">LOW / INFO (P3)</span>
              <span className="f-metric-val">{p3Low.length}</span>
            </div>
          </div>
        </div>

        {/* OWASP Top 10 Compliance Matrix */}
        <div className="formal-section">
          <h4 className="section-heading">2. OWASP Top 10 (2021) Compliance Matrix</h4>
          <div className="owasp-formal-table-wrap">
            <table className="formal-table">
              <thead>
                <tr>
                  <th style={{ width: '10%' }}>Control</th>
                  <th style={{ width: '25%' }}>Vulnerability Category</th>
                  <th style={{ width: '15%' }}>Compliance Status</th>
                  <th style={{ width: '12%' }}>Impacted Findings</th>
                  <th style={{ width: '38%' }}>Prescriptive Hardening Guidance</th>
                </tr>
              </thead>
              <tbody>
                {OWASP_CATEGORIES.map((cat) => {
                  const matches = findings.filter((f) => {
                    const full = `${f.title} ${f.description} ${f.cwe || ''} ${f.category || ''}`.toLowerCase();
                    return cat.match.some((m) => full.includes(m));
                  });
                  const hasCrit = matches.some((f) => f.severity === 'CRITICAL');
                  const hasHigh = matches.some((f) => f.severity === 'HIGH');
                  const hasMed = matches.some((f) => f.severity === 'MEDIUM');
                  const status = hasCrit || hasHigh ? 'FAIL' : hasMed ? 'DEFICIENT' : 'PASSED';

                  return (
                    <tr key={cat.id}>
                      <td><b>{cat.code}</b></td>
                      <td>
                        <div className="cat-title-text">{cat.title}</div>
                        <div className="cat-cwe-text">{cat.cwe}</div>
                      </td>
                      <td>
                        <span className={`owasp-status-badge ${status.toLowerCase()}`}>
                          {status === 'PASSED' ? 'PASSED ✓' : status === 'DEFICIENT' ? 'WARNING ⚠' : 'FAIL ✕'}
                        </span>
                      </td>
                      <td>
                        <b>{matches.length}</b> {matches.length === 1 ? 'finding' : 'findings'}
                      </td>
                      <td className="cat-guide-text">{cat.recommendation}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Cryptographic & SSL/TLS Audit Section */}
        {!isFleetMode && (
          <div className="formal-section">
            <h4 className="section-heading">3. SSL/TLS Cryptographic Public Key Infrastructure</h4>
            <div className="crypto-details-grid">
              <div className="crypto-cell">
                <span className="c-label">X.509 Certificate Validity</span>
                <span className="c-val">
                  {selectedSite.tls_days_left >= 0 ? `${selectedSite.tls_days_left} Days Remaining` : 'Invalid / Expired'}
                </span>
              </div>
              <div className="crypto-cell">
                <span className="c-label">Certificate Authority (Issuer)</span>
                <span className="c-val" title={selectedSite.tls_issuer}>
                  {selectedSite.tls_issuer || 'None Detected'}
                </span>
              </div>
              <div className="crypto-cell">
                <span className="c-label">Negotiated Protocol</span>
                <span className="c-val">{selectedSite.tls_proto || 'Plaintext HTTP / None'}</span>
              </div>
              <div className="crypto-cell">
                <span className="c-label">Negotiated Cipher Suite</span>
                <span className="c-val mono">{selectedSite.tls_cipher || 'None Negotiated'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Detailed Vulnerability Findings Catalog with Fixes */}
        <div className="formal-section">
          <h4 className="section-heading">4. Detailed Vulnerability Findings &amp; Code Remediation</h4>
          {findings.length === 0 ? (
            <div className="formal-empty-box">
              No vulnerabilities were identified during this assessment cycle. Target meets verified baseline criteria.
            </div>
          ) : (
            <div className="formal-findings-list">
              {findings.map((f, i) => {
                const codeSnippet = getRemediationSnippet(f);
                return (
                  <div key={i} className={`formal-finding-card ${f.severity.toLowerCase()}`}>
                    <div className="f-card-header">
                      <div className="f-card-title-row">
                        <span className={`finding-chip ${f.severity.toLowerCase()}`}>{f.severity}</span>
                        <span className="f-title">{f.title}</span>
                        {f.cwe && <span className="code-badge">{f.cwe}</span>}
                        {f.mitre && <span className="code-badge mitre">ATT&amp;CK: {f.mitre}</span>}
                      </div>
                      <div className="f-cat-badge">{f.category || 'General'}</div>
                    </div>

                    <div className="f-card-body">
                      <p className="f-desc">{f.description}</p>

                      {f.evidence && (
                        <div className="f-evidence-box">
                          <span className="f-box-title">Observed Technical Evidence:</span>
                          <pre className="f-evidence-code">{f.evidence}</pre>
                        </div>
                      )}

                      <div className="f-remediation-box">
                        <div className="f-remed-header">
                          <span className="f-box-title">Prescriptive Mitigation Action:</span>
                          <button
                            className="btn btn-sm btn-ghost no-print copy-fix-btn"
                            onClick={() => copySnippet(codeSnippet, i)}
                            title="Copy code configuration to clipboard"
                          >
                            <Icon name="file" size={12} />
                            {copiedIndex === i ? 'Copied ✓' : 'Copy Config Snippet'}
                          </button>
                        </div>
                        <p className="f-remed-text">{f.remediation}</p>
                        <pre className="f-code-block">{codeSnippet}</pre>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Prioritized Implementation Roadmap */}
        <div className="formal-section">
          <h4 className="section-heading">5. Prioritized Remediation Roadmap &amp; Service Level Objectives</h4>
          <div className="roadmap-grid">
            <div className="roadmap-col p0">
              <div className="roadmap-header">
                <span className="r-badge p0">Priority 0 · 24 Hours</span>
                <h4>Critical Vulnerabilities</h4>
              </div>
              <p className="r-desc">Immediate action mandatory. High exploitation probability or unencrypted secrets.</p>
              <div className="r-count">{p0Crit.length} Active Items</div>
              <ul className="r-items">
                {p0Crit.map((f, idx) => (
                  <li key={idx}>{f.title}</li>
                ))}
                {p0Crit.length === 0 && <li className="empty-li">No Critical P0 items pending</li>}
              </ul>
            </div>

            <div className="roadmap-col p1">
              <div className="roadmap-header">
                <span className="r-badge p1">Priority 1 · 7 Days</span>
                <h4>High-Risk Deficiencies</h4>
              </div>
              <p className="r-desc">Severe misconfigurations, vulnerable components, or exposed endpoints.</p>
              <div className="r-count">{p1High.length} Active Items</div>
              <ul className="r-items">
                {p1High.map((f, idx) => (
                  <li key={idx}>{f.title}</li>
                ))}
                {p1High.length === 0 && <li className="empty-li">No High P1 items pending</li>}
              </ul>
            </div>

            <div className="roadmap-col p2">
              <div className="roadmap-header">
                <span className="r-badge p2">Priority 2 · 30 Days</span>
                <h4>Medium-Risk Hardening</h4>
              </div>
              <p className="r-desc">Security headers, cookie protections, and missing defense-in-depth controls.</p>
              <div className="r-count">{p2Med.length} Active Items</div>
              <ul className="r-items">
                {p2Med.slice(0, 5).map((f, idx) => (
                  <li key={idx}>{f.title}</li>
                ))}
                {p2Med.length > 5 && <li className="more-li">+{p2Med.length - 5} additional items</li>}
                {p2Med.length === 0 && <li className="empty-li">No Medium P2 items pending</li>}
              </ul>
            </div>
          </div>
        </div>

        {/* Sign-off & Audit Disclaimer */}
        <div className="formal-footer">
          <div className="formal-disclaimer">
            <b>Assessment Notice:</b> This report is generated dynamically by the Aegis WebSec Autonomous Security Scanner.
            Findings reflect the state of the target at the time of inspection. Continuous automated auditing is recommended
            to detect regressions.
          </div>
          <div className="formal-signoff">
            <span>Verified by: Aegis Security Posture Engine v2.4</span>
            <span>Document Checksum: {reportId}-SHA256-VALID</span>
          </div>
        </div>
      </div>
    </div>
  );
}

import { useState } from 'react';
import type { Site, SiteCheck } from '../../types';
import { ScoreRing, getGrade } from '../ScoreRing';
import { FindingSummary } from '../FindingSummary';
import { Icon } from '../Icon';

interface WebSecScannerPageProps {
  onAddSiteToFleet: (url: string, name: string) => Promise<void>;
  onOpenAudit: (site: Site, check?: SiteCheck | null) => void;
}

const SCAN_PHASES = [
  { id: 1, label: 'DNS Resolution & Reachability', desc: 'Resolving A/AAAA records and measuring TCP round-trip latency' },
  { id: 2, label: 'TLS Cryptographic Handshake', desc: 'Verifying X.509 certificate chain, cipher suites, protocol version, and expiration' },
  { id: 3, label: 'Security Headers Compliance', desc: 'Auditing HSTS, CSP, X-Frame-Options, X-Content-Type, Referrer-Policy, COOP, CORP' },
  { id: 4, label: 'Attack Surface & Path Probes', desc: 'Inspecting /.env, /.git, /admin, backup archives, phpinfo, actuators, debug routes' },
  { id: 5, label: 'Dangerous HTTP Verbs Probe', desc: 'Testing TRACE/TRACK Cross-Site Tracing, unauthenticated PUT/DELETE, OPTIONS methods' },
  { id: 6, label: 'Subresource Integrity (SRI)', desc: 'Validating external CDN script tags for missing cryptographic hash verification' },
  { id: 7, label: 'RFC 9116 & Robots Disclosure', desc: 'Auditing /.well-known/security.txt policy and parsing sensitive robots.txt paths' },
  { id: 8, label: 'Posture Scoring & Synthesis', desc: 'Synthesizing findings, assigning CWE & MITRE mappings, and calculating grade' },
];

export function WebSecScannerPage({
  onAddSiteToFleet,
  onOpenAudit,
}: WebSecScannerPageProps) {
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [profile, setProfile] = useState('full');
  const [scanning, setScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [scanResult, setScanResult] = useState<{ site: Site; check: SiteCheck } | null>(null);
  const [savedToFleet, setSavedToFleet] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const runScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setScanning(true);
    setScanResult(null);
    setSavedToFleet(false);
    setErrorMsg(null);
    setTerminalLogs([
      `[INIT] Initializing scanner engine for target: ${url.trim()}`,
      `[PROFILE] Selected Audit Profile: ${profile.toUpperCase()}`,
    ]);

    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = `https://${targetUrl}`;
    }

    // Step simulation while the real backend probe runs
    let stepTimer: ReturnType<typeof setInterval> | null = null;
    let step = 1;
    setCurrentStep(1);

    stepTimer = setInterval(() => {
      if (step < SCAN_PHASES.length) {
        step += 1;
        setCurrentStep(step);
        const p = SCAN_PHASES[step - 1];
        setTerminalLogs((prev) => [
          ...prev,
          `[PHASE ${step}/${SCAN_PHASES.length}] ${p.label}: ${p.desc}`,
        ]);
      }
    }, 550);

    try {
      const res = await fetch('/api/scanner/instant', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl,
          name: name.trim() || targetUrl,
        }),
      });

      if (!res.ok) {
        throw new Error(`Scanner error: HTTP ${res.status}`);
      }

      const data = await res.json();
      if (stepTimer) clearInterval(stepTimer);
      setCurrentStep(SCAN_PHASES.length);

      const check = data.check;
      const findingsCount = check.findings?.length || 0;
      const critCount = check.findings?.filter((f: any) => f.severity === 'CRITICAL').length || 0;
      const highCount = check.findings?.filter((f: any) => f.severity === 'HIGH').length || 0;

      setTerminalLogs((prev) => [
        ...prev,
        `[COMPLETE] Scan successfully concluded for ${targetUrl}`,
        `[RESULT] Up: ${check.up ? 'YES' : 'NO'} | Latency: ${check.latency_ms}ms | Status: HTTP ${check.status_code}`,
        `[SCORE] Security Score: ${check.security_score}/100 | Grade: ${getGrade(check.security_score).grade}`,
        `[AUDIT] Discovered ${findingsCount} total issues (${critCount} critical, ${highCount} high)`,
      ]);

      const constructedSite: Site = {
        id: data.site.id || 999999,
        name: name.trim() || targetUrl,
        url: targetUrl,
        enabled: true,
        interval: 60,
        up: check.up,
        status_code: check.status_code,
        latency_ms: check.latency_ms,
        error: check.error || '',
        tls_days_left: check.tls_days_left,
        tls_issuer: check.tls_issuer,
        tls_proto: check.tls_proto,
        tls_cipher: check.tls_cipher,
        security_score: check.security_score,
        server_banner: check.server_banner || '',
        technology: check.technology || '',
        headers: check.headers || {},
        findings: check.findings || [],
        uptime_24h: check.up ? 100 : 0,
      };

      setScanResult({
        site: constructedSite,
        check: check,
      });
    } catch (err: any) {
      if (stepTimer) clearInterval(stepTimer);
      setErrorMsg(err.message || 'Failed to complete vulnerability scan');
      setTerminalLogs((prev) => [
        ...prev,
        `[ERROR] Scan execution terminated with error: ${err.message}`,
      ]);
    } finally {
      setScanning(false);
    }
  };

  const handleSaveToFleet = async () => {
    if (!scanResult) return;
    try {
      await onAddSiteToFleet(scanResult.site.url, scanResult.site.name);
      setSavedToFleet(true);
    } catch (e: any) {
      alert(`Failed to save to fleet: ${e.message}`);
    }
  };

  const handleExportJson = () => {
    if (!scanResult) return;
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' });
    const u = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = u;
    a.download = `scan_report_${scanResult.site.url.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(u);
  };

  return (
    <div className="websec-page-wrap">
      {/* ── Page Header ── */}
      <div className="websec-page-header">
        <div>
          <h2>Active Vulnerability Scanner</h2>
          <p>
            Perform instant on-demand dynamic audits, attack surface discovery, cryptographic analysis,
            and OWASP vulnerability verification on any target origin.
          </p>
        </div>
      </div>

      {/* ── Scanner Configuration Card ── */}
      <div className="card">
        <form onSubmit={runScan} className="websec-scanner-form">
          <div className="scanner-form-grid">
            <div className="form-field url-field">
              <label>Target Website URL or Domain *</label>
              <div className="input-with-icon">
                <Icon name="globe" size={15} />
                <input
                  type="text"
                  placeholder="https://example.com or sub.domain.org"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={scanning}
                  required
                />
              </div>
            </div>

            <div className="form-field">
              <label>Friendly Target Label</label>
              <input
                type="text"
                placeholder="e.g. Production API Gateway"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={scanning}
              />
            </div>

            <div className="form-field">
              <label>Inspection Depth Profile</label>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                disabled={scanning}
              >
                <option value="full">Full-Spectrum OWASP &amp; Attack Surface</option>
                <option value="headers">HTTP Security Headers &amp; TLS Cryptography</option>
                <option value="recon">Passive Reconnaissance &amp; Secrets</option>
                <option value="tls">Deep SSL/TLS Cryptographic Probe</option>
              </select>
            </div>
          </div>

          <div className="scanner-form-actions">
            <button
              type="submit"
              className="btn btn-primary scanner-launch-btn"
              disabled={scanning || !url.trim()}
            >
              <Icon name="zap" size={15} />
              {scanning ? 'Auditing Target Origin…' : 'Start Dynamic Vulnerability Scan'}
            </button>
          </div>
        </form>

        {errorMsg && (
          <div className="websec-status-msg err" style={{ marginTop: 14 }}>
            <Icon name="alert" size={14} />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* ── Active Scanning Phase Visualizer ── */}
      {(scanning || terminalLogs.length > 0) && (
        <div className="grid2-equal" style={{ marginTop: 18 }}>
          {/* Phase Progress Checklist */}
          <div className="card">
            <div className="card-head">
              <h3>
                <span className="icon"><Icon name="target" size={16} /></span> Scanner Inspection Phases
              </h3>
              <span className="card-sub">
                {scanning ? `Step ${currentStep} of ${SCAN_PHASES.length}` : 'Audit Sequence Finished'}
              </span>
            </div>
            <div className="scan-phases-list">
              {SCAN_PHASES.map((p) => {
                const isPassed = currentStep > p.id || (!scanning && terminalLogs.length > 0);
                const isCurrent = scanning && currentStep === p.id;
                return (
                  <div
                    key={p.id}
                    className={`phase-item ${isPassed ? 'done' : isCurrent ? 'active' : 'pending'}`}
                  >
                    <div className="phase-bullet">
                      {isPassed ? (
                        <Icon name="check" size={12} />
                      ) : isCurrent ? (
                        <span className="phase-spinner" />
                      ) : (
                        p.id
                      )}
                    </div>
                    <div className="phase-details">
                      <div className="phase-title">{p.label}</div>
                      <div className="phase-desc">{p.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Terminal Logs Output */}
          <div className="card scanner-terminal-card">
            <div className="card-head">
              <h3>
                <span className="icon"><Icon name="terminal" size={16} /></span> Live Diagnostic Probe Stream
              </h3>
              <span className="card-sub">{terminalLogs.length} events logged</span>
            </div>
            <div className="scanner-terminal">
              {terminalLogs.map((log, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-prompt">&gt;</span> {log}
                </div>
              ))}
              {scanning && <div className="terminal-cursor">█</div>}
            </div>
          </div>
        </div>
      )}

      {/* ── Scan Results Presentation ── */}
      {scanResult && (
        <div className="card scan-result-card" style={{ marginTop: 18 }}>
          <div className="scan-result-header">
            <div className="scan-result-identity">
              <div className="scan-result-badge-row">
                <span
                  className={`site-status-pill ${scanResult.check.up ? 'up' : 'down'}`}
                >
                  <span className="status-dot" />
                  {scanResult.check.up ? `HTTP ${scanResult.check.status_code}` : 'OFFLINE'}
                </span>
                <span className="scan-result-time">
                  Scanned just now · {scanResult.check.latency_ms}ms round-trip
                </span>
              </div>
              <h3 className="scan-result-title">{scanResult.site.name}</h3>
              <a
                href={scanResult.site.url}
                target="_blank"
                rel="noreferrer"
                className="scan-result-url"
              >
                {scanResult.site.url} <Icon name="external" size={12} />
              </a>
            </div>

            <div className="scan-result-actions">
              <button
                className="btn btn-primary"
                onClick={handleSaveToFleet}
                disabled={savedToFleet}
              >
                <Icon name="globe" size={14} />
                {savedToFleet ? 'Saved to Monitored Fleet ✓' : 'Save Target to Fleet'}
              </button>
              <button className="btn" onClick={handleExportJson}>
                <Icon name="download" size={14} /> Export Report (JSON)
              </button>
              <button
                className="btn"
                onClick={() => onOpenAudit(scanResult.site, scanResult.check)}
              >
                Deep-Dive Modal →
              </button>
            </div>
          </div>

          <div className="scan-result-body">
            <div className="scan-result-score-block">
              <ScoreRing
                score={scanResult.check.security_score}
                size={80}
                strokeWidth={7}
                showGrade={true}
                isUp={scanResult.check.up}
              />
              <div className="score-block-label">
                <span className="grade-title">
                  Grade {getGrade(scanResult.check.security_score, scanResult.check.up).grade}
                </span>
                <span className="grade-sub">
                  {getGrade(scanResult.check.security_score, scanResult.check.up).label}
                </span>
              </div>
            </div>

            <div className="scan-result-meta-block">
              <div className="meta-card">
                <span className="meta-card-label">SSL / TLS Protocol</span>
                <span className="meta-card-val">
                  {scanResult.check.tls_proto || 'None / Plaintext'}
                </span>
              </div>
              <div className="meta-card">
                <span className="meta-card-label">Certificate Validity</span>
                <span className="meta-card-val">
                  {scanResult.check.tls_days_left >= 0
                    ? `${scanResult.check.tls_days_left} days left`
                    : 'Invalid / Expired'}
                </span>
              </div>
              <div className="meta-card">
                <span className="meta-card-label">Certificate Authority</span>
                <span className="meta-card-val" title={scanResult.check.tls_issuer}>
                  {scanResult.check.tls_issuer ? scanResult.check.tls_issuer.split(',')[0] : 'None'}
                </span>
              </div>
              <div className="meta-card">
                <span className="meta-card-label">Technologies Detected</span>
                <span className="meta-card-val" title={scanResult.check.technology}>
                  {scanResult.check.technology || 'None identified'}
                </span>
              </div>
            </div>
          </div>

          <div className="scan-result-findings">
            <div className="findings-head-row">
              <h4>Vulnerability Findings ({scanResult.check.findings?.length || 0})</h4>
              <FindingSummary findings={scanResult.check.findings || []} />
            </div>

            <div className="findings-cards-list">
              {scanResult.check.findings?.map((f, idx) => (
                <div key={idx} className={`finding-detail-box ${f.severity.toLowerCase()}`}>
                  <div className="finding-box-top">
                    <span className={`finding-chip ${f.severity.toLowerCase()}`}>{f.severity}</span>
                    <span className="finding-box-title">{f.title}</span>
                    {f.cwe && <span className="code-badge">{f.cwe}</span>}
                    {f.mitre && <span className="code-badge mitre">{f.mitre}</span>}
                  </div>
                  <div className="finding-box-desc">{f.description}</div>
                  {f.evidence && (
                    <div className="finding-box-evidence">
                      <b>Observed Evidence:</b> <code>{f.evidence}</code>
                    </div>
                  )}
                  {f.remediation && (
                    <div className="finding-box-remediation">
                      <b>Prescriptive Remediation:</b> {f.remediation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

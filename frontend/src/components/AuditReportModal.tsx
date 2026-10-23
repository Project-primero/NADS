import { useEffect, useMemo, useState } from 'react';
import type { Site, SiteCheck, SiteFinding } from '../types';
import { ScoreRing, getGrade } from './ScoreRing';
import { Icon } from './Icon';

interface AuditReportModalProps {
  site: Site;
  latestCheck?: SiteCheck | null;
  onClose: () => void;
  onScanNow: (siteId: number) => Promise<void>;
  isScanning?: boolean;
}

const SEV_WEIGHT: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function AuditReportModal({
  site,
  latestCheck,
  onClose,
  onScanNow,
  isScanning = false,
}: AuditReportModalProps) {
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'headers' | 'tls' | 'tech'>('vulnerabilities');
  const [sevFilter, setSevFilter] = useState<string>('ALL');
  const [catFilter, setCatFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [checkData, setCheckData] = useState<SiteCheck | null>(latestCheck || null);
  const [loadingCheck, setLoadingCheck] = useState<boolean>(!latestCheck && site.id > 0);
  const [localScanning, setLocalScanning] = useState(false);

  // Fetch audit on mount or when site changes if not provided
  useEffect(() => {
    if (latestCheck) {
      setCheckData(latestCheck);
      return;
    }
    if (site.id > 0) {
      let cancelled = false;
      setLoadingCheck(true);
      fetch(`/api/sites/${site.id}/audit`)
        .then((r) => r.json())
        .then((data) => {
          if (!cancelled && data.audit) {
            setCheckData(data.audit);
          }
        })
        .catch(() => {})
        .finally(() => {
          if (!cancelled) setLoadingCheck(false);
        });
      return () => {
        cancelled = true;
      };
    }
  }, [site.id, latestCheck]);

  const handleReScan = async () => {
    setLocalScanning(true);
    try {
      if (site.id > 0) {
        await onScanNow(site.id);
        const res = await fetch(`/api/sites/${site.id}/audit`);
        const data = await res.json();
        if (data.audit) setCheckData(data.audit);
      } else {
        const res = await fetch('/api/scanner/instant', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: site.url, name: site.name }),
        });
        const data = await res.json();
        if (data.check) setCheckData(data.check);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLocalScanning(false);
    }
  };

  const currentCheck = checkData ?? latestCheck;
  const isUp = currentCheck != null ? currentCheck.up : site.up;
  const isPending = isUp === null || isUp === undefined;
  const isOffline = isUp === false;
  const rawScore = currentCheck?.security_score ?? site.security_score;
  const score = isPending ? 0 : isOffline ? 0 : Math.max(0, Math.min(100, rawScore ?? 0));
  const { grade, label: gradeLabel, color: gradeColor } = getGrade(score, isUp);
  const findings = currentCheck?.findings ?? site.findings ?? [];
  const headers = currentCheck?.headers ?? site.headers ?? {};
  const tlsDays = currentCheck?.tls_days_left ?? site.tls_days_left ?? -1;
  const tlsProto = currentCheck?.tls_proto ?? site.tls_proto ?? '';
  const tlsCipher = currentCheck?.tls_cipher ?? site.tls_cipher ?? '';
  const tlsIssuer = currentCheck?.tls_issuer ?? site.tls_issuer ?? '';
  const tech = currentCheck?.technology ?? site.technology ?? '';
  const banner = currentCheck?.server_banner ?? site.server_banner ?? '';
  const latency = currentCheck?.latency_ms ?? site.latency_ms ?? 0;

  // Close on Escape key
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [onClose]);

  // Extract unique categories
  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const f of findings) {
      if (f.category) set.add(f.category);
    }
    return Array.from(set).sort();
  }, [findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (sevFilter !== 'ALL' && f.severity?.toUpperCase() !== sevFilter) return false;
        if (catFilter !== 'ALL' && f.category !== catFilter) return false;
        if (search) {
          const q = search.toLowerCase();
          const matchTitle = f.title.toLowerCase().includes(q);
          const matchDesc = f.description.toLowerCase().includes(q);
          const matchCwe = (f.cwe ?? '').toLowerCase().includes(q);
          const matchMitre = (f.mitre ?? '').toLowerCase().includes(q);
          if (!matchTitle && !matchDesc && !matchCwe && !matchMitre) return false;
        }
        return true;
      })
      .sort((a, b) => {
        const diff = (SEV_WEIGHT[a.severity] ?? 9) - (SEV_WEIGHT[b.severity] ?? 9);
        if (diff !== 0) return diff;
        return a.title.localeCompare(b.title);
      });
  }, [findings, sevFilter, catFilter, search]);

  const toggleFinding = (idx: string) => {
    setExpandedFindings((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const expandAll = () => {
    const next: Record<string, boolean> = {};
    filteredFindings.forEach((_, i) => {
      next[`${i}`] = true;
    });
    setExpandedFindings(next);
  };

  const collapseAll = () => {
    setExpandedFindings({});
  };

  const downloadReportJson = () => {
    window.location.href = `/api/sites/${site.id}/report`;
  };

  return (
    <div className="audit-modal-backdrop" onClick={onClose}>
      <div
        className="audit-modal-container"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Top Bar */}
        <div className="audit-modal-topbar">
          <div className="audit-modal-title-area">
            <span className="audit-modal-badge">Vulnerability Assessment Report</span>
            <h2 className="audit-modal-title">{site.name || site.url}</h2>
            <a
              href={site.url}
              target="_blank"
              rel="noopener noreferrer"
              className="audit-modal-link"
            >
              {site.url} <Icon name="link" size={13} />
            </a>
          </div>

          <div className="audit-modal-actions">
            <button
              className="btn btn-secondary"
              onClick={handleReScan}
              disabled={isScanning || localScanning}
              title="Execute full vulnerability probe right now"
            >
              <Icon name="zap" size={14} />
              {isScanning || localScanning ? 'Probing…' : 'Re-Scan Origin'}
            </button>
            <button
              className="btn btn-primary"
              onClick={downloadReportJson}
              title="Download formal JSON security audit report"
            >
              <Icon name="note" size={14} /> Export Report
            </button>
            <button
              className="audit-modal-close"
              onClick={onClose}
              title="Close audit view (Esc)"
              aria-label="Close"
            >
              <Icon name="close" size={18} />
            </button>
          </div>
        </div>

        {/* Executive Summary Card */}
        <div className="audit-exec-card">
          <div className="audit-exec-score">
            <ScoreRing score={score} size={82} strokeWidth={8} showGrade={false} isUp={isUp} />
            <div className="audit-exec-grade-info">
              <span className="audit-grade-letter" style={{ color: gradeColor }}>
                Grade {grade}
              </span>
              <span className="audit-grade-label">{gradeLabel} Security Posture</span>
              {loadingCheck && (
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                  Refreshing live telemetry…
                </span>
              )}
            </div>
          </div>

          <div className="audit-exec-metrics">
            <div className="audit-exec-metric">
              <span className="audit-metric-label">Status</span>
              <span
                className="audit-metric-value"
                style={{ color: isPending ? 'var(--muted)' : isUp ? 'var(--low)' : 'var(--crit)' }}
              >
                {isPending ? 'Pending Audit' : isUp ? `ONLINE ${currentCheck?.status_code || site.status_code || 200}` : 'OFFLINE'}
              </span>
            </div>
            <div className="audit-exec-metric">
              <span className="audit-metric-label">Ping Latency</span>
              <span className="audit-metric-value">
                {latency > 0 ? `${latency} ms` : '—'}
              </span>
            </div>
            <div className="audit-exec-metric">
              <span className="audit-metric-label">24h Uptime</span>
              <span
                className="audit-metric-value"
                style={{
                  color: (site.uptime_24h != null && site.uptime_24h >= 99) ? 'var(--low)' : (site.uptime_24h != null && site.uptime_24h >= 95) ? 'var(--med)' : 'var(--crit)',
                }}
              >
                {(site.uptime_24h == null || site.uptime_24h < 0) ? '—' : `${site.uptime_24h}%`}
              </span>
            </div>
            <div className="audit-exec-metric">
              <span className="audit-metric-label">SSL/TLS Expiry</span>
              <span
                className="audit-metric-value"
                style={{
                  color: tlsDays > 30 ? 'var(--low)' : tlsDays > 14 ? 'var(--med)' : 'var(--crit)',
                }}
              >
                {tlsDays < 0 ? (isOffline ? 'Unreachable' : 'Invalid/None') : `${tlsDays} days left`}
              </span>
            </div>
            <div className="audit-exec-metric">
              <span className="audit-metric-label">Total Findings</span>
              <span className="audit-metric-value">{findings.length} items</span>
            </div>
          </div>
        </div>

        {/* Modal Navigation Tabs */}
        <div className="audit-tabs">
          <button
            className={`audit-tab-btn ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
            onClick={() => setActiveTab('vulnerabilities')}
          >
            <Icon name="shield" size={15} /> Vulnerability Findings ({findings.length})
          </button>
          <button
            className={`audit-tab-btn ${activeTab === 'headers' ? 'active' : ''}`}
            onClick={() => setActiveTab('headers')}
          >
            <Icon name="radio" size={15} /> Security Headers
          </button>
          <button
            className={`audit-tab-btn ${activeTab === 'tls' ? 'active' : ''}`}
            onClick={() => setActiveTab('tls')}
          >
            <Icon name="link" size={15} /> TLS & Cryptography
          </button>
          <button
            className={`audit-tab-btn ${activeTab === 'tech' ? 'active' : ''}`}
            onClick={() => setActiveTab('tech')}
          >
            <Icon name="target" size={15} /> Attack Surface & Tech
          </button>
        </div>

        {/* Tab Body */}
        <div className="audit-tab-content">
          {/* TAB 1: VULNERABILITIES */}
          {activeTab === 'vulnerabilities' && (
            <div className="audit-vuln-panel">
              {/* Filter and Search Bar */}
              <div className="audit-filter-bar">
                <div className="audit-search-wrap">
                  <Icon name="search" size={14} />
                  <input
                    type="text"
                    placeholder="Search findings by title, CWE, or remediation..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="audit-search-input"
                  />
                  {search && (
                    <button
                      className="audit-search-clear"
                      onClick={() => setSearch('')}
                    >
                      ×
                    </button>
                  )}
                </div>

                <div className="audit-filter-selects">
                  <select
                    value={sevFilter}
                    onChange={(e) => setSevFilter(e.target.value)}
                    className="audit-select"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="INFO">Info</option>
                  </select>

                  {categories.length > 0 && (
                    <select
                      value={catFilter}
                      onChange={(e) => setCatFilter(e.target.value)}
                      className="audit-select"
                    >
                      <option value="ALL">All Categories</option>
                      {categories.map((c) => (
                        <option key={c} value={c}>
                          {c}
                        </option>
                      ))}
                    </select>
                  )}

                  <div className="audit-expand-controls">
                    <button className="text-btn" onClick={expandAll}>
                      Expand all
                    </button>
                    <span>·</span>
                    <button className="text-btn" onClick={collapseAll}>
                      Collapse all
                    </button>
                  </div>
                </div>
              </div>

              {/* Findings List */}
              {filteredFindings.length === 0 ? (
                <div className="audit-empty-findings">
                  <Icon name="check" size={32} />
                  <h4>No Vulnerabilities Found</h4>
                  <p>
                    {findings.length === 0
                      ? 'The target passed all security checks cleanly with no identified misconfigurations.'
                      : 'No findings match the current filter selection.'}
                  </p>
                </div>
              ) : (
                <div className="audit-findings-list">
                  {filteredFindings.map((f, i) => {
                    const key = `${i}`;
                    const isOpen = expandedFindings[key] ?? ((SEV_WEIGHT[f.severity] ?? 9) <= 1);

                    return (
                      <div
                        key={`${f.title}-${i}`}
                        className={`audit-finding-card sev-border-${f.severity}`}
                      >
                        <div
                          className="audit-finding-header"
                          onClick={() => toggleFinding(key)}
                        >
                          <div className="audit-finding-title-wrap">
                            <span className={`sev ${f.severity}`}>{f.severity}</span>
                            <span className="audit-finding-title">{f.title}</span>
                            {f.category && (
                              <span className="audit-category-tag">{f.category}</span>
                            )}
                          </div>

                          <div className="audit-finding-meta-tags">
                            {f.cwe && <span className="meta-chip">{f.cwe}</span>}
                            {f.mitre && f.mitre !== '—' && (
                              <span className="meta-chip mitre">{f.mitre}</span>
                            )}
                            <span className={`finding-chevron ${isOpen ? 'open' : ''}`}>
                              ▾
                            </span>
                          </div>
                        </div>

                        {isOpen && (
                          <div className="audit-finding-body">
                            <p className="audit-finding-desc">{f.description}</p>

                            {f.evidence && (
                              <div className="audit-finding-section">
                                <span className="audit-section-label">Evidence / Observation</span>
                                <pre className="audit-evidence-block">
                                  <code>{f.evidence}</code>
                                </pre>
                              </div>
                            )}

                            {f.remediation && (
                              <div className="audit-finding-section">
                                <span className="audit-section-label">Prescriptive Remediation</span>
                                <div className="audit-remediation-box">
                                  <span className="remediation-icon">🛠</span>
                                  <p>{f.remediation}</p>
                                </div>
                              </div>
                            )}

                            <div className="audit-finding-footer">
                              {f.confidence != null && (
                                <span className="audit-confidence">
                                  Confidence: {Math.round(f.confidence * 100)}%
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 2: SECURITY HEADERS */}
          {activeTab === 'headers' && (
            <div className="audit-headers-panel">
              <div className="audit-headers-grid">
                {[
                  {
                    name: 'Strict-Transport-Security (HSTS)',
                    key: 'strict-transport-security',
                    purpose: 'Enforces HTTPS encryptionsitewide and prevents SSL stripping.',
                  },
                  {
                    name: 'Content-Security-Policy (CSP)',
                    key: 'content-security-policy',
                    purpose: 'Restricts script sources and mitigates XSS and data exfiltration.',
                  },
                  {
                    name: 'X-Frame-Options',
                    key: 'x-frame-options',
                    purpose: 'Protects users against Clickjacking and UI redressing attacks.',
                  },
                  {
                    name: 'X-Content-Type-Options',
                    key: 'x-content-type-options',
                    purpose: 'Prevents MIME type sniffing (must be "nosniff").',
                  },
                  {
                    name: 'Referrer-Policy',
                    key: 'referrer-policy',
                    purpose: 'Controls leakage of sensitive URLs to external destinations.',
                  },
                  {
                    name: 'Permissions-Policy',
                    key: 'permissions-policy',
                    purpose: 'Restricts browser hardware features (camera, mic, geolocation).',
                  },
                  {
                    name: 'Cross-Origin-Opener-Policy (COOP)',
                    key: 'cross-origin-opener-policy',
                    purpose: 'Isolates the window browsing context against Spectre and side-channels.',
                  },
                  {
                    name: 'Cross-Origin-Resource-Policy (CORP)',
                    key: 'cross-origin-resource-policy',
                    purpose: 'Prevents untrusted domains from loading this resource via no-cors.',
                  },
                ].map((hdr) => {
                  const val = headers[hdr.key];
                  const isPresent = Boolean(val);
                  return (
                    <div
                      key={hdr.key}
                      className={`audit-header-item ${isPresent ? 'present' : 'missing'}`}
                    >
                      <div className="audit-header-top">
                        <span className="audit-header-name">{hdr.name}</span>
                        <span className={`status-badge ${isPresent ? 'pass' : 'fail'}`}>
                          {isPresent ? 'CONFORMS' : 'ABSENT'}
                        </span>
                      </div>
                      <p className="audit-header-purpose">{hdr.purpose}</p>
                      <div className="audit-header-val">
                        <code>{val || 'Header not returned by target server'}</code>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Raw Headers Accordion */}
              <div className="audit-raw-headers-wrap">
                <h4>All Received HTTP Response Headers ({Object.keys(headers).length})</h4>
                <div className="audit-raw-headers">
                  {Object.entries(headers).map(([k, v]) => (
                    <div key={k} className="raw-header-row">
                      <span className="raw-header-key">{k}:</span>
                      <span className="raw-header-val">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: TLS & CRYPTOGRAPHY */}
          {activeTab === 'tls' && (
            <div className="audit-tls-panel">
              <div className="audit-tls-cards">
                <div className="audit-info-card">
                  <h4>Cryptographic Handshake</h4>
                  <div className="info-grid">
                    <div className="info-row">
                      <span className="info-lbl">Negotiated Protocol</span>
                      <span className="info-val highlight">{tlsProto || 'None / Plain HTTP'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Cipher Suite</span>
                      <span className="info-val">{tlsCipher || 'None'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Port Audited</span>
                      <span className="info-val">443 (HTTPS)</span>
                    </div>
                  </div>
                </div>

                <div className="audit-info-card">
                  <h4>Certificate Authority & Validity</h4>
                  <div className="info-grid">
                    <div className="info-row">
                      <span className="info-lbl">Certificate Issuer</span>
                      <span className="info-val">{tlsIssuer || 'Unknown / Self-signed'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Days Remaining</span>
                      <span
                        className="info-val highlight"
                        style={{
                          color: tlsDays > 30 ? 'var(--low)' : tlsDays > 0 ? 'var(--med)' : 'var(--crit)',
                        }}
                      >
                        {tlsDays >= 0 ? `${tlsDays} days` : 'Expired or Inactive'}
                      </span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Certificate Status</span>
                      <span className="info-val">
                        {tlsDays > 0 ? 'Valid & Trusted' : 'Invalid / Requires Renewal'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: ATTACK SURFACE & TECH */}
          {activeTab === 'tech' && (
            <div className="audit-tech-panel">
              <div className="audit-tech-cards">
                <div className="audit-info-card">
                  <h4>Identified Stack & Fingerprints</h4>
                  <div className="info-grid">
                    <div className="info-row">
                      <span className="info-lbl">Server Banner</span>
                      <span className="info-val highlight">{banner || 'Hidden / Suppressed'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Frameworks & Technologies</span>
                      <span className="info-val">{tech || 'No prominent signatures detected'}</span>
                    </div>
                    <div className="info-row">
                      <span className="info-lbl">Scan Engine</span>
                      <span className="info-val">Dynamic Vulnerability Probe</span>
                    </div>
                  </div>
                </div>

                <div className="audit-info-card">
                  <h4>Monitored Probes Catalog</h4>
                  <p className="audit-probe-desc">
                    The scanner automatically executes safe unauthenticated exposure probes against:
                  </p>
                  <div className="audit-probe-pills">
                    {[
                      'Environment secrets (/.env)',
                      'Git repository metadata (/.git)',
                      'SSH private keys (/id_rsa)',
                      'Database dumps (/dump.sql)',
                      'AWS credentials (/.aws)',
                      'WordPress XML-RPC & Admin',
                      'Spring Boot Actuators',
                      'PHPMyAdmin & Adminer',
                      'Directory Indexing',
                      'Open Redirect query params',
                      'Subresource Integrity (SRI)',
                      'RFC 9116 security.txt',
                      'Robots.txt leakage',
                      'Dangerous HTTP methods (OPTIONS/TRACE)',
                    ].map((p) => (
                      <span key={p} className="audit-probe-pill">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

import { useMemo } from 'react';
import type { Site, SiteSummaryKpis } from '../../types';
import { ScoreRing, getGrade } from '../ScoreRing';
import { Icon } from '../Icon';

interface WebSecOverviewPageProps {
  sites: Site[];
  onNavigate: (tab: string) => void;
  onOpenAudit: (site: Site) => void;
  onScanNow: (siteId: number) => Promise<void>;
  onAddSite: () => void;
}

export function WebSecOverviewPage({
  sites,
  onNavigate,
  onOpenAudit,
  onScanNow,
  onAddSite,
}: WebSecOverviewPageProps) {
  // Aggregate KPI Calculations
  const kpis: SiteSummaryKpis = useMemo(() => {
    const total = sites.length;
    if (total === 0) {
      return {
        total_sites: 0,
        avg_security_score: 100,
        up_count: 0,
        down_count: 0,
        critical_high_count: 0,
        tls_expiring_count: 0,
        avg_uptime_24h: 100,
      };
    }
    const activeSites = sites.filter((s) => s.up !== null && s.up !== undefined);
    const scores = activeSites.map((s) => (s.up === false ? 0 : (s.security_score ?? 0)));
    const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    const upCount = sites.filter((s) => s.up === true).length;
    const downCount = sites.filter((s) => s.up === false).length;
    const tlsExp = sites.filter((s) => (s.tls_days_left ?? -1) >= 0 && (s.tls_days_left ?? -1) < 30).length;

    let critHigh = 0;
    for (const s of sites) {
      for (const f of s.findings ?? []) {
        if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
          critHigh += 1;
        }
      }
    }

    const validUptimes = sites.filter((s) => s.uptime_24h >= 0).map((s) => s.uptime_24h);
    const avgUptime = validUptimes.length
      ? Math.round((validUptimes.reduce((a, b) => a + b, 0) / validUptimes.length) * 10) / 10
      : 100;

    return {
      total_sites: total,
      avg_security_score: avgScore,
      up_count: upCount,
      down_count: downCount,
      critical_high_count: critHigh,
      tls_expiring_count: tlsExp,
      avg_uptime_24h: avgUptime,
    };
  }, [sites]);

  // Vulnerability Distribution by Severity
  const sevCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const s of sites) {
      for (const f of s.findings ?? []) {
        const sev = f.severity?.toUpperCase() as keyof typeof counts;
        if (counts[sev] !== undefined) {
          counts[sev] += 1;
        }
      }
    }
    return counts;
  }, [sites]);

  const totalFindings =
    sevCounts.CRITICAL + sevCounts.HIGH + sevCounts.MEDIUM + sevCounts.LOW + sevCounts.INFO;

  // Grade Distribution across fleet
  const gradeDistribution = useMemo(() => {
    const dist = { 'A+': 0, A: 0, B: 0, C: 0, D: 0, F: 0 };
    for (const s of sites) {
      const g = getGrade(s.security_score ?? 100).grade as keyof typeof dist;
      if (dist[g] !== undefined) dist[g] += 1;
    }
    return dist;
  }, [sites]);

  // Critical / High findings list
  const urgentFindings = useMemo(() => {
    const list: Array<{ site: Site; finding: any }> = [];
    for (const s of sites) {
      for (const f of s.findings ?? []) {
        if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
          list.push({ site: s, finding: f });
        }
      }
    }
    return list.slice(0, 6);
  }, [sites]);

  const avgGrade = getGrade(kpis.avg_security_score);

  return (
    <div className="websec-page-wrap">
      {/* ── 1. Top Action Hero Bar ── */}
      <div className="websec-hero-banner card">
        <div className="websec-hero-content">
          <div className="websec-hero-badge">
            <span className="dot" /> CONTINUOUS SECURITY MONITORING ACTIVE
          </div>
          <h2>Website Security Monitoring &amp; Vulnerability Assessment Platform</h2>
          <p>
            Real-world dynamic attack surface probing, SSL/TLS cryptography auditing, OWASP Top 10
            vulnerability assessment, and continuous health telemetry.
          </p>
        </div>
        <div className="websec-hero-actions">
          <button className="btn btn-primary" onClick={onAddSite}>
            <Icon name="globe" size={15} /> + Add Target Domain
          </button>
          <button className="btn" onClick={() => onNavigate('scanner')}>
            <Icon name="zap" size={15} /> Launch Live Scanner
          </button>
        </div>
      </div>

      {/* ── 2. Executive Posture KPI Banner ── */}
      <div className="websec-posture-banner">
        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Monitored Targets</span>
            <Icon name="globe" size={16} />
          </div>
          <div className="posture-value">{kpis.total_sites}</div>
          <div className="posture-sub">
            <span style={{ color: 'var(--low)', fontWeight: 600 }}>{kpis.up_count} UP</span>
            {kpis.down_count > 0 && (
              <span style={{ color: 'var(--crit)', fontWeight: 600, marginLeft: 6 }}>
                · {kpis.down_count} DOWN
              </span>
            )}
          </div>
        </div>

        <div className="posture-card score-highlight">
          <div className="posture-card-top">
            <span className="posture-label">Fleet Posture Score</span>
            <span className="score-grade-pill" style={{ background: avgGrade.color }}>
              {avgGrade.grade}
            </span>
          </div>
          <div className="posture-value-row">
            <div className="posture-value">{kpis.avg_security_score}</div>
            <span className="posture-scale">/ 100</span>
          </div>
          <div className="posture-sub">{avgGrade.label}</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Critical &amp; High Risks</span>
            <Icon name="alert" size={16} />
          </div>
          <div
            className="posture-value"
            style={{ color: kpis.critical_high_count > 0 ? 'var(--crit)' : 'var(--text)' }}
          >
            {kpis.critical_high_count}
          </div>
          <div className="posture-sub">{totalFindings} total identified issues</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">TLS Expiry Warning</span>
            <Icon name="lock" size={16} />
          </div>
          <div
            className="posture-value"
            style={{ color: kpis.tls_expiring_count > 0 ? 'var(--high)' : 'var(--text)' }}
          >
            {kpis.tls_expiring_count}
          </div>
          <div className="posture-sub">Certificates expiring in &lt; 30d</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">24h Average Uptime</span>
            <Icon name="zap" size={16} />
          </div>
          <div className="posture-value">{kpis.avg_uptime_24h}%</div>
          <div className="posture-sub">Telemetry availability</div>
        </div>
      </div>

      {/* ── 3. Posture Breakdown Grid ── */}
      <div className="grid2-equal" style={{ marginTop: 18 }}>
        {/* Vulnerability Severity Distribution */}
        <div className="card">
          <div className="card-head">
            <h3>
              <span className="icon"><Icon name="bug" size={16} /></span> Vulnerability Severity Distribution
            </h3>
            <span className="card-sub">{totalFindings} total findings</span>
          </div>
          <div className="websec-dist-bars">
            <div className="dist-row">
              <span className="dist-name critical">Critical Risk</span>
              <div className="dist-bar-track">
                <div
                  className="dist-bar-fill critical"
                  style={{ width: `${totalFindings ? (sevCounts.CRITICAL / totalFindings) * 100 : 0}%` }}
                />
              </div>
              <span className="dist-count">{sevCounts.CRITICAL}</span>
            </div>
            <div className="dist-row">
              <span className="dist-name high">High Severity</span>
              <div className="dist-bar-track">
                <div
                  className="dist-bar-fill high"
                  style={{ width: `${totalFindings ? (sevCounts.HIGH / totalFindings) * 100 : 0}%` }}
                />
              </div>
              <span className="dist-count">{sevCounts.HIGH}</span>
            </div>
            <div className="dist-row">
              <span className="dist-name medium">Medium Risk</span>
              <div className="dist-bar-track">
                <div
                  className="dist-bar-fill medium"
                  style={{ width: `${totalFindings ? (sevCounts.MEDIUM / totalFindings) * 100 : 0}%` }}
                />
              </div>
              <span className="dist-count">{sevCounts.MEDIUM}</span>
            </div>
            <div className="dist-row">
              <span className="dist-name low">Low Severity</span>
              <div className="dist-bar-track">
                <div
                  className="dist-bar-fill low"
                  style={{ width: `${totalFindings ? (sevCounts.LOW / totalFindings) * 100 : 0}%` }}
                />
              </div>
              <span className="dist-count">{sevCounts.LOW}</span>
            </div>
            <div className="dist-row">
              <span className="dist-name info">Informational</span>
              <div className="dist-bar-track">
                <div
                  className="dist-bar-fill info"
                  style={{ width: `${totalFindings ? (sevCounts.INFO / totalFindings) * 100 : 0}%` }}
                />
              </div>
              <span className="dist-count">{sevCounts.INFO}</span>
            </div>
          </div>
          <div style={{ marginTop: 16, textAlign: 'right' }}>
            <button className="btn btn-sm" onClick={() => onNavigate('vulnerabilities')}>
              Explore All Vulnerabilities →
            </button>
          </div>
        </div>

        {/* Security Grade Distribution */}
        <div className="card">
          <div className="card-head">
            <h3>
              <span className="icon"><Icon name="shield" size={16} /></span> Target Grade Distribution
            </h3>
            <span className="card-sub">{sites.length} monitored origins</span>
          </div>
          <div className="websec-grade-grid">
            {Object.entries(gradeDistribution).map(([grade, count]) => {
              const info = getGrade(
                grade === 'A+' ? 98 : grade === 'A' ? 88 : grade === 'B' ? 75 : grade === 'C' ? 55 : grade === 'D' ? 40 : 20
              );
              return (
                <div key={grade} className="websec-grade-box" style={{ borderColor: count > 0 ? info.color : 'var(--border)' }}>
                  <div className="grade-box-letter" style={{ color: info.color }}>
                    {grade}
                  </div>
                  <div className="grade-box-count">{count}</div>
                  <div className="grade-box-label">{info.label}</div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 16, textAlign: 'right' }}>
            <button className="btn btn-sm" onClick={() => onNavigate('targets')}>
              View Monitored Fleet →
            </button>
          </div>
        </div>
      </div>

      {/* ── 4. Urgent Action Findings Table ── */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-head">
          <h3>
            <span className="icon"><Icon name="alert" size={16} /></span> Priority Security Findings
          </h3>
          <span className="card-sub">Top issues requiring immediate remediation</span>
        </div>
        {urgentFindings.length === 0 ? (
          <div className="websec-empty-state" style={{ padding: '24px 0' }}>
            <Icon name="check" size={32} />
            <p style={{ margin: '8px 0 0 0', fontWeight: 600 }}>No Critical or High Vulnerabilities Detected!</p>
            <span style={{ fontSize: '0.85rem', color: 'var(--muted)' }}>
              All monitored targets currently satisfy baseline security posture standards.
            </span>
          </div>
        ) : (
          <div className="websec-urgent-table">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Vulnerability Finding</th>
                  <th>Target Origin</th>
                  <th>CWE / MITRE</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {urgentFindings.map(({ site, finding }, idx) => (
                  <tr key={`${site.id}-${finding.title}-${idx}`}>
                    <td>
                      <span className={`finding-chip ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      <div className="urgent-title">{finding.title}</div>
                      <div className="urgent-desc">{finding.description}</div>
                    </td>
                    <td>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noreferrer"
                        className="site-table-link"
                      >
                        {site.name || site.url}
                      </a>
                    </td>
                    <td>
                      <div className="urgent-codes">
                        {finding.cwe && <span className="code-badge">{finding.cwe}</span>}
                        {finding.mitre && <span className="code-badge mitre">{finding.mitre}</span>}
                      </div>
                    </td>
                    <td>
                      <button
                        className="btn btn-sm"
                        onClick={() => onOpenAudit(site)}
                        title="View complete audit & remediation instructions"
                      >
                        View Audit →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

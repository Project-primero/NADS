import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Site, SiteCheck, SiteSummaryKpis } from '../types';
import { ScoreRing, getGrade } from './ScoreRing';
import { SecurityTrend } from './SecurityTrend';
import { FindingSummary } from './FindingSummary';
import { AuditReportModal } from './AuditReportModal';
import { Icon } from './Icon';

interface WebsiteMonitorProps {
  sites: Site[];
}

function UptimeBar({ checks }: { checks: SiteCheck[] }) {
  const ticks = checks.slice(0, 48).reverse();
  if (!ticks.length) {
    return <div className="uptime-bar empty" title="Uptime ticks will accumulate over scans" />;
  }
  return (
    <div className="uptime-bar">
      {ticks.map((c) => (
        <span
          key={c.id}
          className={`tick ${c.up ? 'up' : 'down'}`}
          title={`${new Date(c.ts * 1000).toLocaleTimeString()} — ${
            c.up ? `UP (${c.latency_ms}ms, HTTP ${c.status_code})` : c.error || 'DOWN'
          }`}
        />
      ))}
    </div>
  );
}

function SiteCard({
  site,
  history,
  onCheck,
  onDelete,
  onOpenAudit,
}: {
  site: Site;
  history: SiteCheck[];
  onCheck: (id: number) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  onOpenAudit: (site: Site) => void;
}) {
  const [checking, setChecking] = useState(false);
  const findings = site.findings ?? [];
  const score = site.security_score ?? 100;
  const { grade, label: gradeLabel } = getGrade(score);

  const handleScan = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setChecking(true);
    try {
      await onCheck(site.id);
    } finally {
      setChecking(false);
    }
  };

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (window.confirm(`Stop monitoring and remove ${site.name || site.url}?`)) {
      onDelete(site.id);
    }
  };

  const handleExport = (e: React.MouseEvent) => {
    e.stopPropagation();
    window.location.href = `/api/sites/${site.id}/report`;
  };

  // Convert history checks to trend points
  const trendData = useMemo(() => {
    return history.slice(0, 24).reverse().map((c) => ({
      id: c.id,
      ts: c.ts,
      score: c.security_score,
      up: c.up,
      latency: c.latency_ms,
      findings_count: c.findings?.length ?? 0,
    }));
  }, [history]);

  const tlsDays = site.tls_days_left ?? -1;

  return (
    <div className={`site-card ${site.up === false ? 'is-down' : ''}`}>
      {/* Site Header */}
      <div className="site-card-top">
        <div className="site-identity">
          <div className="site-title-row">
            <h4 className="site-name" title={site.name}>{site.name || site.url}</h4>
            <span
              className={`site-status-pill ${
                site.up === null ? 'pending' : site.up ? 'up' : 'down'
              }`}
            >
              <span className="status-dot" />
              {site.up === null ? 'PENDING' : site.up ? `HTTP ${site.status_code || 200}` : 'OFFLINE'}
            </span>
          </div>
          <a
            href={site.url}
            target="_blank"
            rel="noopener noreferrer"
            className="site-url"
            onClick={(e) => e.stopPropagation()}
          >
            {site.url} <Icon name="link" size={11} />
          </a>
        </div>

        <div className="site-card-actions">
          <button
            className="card-action-btn scan"
            title="Run instant vulnerability & uptime scan"
            onClick={handleScan}
            disabled={checking}
          >
            <Icon name="zap" size={13} />
            {checking ? 'Scanning…' : 'Scan'}
          </button>
          <button
            className="card-action-btn"
            title="Download JSON vulnerability report"
            onClick={handleExport}
          >
            <Icon name="note" size={13} />
          </button>
          <button
            className="card-action-btn delete"
            title="Remove from monitoring"
            onClick={handleDelete}
          >
            <Icon name="close" size={13} />
          </button>
        </div>
      </div>

      {/* Body: Score & Findings Overview */}
      <div className="site-card-main-grid">
        <div className="site-score-col" onClick={() => onOpenAudit(site)}>
          <ScoreRing score={score} size={64} strokeWidth={6} showGrade={false} />
          <div className="site-score-info">
            <span className="site-grade-badge">{grade}</span>
            <span className="site-grade-text">{gradeLabel}</span>
          </div>
        </div>

        <div className="site-findings-col" onClick={() => onOpenAudit(site)}>
          <span className="card-sub-label">Vulnerability Breakdown</span>
          <FindingSummary findings={findings} />
          <div className="site-quick-meta">
            <span className="meta-item">
              <Icon name="clock" size={12} /> {site.latency_ms > 0 ? `${site.latency_ms}ms` : '—'}
            </span>
            <span className="meta-item">
              <Icon name="shield" size={12} />{' '}
              {tlsDays < 0 ? 'No TLS' : `${tlsDays}d SSL left`}
            </span>
            {site.technology && (
              <span className="meta-item tech" title={site.technology}>
                {site.technology.split(',')[0]}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Score History Trend Chart */}
      <div className="site-trend-container" onClick={() => onOpenAudit(site)}>
        <div className="trend-header">
          <span className="card-sub-label">Security Posture Trend</span>
          <span className="trend-latest">
            {site.uptime_24h >= 0 ? `${site.uptime_24h}% 24h uptime` : ''}
          </span>
        </div>
        <SecurityTrend data={trendData} height={60} />
      </div>

      {/* Footer: 48-check uptime bar + Audit CTA */}
      <div className="site-card-bottom">
        <UptimeBar checks={history} />
        <button className="open-audit-btn" onClick={() => onOpenAudit(site)}>
          View Vulnerability Audit →
        </button>
      </div>

      {site.error && <div className="site-card-error-banner">{site.error}</div>}
    </div>
  );
}

export function WebsiteMonitor({ sites }: WebsiteMonitorProps) {
  const [history, setHistory] = useState<Record<number, SiteCheck[]>>({});
  const [selectedSiteForAudit, setSelectedSiteForAudit] = useState<Site | null>(null);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [interval, setIntervalSec] = useState(60);
  const [adding, setAdding] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [sortBy, setSortBy] = useState<'score_asc' | 'score_desc' | 'name' | 'latency'>('score_asc');
  const [scanningSiteIds, setScanningSiteIds] = useState<Record<number, boolean>>({});

  // Load check history for sites
  const loadHistory = useCallback(async (id: number) => {
    try {
      const r = await fetch(`/api/sites/${id}/history?limit=48`);
      if (r.ok) {
        const j = await r.json();
        setHistory((prev) => ({ ...prev, [id]: j.checks ?? [] }));
      }
    } catch {
      /* offline */
    }
  }, []);

  useEffect(() => {
    sites.forEach((s) => loadHistory(s.id));
  }, [sites.map((s) => `${s.id}:${s.up}:${s.latency_ms}:${s.security_score}`).join('|')]); // eslint-disable-line react-hooks/exhaustive-deps

  // Platform Summary Metrics
  const summaryKpis: SiteSummaryKpis = useMemo(() => {
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

    const scores = sites.map((s) => s.security_score ?? 100);
    const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / total);
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

  // Add site handler
  const handleAddSite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setStatusMsg({ type: 'err', text: 'Please enter a target website URL' });
      return;
    }
    setAdding(true);
    setStatusMsg(null);

    try {
      const res = await fetch('/api/sites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim() || url.trim(),
          url: url.trim(),
          interval,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMsg({
          type: 'err',
          text: data.detail || `Failed to register target (HTTP ${res.status})`,
        });
      } else {
        setName('');
        setUrl('');
        const c = data.check;
        if (c && c.up) {
          setStatusMsg({
            type: 'ok',
            text: `Vulnerability scan completed — Grade ${getGrade(c.security_score).grade} (${c.security_score}/100), ${c.findings?.length || 0} findings detected.`,
          });
        } else {
          setStatusMsg({
            type: 'ok',
            text: 'Site registered — Automated vulnerability and uptime assessment active.',
          });
        }
        if (data.site?.id) await loadHistory(data.site.id);
      }
    } catch {
      setStatusMsg({
        type: 'err',
        text: 'Failed to communicate with NAD backend API. Ensure backend is running.',
      });
    } finally {
      setAdding(false);
    }
  };

  // Immediate check
  const handleCheckNow = async (id: number) => {
    setScanningSiteIds((prev) => ({ ...prev, [id]: true }));
    try {
      await fetch(`/api/sites/${id}/scan-now`, { method: 'POST' });
      await loadHistory(id);
    } catch {
      /* ignore */
    } finally {
      setScanningSiteIds((prev) => ({ ...prev, [id]: false }));
    }
  };

  // Delete site
  const handleDeleteSite = async (id: number) => {
    try {
      await fetch(`/api/sites/${id}`, { method: 'DELETE' });
      setHistory((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      if (selectedSiteForAudit?.id === id) {
        setSelectedSiteForAudit(null);
      }
    } catch {
      /* ignore */
    }
  };

  // Filter & Sort
  const displayedSites = useMemo(() => {
    return sites
      .filter((s) => {
        if (search) {
          const q = search.toLowerCase();
          const matchName = s.name.toLowerCase().includes(q);
          const matchUrl = s.url.toLowerCase().includes(q);
          if (!matchName && !matchUrl) return false;
        }
        if (filterSeverity === 'DOWN' && s.up !== false) return false;
        if (filterSeverity === 'CRITICAL') {
          const hasCrit = (s.findings ?? []).some((f) => f.severity === 'CRITICAL');
          if (!hasCrit) return false;
        }
        if (filterSeverity === 'HIGH_RISK') {
          const hasHigh = (s.findings ?? []).some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
          if (!hasHigh) return false;
        }
        if (filterSeverity === 'HEALTHY' && (s.security_score ?? 0) < 80) return false;
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'score_asc') return (a.security_score ?? 100) - (b.security_score ?? 100);
        if (sortBy === 'score_desc') return (b.security_score ?? 100) - (a.security_score ?? 100);
        if (sortBy === 'latency') return (b.latency_ms ?? 0) - (a.latency_ms ?? 0);
        return a.name.localeCompare(b.name);
      });
  }, [sites, search, filterSeverity, sortBy]);

  return (
    <div className="websec-platform-root">
      {/* ── 1. GLOBAL POSTURE SUMMARY BAR ── */}
      <div className="websec-summary-banner card">
        <div className="websec-banner-kpi">
          <span className="banner-kpi-val">{summaryKpis.total_sites}</span>
          <span className="banner-kpi-lbl">Monitored Targets</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span
            className="banner-kpi-val"
            style={{
              color:
                summaryKpis.avg_security_score >= 80
                  ? 'var(--low)'
                  : summaryKpis.avg_security_score >= 50
                  ? 'var(--med)'
                  : 'var(--crit)',
            }}
          >
            {summaryKpis.avg_security_score}/100
          </span>
          <span className="banner-kpi-lbl">Mean Security Score</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span className="banner-kpi-val" style={{ color: 'var(--low)' }}>
            {summaryKpis.up_count}
          </span>
          <span className="banner-kpi-lbl">Online (UP)</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span
            className="banner-kpi-val"
            style={{ color: summaryKpis.down_count > 0 ? 'var(--crit)' : 'var(--text)' }}
          >
            {summaryKpis.down_count}
          </span>
          <span className="banner-kpi-lbl">Offline (DOWN)</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span
            className="banner-kpi-val"
            style={{ color: summaryKpis.critical_high_count > 0 ? 'var(--crit)' : 'var(--text)' }}
          >
            {summaryKpis.critical_high_count}
          </span>
          <span className="banner-kpi-lbl">High/Crit Vulns</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span
            className="banner-kpi-val"
            style={{ color: summaryKpis.tls_expiring_count > 0 ? 'var(--med)' : 'var(--text)' }}
          >
            {summaryKpis.tls_expiring_count}
          </span>
          <span className="banner-kpi-lbl">SSL Expiring &lt;30d</span>
        </div>
        <div className="banner-divider" />
        <div className="websec-banner-kpi">
          <span className="banner-kpi-val">{summaryKpis.avg_uptime_24h}%</span>
          <span className="banner-kpi-lbl">Avg 24h Uptime</span>
        </div>
      </div>

      {/* ── 2. TARGET REGISTRATION & VULNERABILITY SCANNER FORM ── */}
      <div className="websec-onboard-card card">
        <div className="card-head">
          <h3>
            <span className="icon">
              <Icon name="globe" size={16} />
            </span>{' '}
            Vulnerability Scanner & Target Onboarding
          </h3>
          <span className="card-sub">
            Continuous SSL/TLS verification · OWASP exposure testing · Security headers compliance
          </span>
        </div>

        <form onSubmit={handleAddSite} className="websec-form">
          <div className="websec-form-fields">
            <input
              type="text"
              placeholder="Friendly Name (e.g. Production Web Gateway)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="websec-input"
            />
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="websec-input url-field"
              required
            />
            <select
              value={interval}
              onChange={(e) => setIntervalSec(Number(e.target.value))}
              className="websec-select"
            >
              <option value={30}>Audit every 30s</option>
              <option value={60}>Audit every 60s (Default)</option>
              <option value={300}>Audit every 5 min</option>
              <option value={900}>Audit every 15 min</option>
              <option value={3600}>Audit every 1 hour</option>
            </select>
            <button type="submit" className="primary-btn websec-submit-btn" disabled={adding}>
              <Icon name="zap" size={14} />
              {adding ? 'Scanning Target…' : 'Scan & Monitor'}
            </button>
          </div>
        </form>

        {statusMsg && (
          <div className={`websec-status-msg ${statusMsg.type}`}>
            <Icon name={statusMsg.type === 'ok' ? 'check' : 'alert'} size={14} />
            <span>{statusMsg.text}</span>
          </div>
        )}
      </div>

      {/* ── 3. SEARCH & FILTER CONTROLS ── */}
      <div className="websec-controls-row">
        <div className="websec-search-input-wrap">
          <Icon name="search" size={14} />
          <input
            type="text"
            placeholder="Search targets by domain or name..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && <button onClick={() => setSearch('')}>×</button>}
        </div>

        <div className="websec-filter-group">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="filter-select"
          >
            <option value="ALL">All Postures</option>
            <option value="HIGH_RISK">High / Critical Risk Only</option>
            <option value="CRITICAL">Critical Vulnerabilities</option>
            <option value="DOWN">Offline (Down) Targets</option>
            <option value="HEALTHY">Hardened (&gt;=80 Score)</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="filter-select"
          >
            <option value="score_asc">Sort: Lowest Security Score First</option>
            <option value="score_desc">Sort: Highest Security Score First</option>
            <option value="latency">Sort: Highest Latency First</option>
            <option value="name">Sort: Target Name (A–Z)</option>
          </select>
        </div>
      </div>

      {/* ── 4. TARGET CARDS GRID ── */}
      {displayedSites.length === 0 ? (
        <div className="card websec-empty-state">
          <div className="empty-state-icon">
            <Icon name="globe" size={36} />
          </div>
          <h4>No Monitored Targets Found</h4>
          <p>
            {sites.length === 0
              ? 'Onboard your first website above to initiate automated vulnerability scanning and security posture tracking.'
              : 'No targets match the active filter criteria. Clear filters to view all monitored origins.'}
          </p>
        </div>
      ) : (
        <div className="websec-cards-grid">
          {displayedSites.map((s) => (
            <SiteCard
              key={s.id}
              site={s}
              history={history[s.id] ?? []}
              onCheck={handleCheckNow}
              onDelete={handleDeleteSite}
              onOpenAudit={(target) => setSelectedSiteForAudit(target)}
            />
          ))}
        </div>
      )}

      {/* ── 5. FULL-SCREEN AUDIT REPORT MODAL ── */}
      {selectedSiteForAudit && (
        <AuditReportModal
          site={selectedSiteForAudit}
          latestCheck={history[selectedSiteForAudit.id]?.[0]}
          onClose={() => setSelectedSiteForAudit(null)}
          onScanNow={handleCheckNow}
          isScanning={Boolean(scanningSiteIds[selectedSiteForAudit.id])}
        />
      )}
    </div>
  );
}

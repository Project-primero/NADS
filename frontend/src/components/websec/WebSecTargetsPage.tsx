import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Site, SiteCheck } from '../../types';
import { ScoreRing, getGrade } from '../ScoreRing';
import { SecurityTrend } from '../SecurityTrend';
import { FindingSummary } from '../FindingSummary';
import { Icon } from '../Icon';

interface WebSecTargetsPageProps {
  sites: Site[];
  onOpenAudit: (site: Site) => void;
  onScanNow: (siteId: number) => Promise<void>;
  onDeleteSite: (siteId: number) => Promise<void>;
  onAddSite: () => void;
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
  const isUp = site.up;
  const isPending = isUp === null || isUp === undefined;
  const isOffline = isUp === false;
  const score = isPending ? 0 : isOffline ? 0 : (site.security_score ?? 0);
  const { grade, label: gradeLabel } = getGrade(score, isUp);

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
            title="Download JSON vulnerability assessment report"
            onClick={handleExport}
          >
            <Icon name="download" size={13} />
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
          <ScoreRing score={score} size={64} strokeWidth={6} showGrade={false} isUp={isUp} />
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
            {(site.uptime_24h != null && site.uptime_24h >= 0) ? `${site.uptime_24h}% 24h uptime` : ''}
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

export function WebSecTargetsPage({
  sites,
  onOpenAudit,
  onScanNow,
  onDeleteSite,
  onAddSite,
}: WebSecTargetsPageProps) {
  const [history, setHistory] = useState<Record<number, SiteCheck[]>>({});
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [sortBy, setSortBy] = useState<'score_asc' | 'score_desc' | 'name' | 'latency'>('score_asc');

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

  // Filter & sort
  const displayedSites = useMemo(() => {
    let list = sites.slice();

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (s) => s.url.toLowerCase().includes(q) || (s.name && s.name.toLowerCase().includes(q))
      );
    }

    if (filterSeverity === 'HIGH_RISK') {
      list = list.filter((s) => (s.findings ?? []).some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH'));
    } else if (filterSeverity === 'CRITICAL') {
      list = list.filter((s) => (s.findings ?? []).some((f) => f.severity === 'CRITICAL'));
    } else if (filterSeverity === 'DOWN') {
      list = list.filter((s) => s.up === false);
    } else if (filterSeverity === 'HEALTHY') {
      list = list.filter((s) => (s.security_score ?? 100) >= 80);
    }

    list.sort((a, b) => {
      if (sortBy === 'score_asc') return (a.security_score ?? 100) - (b.security_score ?? 100);
      if (sortBy === 'score_desc') return (b.security_score ?? 100) - (a.security_score ?? 100);
      if (sortBy === 'latency') return (b.latency_ms || 0) - (a.latency_ms || 0);
      if (sortBy === 'name') return (a.name || a.url).localeCompare(b.name || b.url);
      return 0;
    });

    return list;
  }, [sites, search, filterSeverity, sortBy]);

  return (
    <div className="websec-page-wrap">
      {/* ── Page Header & Controls ── */}
      <div className="websec-page-header">
        <div>
          <h2>Monitored Target Fleet</h2>
          <p>
            Continuous health telemetry, automated vulnerability scans, and security posture ratings across {sites.length} registered targets.
          </p>
        </div>
        <button className="btn btn-primary" onClick={onAddSite}>
          <Icon name="globe" size={15} /> + Add Target Domain
        </button>
      </div>

      {/* ── Search & Filter Controls ── */}
      <div className="websec-controls-row">
        <div className="websec-search-input-wrap">
          <Icon name="search" size={14} />
          <input
            type="text"
            placeholder="Search targets by domain, host, or name..."
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
            <option value="ALL">All Postures ({sites.length})</option>
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
            <option value="latency">Sort: Slowest Response Latency First</option>
            <option value="name">Sort: Target Name (A–Z)</option>
          </select>
        </div>
      </div>

      {/* ── Target Cards Grid ── */}
      {displayedSites.length === 0 ? (
        <div className="card websec-empty-state">
          <div className="empty-state-icon">
            <Icon name="globe" size={36} />
          </div>
          <h4>No Monitored Targets Found</h4>
          <p>
            {sites.length === 0
              ? 'Click "+ Add Target Domain" above to register your first website origin for continuous inspection.'
              : 'No targets match the active filter criteria. Clear filters or adjust your search term.'}
          </p>
          {sites.length === 0 && (
            <button className="btn btn-primary" onClick={onAddSite} style={{ marginTop: 12 }}>
              Add Target Now
            </button>
          )}
        </div>
      ) : (
        <div className="websec-cards-grid">
          {displayedSites.map((s) => (
            <SiteCard
              key={s.id}
              site={s}
              history={history[s.id] ?? []}
              onCheck={onScanNow}
              onDelete={onDeleteSite}
              onOpenAudit={onOpenAudit}
            />
          ))}
        </div>
      )}
    </div>
  );
}

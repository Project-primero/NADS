import { useMemo, useState } from 'react';
import type { Site } from '../../types';
import { Icon } from '../Icon';

interface WebSecTlsAuditPageProps {
  sites: Site[];
  onScanNow: (siteId: number) => Promise<void>;
  onOpenAudit: (site: Site) => void;
}

export function WebSecTlsAuditPage({
  sites,
  onScanNow,
  onOpenAudit,
}: WebSecTlsAuditPageProps) {
  const [filter, setFilter] = useState<'ALL' | 'EXPIRING' | 'INVALID' | 'MODERN'>('ALL');
  const [search, setSearch] = useState('');
  const [scanningId, setScanningId] = useState<number | null>(null);

  // Filtered sites
  const displayedSites = useMemo(() => {
    let list = sites.slice();

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((s) => s.url.toLowerCase().includes(q) || (s.name && s.name.toLowerCase().includes(q)));
    }

    if (filter === 'EXPIRING') {
      list = list.filter((s) => (s.tls_days_left ?? -1) >= 0 && (s.tls_days_left ?? -1) < 30);
    } else if (filter === 'INVALID') {
      list = list.filter((s) => (s.tls_days_left ?? -1) < 0);
    } else if (filter === 'MODERN') {
      list = list.filter((s) => s.tls_proto?.includes('1.3'));
    }

    return list;
  }, [sites, search, filter]);

  // Aggregate stats
  const stats = useMemo(() => {
    const total = sites.length;
    const expiring = sites.filter((s) => (s.tls_days_left ?? -1) >= 0 && (s.tls_days_left ?? -1) < 30).length;
    const invalid = sites.filter((s) => (s.tls_days_left ?? -1) < 0).length;
    const tls13 = sites.filter((s) => s.tls_proto?.includes('1.3')).length;
    const tls12 = sites.filter((s) => s.tls_proto?.includes('1.2')).length;

    return { total, expiring, invalid, tls13, tls12 };
  }, [sites]);

  const handleScan = async (siteId: number) => {
    setScanningId(siteId);
    try {
      await onScanNow(siteId);
    } finally {
      setScanningId(null);
    }
  };

  return (
    <div className="websec-page-wrap">
      {/* ── Page Header ── */}
      <div className="websec-page-header">
        <div>
          <h2>SSL / TLS Cryptography &amp; Public Key Infrastructure</h2>
          <p>
            Continuous audit of X.509 certificate chains, validity expiration countdowns, negotiated
            TLS protocol versions, forward secrecy cipher suites, and HSTS preload policies.
          </p>
        </div>
      </div>

      {/* ── Alert Banner if any certs expiring in < 30d ── */}
      {stats.expiring > 0 && (
        <div className="websec-status-msg err" style={{ marginBottom: 18 }}>
          <Icon name="alert" size={16} />
          <span>
            <b>Certificate Expiration Warning:</b> {stats.expiring} monitored origin
            {stats.expiring === 1 ? ' has a certificate' : 's have certificates'} expiring within 30 days.
            Renew immediately to avoid public browser trust outages.
          </span>
        </div>
      )}

      {/* ── Cryptography KPI Metrics ── */}
      <div className="websec-posture-banner" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Total Endpoints</span>
            <Icon name="lock" size={16} />
          </div>
          <div className="posture-value">{stats.total}</div>
          <div className="posture-sub">SSL/TLS monitored origins</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Expiring in &lt; 30d</span>
            <Icon name="clock" size={16} />
          </div>
          <div className="posture-value" style={{ color: stats.expiring > 0 ? 'var(--crit)' : 'var(--low)' }}>
            {stats.expiring}
          </div>
          <div className="posture-sub">Requires near-term renewal</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Modern TLS 1.3</span>
            <Icon name="zap" size={16} />
          </div>
          <div className="posture-value" style={{ color: 'var(--low)' }}>{stats.tls13}</div>
          <div className="posture-sub">Optimal zero-RTT cryptography</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Standard TLS 1.2</span>
            <Icon name="shield" size={16} />
          </div>
          <div className="posture-value">{stats.tls12}</div>
          <div className="posture-sub">Baseline protocol support</div>
        </div>
      </div>

      {/* ── Filter Controls ── */}
      <div className="websec-controls-row" style={{ marginTop: 18 }}>
        <div className="websec-search-input-wrap">
          <Icon name="search" size={14} />
          <input
            type="text"
            placeholder="Search certificate issuer, protocol, cipher, or domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && <button onClick={() => setSearch('')}>×</button>}
        </div>

        <div className="websec-filter-group">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as any)}
            className="filter-select"
          >
            <option value="ALL">All Certificates ({sites.length})</option>
            <option value="EXPIRING">Expiring &lt; 30 Days ({stats.expiring})</option>
            <option value="INVALID">Missing / Invalid TLS ({stats.invalid})</option>
            <option value="MODERN">TLS 1.3 Supported ({stats.tls13})</option>
          </select>
        </div>
      </div>

      {/* ── TLS Table / Cards ── */}
      <div className="card" style={{ marginTop: 14 }}>
        <div className="tls-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target Domain</th>
                <th>Validity &amp; Countdown</th>
                <th>Protocol</th>
                <th>Cipher Suite</th>
                <th>Certificate Authority</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {displayedSites.map((site) => {
                const days = site.tls_days_left ?? -1;
                const isExpiring = days >= 0 && days < 30;
                const isExpired = days < 0;

                return (
                  <tr key={site.id}>
                    <td>
                      <div className="tls-site-title">{site.name || site.url}</div>
                      <a
                        href={site.url}
                        target="_blank"
                        rel="noreferrer"
                        className="site-table-link"
                      >
                        {site.url}
                      </a>
                    </td>
                    <td>
                      {isExpired ? (
                        <span className="tls-pill invalid">Invalid / Expired</span>
                      ) : isExpiring ? (
                        <span className="tls-pill warning">Expires in {days} days</span>
                      ) : (
                        <span className="tls-pill valid">Valid ({days}d left)</span>
                      )}
                    </td>
                    <td>
                      <span className={`protocol-badge ${site.tls_proto?.includes('1.3') ? 'modern' : ''}`}>
                        {site.tls_proto || 'Plaintext HTTP'}
                      </span>
                    </td>
                    <td>
                      <div className="cipher-code" title={site.tls_cipher}>
                        {site.tls_cipher || 'None negotiated'}
                      </div>
                    </td>
                    <td>
                      <div className="issuer-text" title={site.tls_issuer}>
                        {site.tls_issuer ? site.tls_issuer.split(',')[0] : 'None'}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="btn btn-sm"
                          onClick={() => handleScan(site.id)}
                          disabled={scanningId === site.id}
                          title="Re-probe TLS handshake"
                        >
                          {scanningId === site.id ? 'Probing…' : 'Re-probe'}
                        </button>
                        <button
                          className="btn btn-sm btn-ghost"
                          onClick={() => onOpenAudit(site)}
                          title="View complete cryptographic audit"
                        >
                          Audit →
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

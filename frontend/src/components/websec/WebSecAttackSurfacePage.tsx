import { useMemo, useState } from 'react';
import type { Site } from '../../types';
import { Icon } from '../Icon';

interface WebSecAttackSurfacePageProps {
  sites: Site[];
  onOpenAudit: (site: Site) => void;
  onScanNow: (siteId: number) => Promise<void>;
}

export function WebSecAttackSurfacePage({
  sites,
  onOpenAudit,
  onScanNow,
}: WebSecAttackSurfacePageProps) {
  const [selectedSiteId, setSelectedSiteId] = useState<number | 'ALL'>('ALL');

  // Filtered sites
  const displayedSites = useMemo(() => {
    if (selectedSiteId === 'ALL') return sites;
    return sites.filter((s) => s.id === selectedSiteId);
  }, [sites, selectedSiteId]);

  // Aggregate probe counts
  const stats = useMemo(() => {
    let exposedPaths = 0;
    let dangerousMethods = 0;
    let missingSecurityTxt = 0;
    let missingSri = 0;
    let wafDetected = 0;

    for (const site of sites) {
      for (const f of site.findings ?? []) {
        const cat = f.category?.toLowerCase() || '';
        const title = f.title.toLowerCase();
        if (cat.includes('exposure') || title.includes('exposed') || title.includes('backup') || title.includes('.git') || title.includes('.env')) {
          exposedPaths += 1;
        }
        if (title.includes('dangerous') || title.includes('trace') || title.includes('method')) {
          dangerousMethods += 1;
        }
        if (title.includes('security.txt')) {
          missingSecurityTxt += 1;
        }
        if (title.includes('subresource integrity') || title.includes('sri')) {
          missingSri += 1;
        }
        if (title.includes('waf') || title.includes('firewall')) {
          wafDetected += 1;
        }
      }
    }

    return { exposedPaths, dangerousMethods, missingSecurityTxt, missingSri, wafDetected };
  }, [sites]);

  return (
    <div className="websec-page-wrap">
      {/* ── Page Header ── */}
      <div className="websec-page-header">
        <div>
          <h2>Attack Surface &amp; Reconnaissance Exposure</h2>
          <p>
            Continuous inspection of publicly accessible secrets, sensitive administrative interfaces,
            unprotected HTTP methods, subresource integrity on third-party scripts, and RFC 9116 policies.
          </p>
        </div>
        <div className="websec-filter-group">
          <select
            value={selectedSiteId}
            onChange={(e) => setSelectedSiteId(e.target.value === 'ALL' ? 'ALL' : Number(e.target.value))}
            className="filter-select"
          >
            <option value="ALL">All Targets ({sites.length})</option>
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name || s.url}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* ── Attack Surface KPIs ── */}
      <div className="websec-posture-banner" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Exposed Sensitive Files</span>
            <Icon name="file" size={16} />
          </div>
          <div
            className="posture-value"
            style={{ color: stats.exposedPaths > 0 ? 'var(--crit)' : 'var(--low)' }}
          >
            {stats.exposedPaths}
          </div>
          <div className="posture-sub">.env, .git, backups, actuators</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Dangerous HTTP Verbs</span>
            <Icon name="alert" size={16} />
          </div>
          <div
            className="posture-value"
            style={{ color: stats.dangerousMethods > 0 ? 'var(--high)' : 'var(--low)' }}
          >
            {stats.dangerousMethods}
          </div>
          <div className="posture-sub">TRACE XST, PUT/DELETE</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Missing CDN SRI</span>
            <Icon name="link" size={16} />
          </div>
          <div
            className="posture-value"
            style={{ color: stats.missingSri > 0 ? 'var(--high)' : 'var(--low)' }}
          >
            {stats.missingSri}
          </div>
          <div className="posture-sub">Supply-chain script risks</div>
        </div>

        <div className="posture-card">
          <div className="posture-card-top">
            <span className="posture-label">Missing security.txt</span>
            <Icon name="shield" size={16} />
          </div>
          <div className="posture-value">{stats.missingSecurityTxt}</div>
          <div className="posture-sub">RFC 9116 disclosure compliance</div>
        </div>
      </div>

      {/* ── Detailed Surface Cards by Site ── */}
      <div className="attack-surface-grid" style={{ marginTop: 18 }}>
        {displayedSites.map((site) => {
          const findings = site.findings ?? [];
          const exposureFindings = findings.filter(
            (f) =>
              f.category?.toLowerCase().includes('exposure') ||
              f.category?.toLowerCase().includes('information') ||
              f.category?.toLowerCase().includes('method') ||
              f.title.toLowerCase().includes('sri') ||
              f.title.toLowerCase().includes('security.txt') ||
              f.title.toLowerCase().includes('robots') ||
              f.title.toLowerCase().includes('trace') ||
              f.title.toLowerCase().includes('banner')
          );

          return (
            <div key={site.id} className="card attack-surface-site-card">
              <div className="card-head">
                <div>
                  <h3>
                    <span className="icon"><Icon name="target" size={16} /></span> {site.name || site.url}
                  </h3>
                  <a
                    href={site.url}
                    target="_blank"
                    rel="noreferrer"
                    className="site-table-link"
                    style={{ fontSize: '0.8rem' }}
                  >
                    {site.url}
                  </a>
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <span className="site-grade-badge" style={{ fontSize: '0.8rem', padding: '2px 8px' }}>
                    Score: {site.security_score}/100
                  </span>
                  <button
                    className="btn btn-sm"
                    onClick={() => onOpenAudit(site)}
                  >
                    View Audit →
                  </button>
                </div>
              </div>

              {/* Surface Checks Matrix */}
              <div className="surface-checks-grid">
                <div className="surface-check-item">
                  <span className="surface-check-name">Server Banner Exposure</span>
                  <span className="surface-check-val">
                    {site.server_banner ? (
                      <span className="chip-warn">Leaked: {site.server_banner}</span>
                    ) : (
                      <span className="chip-ok">Hidden / Hardened</span>
                    )}
                  </span>
                </div>

                <div className="surface-check-item">
                  <span className="surface-check-name">Technology Fingerprint</span>
                  <span className="surface-check-val">
                    {site.technology ? (
                      <span className="chip-neutral">{site.technology}</span>
                    ) : (
                      <span className="chip-ok">Suppressed</span>
                    )}
                  </span>
                </div>

                <div className="surface-check-item">
                  <span className="surface-check-name">Dangerous Methods (TRACE/PUT)</span>
                  <span className="surface-check-val">
                    {findings.some((f) => f.title.toLowerCase().includes('method') || f.title.toLowerCase().includes('trace')) ? (
                      <span className="chip-err">Dangerous Methods Active</span>
                    ) : (
                      <span className="chip-ok">Restricted</span>
                    )}
                  </span>
                </div>

                <div className="surface-check-item">
                  <span className="surface-check-name">Subresource Integrity (SRI)</span>
                  <span className="surface-check-val">
                    {findings.some((f) => f.title.toLowerCase().includes('sri')) ? (
                      <span className="chip-warn">Unprotected CDN Scripts</span>
                    ) : (
                      <span className="chip-ok">Hardened / Valid</span>
                    )}
                  </span>
                </div>

                <div className="surface-check-item">
                  <span className="surface-check-name">RFC 9116 security.txt</span>
                  <span className="surface-check-val">
                    {findings.some((f) => f.title.toLowerCase().includes('security.txt')) ? (
                      <span className="chip-warn">Missing /.well-known/security.txt</span>
                    ) : (
                      <span className="chip-ok">Configured</span>
                    )}
                  </span>
                </div>

                <div className="surface-check-item">
                  <span className="surface-check-name">robots.txt Disclosures</span>
                  <span className="surface-check-val">
                    {findings.some((f) => f.title.toLowerCase().includes('robots')) ? (
                      <span className="chip-warn">Disclosed Sensitive Paths</span>
                    ) : (
                      <span className="chip-ok">Clean / Protected</span>
                    )}
                  </span>
                </div>
              </div>

              {/* Specific Findings List */}
              {exposureFindings.length > 0 && (
                <div className="surface-findings-wrap" style={{ marginTop: 14 }}>
                  <span className="card-sub-label">Surface Findings &amp; Evidence</span>
                  <div className="surface-findings-list">
                    {exposureFindings.map((f, i) => (
                      <div key={i} className="surface-finding-pill">
                        <span className={`finding-chip ${f.severity.toLowerCase()}`}>{f.severity}</span>
                        <span className="surface-finding-text">{f.title}</span>
                        {f.evidence && <code className="surface-finding-code">{f.evidence}</code>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

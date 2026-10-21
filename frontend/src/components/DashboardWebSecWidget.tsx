import type { Site } from '../types';
import { ScoreRing, getGrade } from './ScoreRing';
import { FindingSummary } from './FindingSummary';
import { Icon } from './Icon';

interface DashboardWebSecWidgetProps {
  sites: Site[];
  onOpenAddModal: () => void;
  onOpenAudit: (site: Site) => void;
  onNavigateToWebSec: () => void;
}

export function DashboardWebSecWidget({
  sites,
  onOpenAddModal,
  onOpenAudit,
  onNavigateToWebSec,
}: DashboardWebSecWidgetProps) {
  const total = sites.length;
  const scores = sites.map((s) => s.security_score ?? 100);
  const avgScore = total > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / total) : 100;
  const upCount = sites.filter((s) => s.up === true).length;
  const downCount = sites.filter((s) => s.up === false).length;
  const critHighCount = sites.reduce(
    (acc, s) =>
      acc + (s.findings ?? []).filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length,
    0
  );

  return (
    <div className="card dashboard-websec-widget">
      <div className="card-head">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <h3>
            <span className="icon">
              <Icon name="globe" size={16} />
            </span>{' '}
            Website Security & Vulnerability Posture
          </h3>
          {total > 0 && (
            <span className="card-sub">
              {total} target{total > 1 ? 's' : ''} monitored · {avgScore}/100 avg score
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button
            className="btn btn-primary"
            style={{ padding: '5px 12px', fontSize: '11.5px', height: 'auto' }}
            onClick={onOpenAddModal}
            title="Add and immediately audit a website target"
          >
            <Icon name="zap" size={13} /> + Add Website
          </button>
          {total > 0 && (
            <button
              className="link-btn"
              style={{ fontSize: '11.5px' }}
              onClick={onNavigateToWebSec}
              title="Open full Website Security Platform console"
            >
              Full Console →
            </button>
          )}
        </div>
      </div>

      {total === 0 ? (
        <div className="websec-widget-empty">
          <div style={{ color: 'var(--muted)', marginBottom: 4 }}>
            <Icon name="globe" size={28} />
          </div>
          <p style={{ margin: 0, fontWeight: 600, fontSize: 13 }}>No websites monitored yet</p>
          <p style={{ margin: '4px 0 12px 0', color: 'var(--muted)', fontSize: 12 }}>
            Start monitoring your public websites, APIs, and portals for vulnerabilities, TLS expiry, and attack surface exposures.
          </p>
          <button className="btn btn-primary" onClick={onOpenAddModal} style={{ fontSize: 12 }}>
            <Icon name="zap" size={13} /> Add & Scan First Target
          </button>
        </div>
      ) : (
        <div>
          {/* Quick Stats Bar */}
          <div className="websec-widget-stats">
            <div className="widget-stat">
              <span className="stat-label">Average Score</span>
              <span
                className="stat-val"
                style={{ color: getGrade(avgScore).color }}
              >
                {avgScore}/100 ({getGrade(avgScore).grade})
              </span>
            </div>
            <div className="widget-stat">
              <span className="stat-label">Online Status</span>
              <span className="stat-val" style={{ color: 'var(--low)' }}>
                {upCount} UP {downCount > 0 ? <span style={{ color: 'var(--crit)' }}>· {downCount} DOWN</span> : ''}
              </span>
            </div>
            <div className="widget-stat">
              <span className="stat-label">High / Critical Vulns</span>
              <span
                className="stat-val"
                style={{ color: critHighCount > 0 ? 'var(--crit)' : 'var(--low)' }}
              >
                {critHighCount} issue{critHighCount === 1 ? '' : 's'}
              </span>
            </div>
          </div>

          {/* Target List */}
          <div className="websec-widget-list">
            {sites.slice(0, 4).map((site) => {
              const findings = site.findings ?? [];
              const score = site.security_score ?? 100;
              const { grade, color } = getGrade(score);

              return (
                <div
                  key={site.id}
                  className="websec-widget-item"
                  onClick={() => onOpenAudit(site)}
                  title="Click to view full vulnerability report"
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: 1 }}>
                    <ScoreRing score={score} size={42} strokeWidth={4.5} showGrade={false} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontWeight: 700, fontSize: 13, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {site.name || site.url}
                        </span>
                        <span
                          className={`site-status-pill ${
                            site.up ? 'up' : site.up === false ? 'down' : 'pending'
                          }`}
                        >
                          {site.up ? 'UP' : site.up === false ? 'DOWN' : 'PENDING'}
                        </span>
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {site.url}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                    <FindingSummary findings={findings} compact />
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontWeight: 800, fontSize: 13, color }}>
                        {grade} ({score})
                      </span>
                      <span style={{ display: 'block', fontSize: 10, color: 'var(--muted)' }}>
                        {site.latency_ms > 0 ? `${site.latency_ms}ms` : '—'}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {sites.length > 4 && (
            <div style={{ textAlign: 'center', marginTop: 10 }}>
              <button className="link-btn" onClick={onNavigateToWebSec} style={{ fontSize: 12 }}>
                View all {sites.length} monitored websites →
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

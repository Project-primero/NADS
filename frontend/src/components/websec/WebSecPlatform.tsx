import { useMemo, useState } from 'react';
import type { Site, SiteCheck } from '../../types';
import { ThemePicker } from '../ThemePicker';
import { Icon } from '../Icon';
import { AddSiteModal } from '../AddSiteModal';
import { AuditReportModal } from '../AuditReportModal';
import { type Theme } from '../../lib/themes';

import { WebSecOverviewPage } from './WebSecOverviewPage';
import { WebSecTargetsPage } from './WebSecTargetsPage';
import { WebSecScannerPage } from './WebSecScannerPage';
import { WebSecVulnerabilitiesPage } from './WebSecVulnerabilitiesPage';
import { WebSecTlsAuditPage } from './WebSecTlsAuditPage';
import { WebSecAttackSurfacePage } from './WebSecAttackSurfacePage';
import { WebSecReportsPage } from './WebSecReportsPage';

interface WebSecPlatformProps {
  sites: Site[];
  connected: boolean;
  theme: Theme;
  onThemeChange: (theme: Theme) => void;
  onSwitchPlatform: (platform: 'nad' | 'websec') => void;
}

const WEBSEC_NAV = [
  { id: 'overview', label: 'Executive Posture', icon: 'dashboard', sub: 'Fleet KPIs & health' },
  { id: 'targets', label: 'Monitored Fleet', icon: 'globe', sub: 'Origins & intervals' },
  { id: 'scanner', label: 'Live Scanner', icon: 'zap', sub: 'On-demand dynamic audit' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: 'bug', sub: 'Deficiency catalog' },
  { id: 'tls', label: 'SSL / TLS Audit', icon: 'lock', sub: 'Certs & cryptography' },
  { id: 'recon', label: 'Attack Surface', icon: 'target', sub: 'Exposure & secrets' },
  { id: 'reports', label: 'Compliance Reports', icon: 'file', sub: 'OWASP & JSON export' },
] as const;

export function WebSecPlatform({
  sites,
  connected,
  theme,
  onThemeChange,
  onSwitchPlatform,
}: WebSecPlatformProps) {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [showAddModal, setShowAddModal] = useState(false);
  const [auditSite, setAuditSite] = useState<Site | null>(null);
  const [auditCheck, setAuditCheck] = useState<SiteCheck | null>(null);

  const handleOpenAudit = (s: Site, c?: SiteCheck | null) => {
    setAuditSite(s);
    setAuditCheck(c || null);
  };

  // Trigger on-demand scan for a site
  const handleScanNow = async (siteId: number) => {
    try {
      await fetch(`/api/sites/${siteId}/scan-now`, { method: 'POST' });
    } catch {
      /* ignore */
    }
  };

  // Delete site
  const handleDeleteSite = async (siteId: number) => {
    try {
      await fetch(`/api/sites/${siteId}`, { method: 'DELETE' });
    } catch {
      /* ignore */
    }
  };

  // Add site to fleet
  const handleAddSiteToFleet = async (url: string, name: string) => {
    const res = await fetch('/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, name, interval: 60 }),
    });
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      throw new Error(j.detail || `Failed to register target (HTTP ${res.status})`);
    }
  };

  // Badge counts
  const totalFindings = useMemo(() => {
    return sites.reduce((acc, s) => acc + (s.findings?.length || 0), 0);
  }, [sites]);

  const expiringTlsCount = useMemo(() => {
    return sites.filter((s) => (s.tls_days_left ?? -1) >= 0 && (s.tls_days_left ?? -1) < 30).length;
  }, [sites]);

  const hasCritOrDown = useMemo(() => {
    return sites.some(
      (s) => s.up === false || (s.findings ?? []).some((f) => f.severity === 'CRITICAL')
    );
  }, [sites]);

  const [scanningAll, setScanningAll] = useState(false);

  const handleScanAll = async () => {
    setScanningAll(true);
    try {
      await fetch('/api/sites/scan-all', { method: 'POST' });
    } catch {
      /* ignore */
    } finally {
      setScanningAll(false);
    }
  };

  return (
    <div className="soc websec-layout">
      {/* ── SEPARATE DEDICATED WEBSEC SIDEBAR ── */}
      <aside className="sidebar websec-sidebar">
        {/* Brand */}
        <div className="brand">
          <span className="logo" style={{ background: 'linear-gradient(135deg, var(--accent), var(--blue))' }}>
            <Icon name="globe" size={22} />
          </span>
          <span className="brand-name">
            WebSec
            <small>Website Security & Vulnerability Platform</small>
          </span>
        </div>

        {/* Platform Switcher Control */}
        <div className="platform-switch-box">
          <div className="platform-switch-label">ACTIVE PLATFORM</div>
          <button
            className="platform-switch-btn"
            onClick={() => onSwitchPlatform('nad')}
            title="Switch back to Network Anomaly Detection SOC Console"
          >
            <span className="platform-switch-name">
              <Icon name="shield" size={14} /> Network Anomaly (NAD)
            </span>
            <span className="platform-switch-arrow">Switch ⇄</span>
          </button>
        </div>

        {/* Dedicated WebSec Nav Menu */}
        <nav className="nav websec-nav">
          {WEBSEC_NAV.map(({ id, label, icon, sub }) => {
            const isActive = activeTab === id;
            return (
              <button
                key={id}
                className={`nav-btn-websec-item ${isActive ? 'active' : ''}`}
                onClick={() => setActiveTab(id)}
              >
                <span className="nav-icon"><Icon name={icon} size={17} /></span>
                <div className="nav-websec-item-text">
                  <div className="nav-websec-item-top">
                    <span className="item-title">{label}</span>
                    {id === 'targets' && sites.length > 0 && (
                      <span className="nav-badge-pill" style={{ background: hasCritOrDown ? 'var(--crit)' : 'var(--low)' }}>
                        {sites.length}
                      </span>
                    )}
                    {id === 'vulnerabilities' && totalFindings > 0 && (
                      <span className="nav-badge-pill info">
                        {totalFindings}
                      </span>
                    )}
                    {id === 'tls' && expiringTlsCount > 0 && (
                      <span className="nav-badge-pill warn">
                        {expiringTlsCount}
                      </span>
                    )}
                  </div>
                  <span className="item-sub">{sub}</span>
                </div>
              </button>
            );
          })}
        </nav>

        {/* Theme Picker */}
        <ThemePicker theme={theme} onChange={onThemeChange} />

        {/* Compliance Standards Footer */}
        <div className="detectors">
          <b>Audit &amp; Compliance Standards</b>
          <div className="pills">
            {['OWASP Top 10', 'RFC 9116 security.txt', 'CWE Hierarchy', 'MITRE ATT&CK', 'HSTS Preload', 'Subresource Integrity (SRI)', 'TLS 1.3 / Cryptography', 'Edge WAF Probing'].map((d) => (
              <span className="pill" key={d}>{d}</span>
            ))}
          </div>
        </div>
      </aside>

      {/* ── SEPARATE MAIN PAGE AREA ── */}
      <div className="main">
        {/* Topbar */}
        <div className="topbar">
          <div>
            <h1>
              {activeTab === 'overview' && 'Executive Posture & Fleet Summary'}
              {activeTab === 'targets' && 'Monitored Fleet & Target Origins'}
              {activeTab === 'scanner' && 'Active On-Demand Vulnerability Scanner'}
              {activeTab === 'vulnerabilities' && 'Vulnerability & Deficiency Catalog'}
              {activeTab === 'tls' && 'SSL / TLS Cryptography & PKI Health'}
              {activeTab === 'recon' && 'Attack Surface & Reconnaissance Exposure'}
              {activeTab === 'reports' && 'Executive Compliance & Assessment Reports'}
            </h1>
            <div className="topbar-sub">
              Website Security Monitoring &amp; Vulnerability Assessment Platform · Continuous telemetry &amp; dynamic security probes
            </div>
          </div>

          <div className="topbar-right" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              className="btn btn-secondary"
              onClick={handleScanAll}
              disabled={scanningAll}
              title="Trigger active real-world vulnerability scan across all fleet targets"
            >
              <Icon name="refresh" size={14} />
              {scanningAll ? 'Scanning Fleet…' : 'Scan All Targets ⚡'}
            </button>
            <button
              className="btn btn-primary topbar-add-site-btn"
              onClick={() => setShowAddModal(true)}
              title="Add a website target for instant dynamic security audit"
            >
              <Icon name="globe" size={14} /> + Add Target
            </button>
            <span className="live">
              <span className="dot" />
              {connected ? 'LIVE TELEMETRY' : 'CONNECTING…'}
            </span>
          </div>
        </div>

        {/* Separated Page Content */}
        {activeTab === 'overview' && (
          <WebSecOverviewPage
            sites={sites}
            onNavigate={(t) => setActiveTab(t)}
            onOpenAudit={handleOpenAudit}
            onScanNow={handleScanNow}
            onAddSite={() => setShowAddModal(true)}
          />
        )}

        {activeTab === 'targets' && (
          <WebSecTargetsPage
            sites={sites}
            onOpenAudit={handleOpenAudit}
            onScanNow={handleScanNow}
            onDeleteSite={handleDeleteSite}
            onAddSite={() => setShowAddModal(true)}
          />
        )}

        {activeTab === 'scanner' && (
          <WebSecScannerPage
            onAddSiteToFleet={handleAddSiteToFleet}
            onOpenAudit={handleOpenAudit}
          />
        )}

        {activeTab === 'vulnerabilities' && (
          <WebSecVulnerabilitiesPage
            sites={sites}
            onOpenAudit={handleOpenAudit}
          />
        )}

        {activeTab === 'tls' && (
          <WebSecTlsAuditPage
            sites={sites}
            onScanNow={handleScanNow}
            onOpenAudit={handleOpenAudit}
          />
        )}

        {activeTab === 'recon' && (
          <WebSecAttackSurfacePage
            sites={sites}
            onOpenAudit={handleOpenAudit}
            onScanNow={handleScanNow}
          />
        )}

        {activeTab === 'reports' && (
          <WebSecReportsPage
            sites={sites}
            onOpenAudit={handleOpenAudit}
          />
        )}
      </div>

      {/* ── Modals ── */}
      {showAddModal && (
        <AddSiteModal
          isOpen={showAddModal}
          onClose={() => setShowAddModal(false)}
          onViewAudit={(site, check) => handleOpenAudit(site, check)}
        />
      )}

      {auditSite && (
        <AuditReportModal
          site={auditSite}
          latestCheck={auditCheck}
          onClose={() => {
            setAuditSite(null);
            setAuditCheck(null);
          }}
          onScanNow={handleScanNow}
        />
      )}
    </div>
  );
}

import { useState, type CSSProperties } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { TrafficChart } from './TrafficChart';
import { ProtocolDonut } from './ProtocolBreakdown';
import { AttackMix } from './AttackMix';
import { AlertFeed } from './AlertPanel';
import { TopTalkers } from './TopTalkers';
import { TopOffenders } from './TopOffenders';
import { ThreatMatrix } from './ThreatMatrix';
import { ThemePicker } from './ThemePicker';
import { Icon } from './Icon';
import { WebsiteMonitor } from './WebsiteMonitor';
import { AddSiteModal } from './AddSiteModal';
import { DashboardWebSecWidget } from './DashboardWebSecWidget';
import { AuditReportModal } from './AuditReportModal';
import { WebSecPlatform } from './websec/WebSecPlatform';
import { initTheme, type Theme } from '../lib/themes';
import type { Site } from '../types';

const DETECTOR_GROUPS = [
  'Port / Horizontal Scan', 'Ping Sweep', 'SYN/UDP/ICMP Flood', 'DDoS', 'Slowloris',
  'SSH/FTP/RDP/Telnet/HTTP Brute Force', 'Password Spraying',
  'DNS Tunneling', 'ARP Spoofing', 'C2 + Beaconing', 'SMB Lateral Movement',
  'Cryptominer', 'SQLi / XSS / CMDi', 'Log4Shell', 'SSRF', 'Exfiltration', '+ ML Anomaly',
];

const TABS = [
  { id: 'Overview', label: 'Overview', icon: 'dashboard' },
  { id: 'Alerts', label: 'Alerts', icon: 'alert' },
  { id: 'Network', label: 'Network', icon: 'network' },
  { id: 'Threat Intel', label: 'Threat Intel', icon: 'brain' },
] as const;

function Kpi({ label, value, sub, accent, icon }: {
  label: string; value: string; sub: string; accent: string; icon: string;
}) {
  return (
    <div className="kpi" style={{ '--kpi-accent': accent } as CSSProperties}>
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <span className="kpi-icon"><Icon name={icon} size={16} /></span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

export function Dashboard() {
  const [platform, setPlatform] = useState<'nad' | 'websec'>(() => {
    const saved = localStorage.getItem('aegis_platform');
    return saved === 'websec' ? 'websec' : 'nad';
  });
  const [tab, setTab] = useState<string>('Overview');
  const [theme, setTheme] = useState<Theme>(() => initTheme());
  const [showAddSiteModal, setShowAddSiteModal] = useState(false);
  const [auditSite, setAuditSite] = useState<Site | null>(null);

  const wsUrl = `ws://${window.location.hostname}:8000/ws`;
  const { stats, alerts, counts, attackMix, protocols, series, sites, connected } = useWebSocket(wsUrl);
  const crit = (counts.CRITICAL ?? 0) + (counts.HIGH ?? 0);
  const totalAlerts = alerts.length;

  const handleScanNow = async (siteId: number) => {
    try {
      await fetch(`/api/sites/${siteId}/scan-now`, { method: 'POST' });
    } catch {
      /* ignore */
    }
  };

  // If on Website Security Platform, render dedicated platform layout with separated pages
  if (platform === 'websec') {
    return (
      <WebSecPlatform
        sites={sites}
        connected={connected}
        theme={theme}
        onThemeChange={(newTheme) => setTheme(newTheme)}
        onSwitchPlatform={(p) => {
          setPlatform(p);
          localStorage.setItem('aegis_platform', p);
        }}
      />
    );
  }

  return (
    <div className="soc">
      <aside className="sidebar">
        <div className="brand">
          <span className="logo"><Icon name="shield" size={22} /></span>
          <span className="brand-name">Aegis NAD<small>SOC Console</small></span>
        </div>

        {/* Platform Switcher to WebSec */}
        <div className="platform-switch-box">
          <div className="platform-switch-label">SWITCH PLATFORM</div>
          <button
            className="platform-switch-btn websec-target"
            onClick={() => {
              setPlatform('websec');
              localStorage.setItem('aegis_platform', 'websec');
            }}
            title="Switch to Website Security Monitoring & Vulnerability Assessment Platform"
          >
            <span className="platform-switch-name">
              <Icon name="globe" size={14} /> Website Security (WebSec)
            </span>
            <span className="platform-switch-arrow">Open ➔</span>
          </button>
        </div>

        <nav className="nav">
          {TABS.map(({ id, label, icon }) => (
            <button
              key={id}
              className={tab === id ? 'active' : ''}
              onClick={() => setTab(id)}
              title={label}
            >
              <span className="nav-icon"><Icon name={icon} size={17} /></span>
              <span className="nav-text">{label}</span>
            </button>
          ))}
        </nav>
        <ThemePicker theme={theme} onChange={setTheme} />
        <div className="detectors">
          <b>Active detectors</b>
          <div className="pills">
            {DETECTOR_GROUPS.map((d) => <span className="pill" key={d}>{d}</span>)}
          </div>
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <div>
            <h1>Network Anomaly Detection</h1>
            <div className="topbar-sub">
              Real-time signature ⊕ ML correlation · 30 detectors · threat scoring
            </div>
          </div>
          <div className="topbar-right" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              className="btn btn-primary topbar-add-site-btn"
              onClick={() => {
                setPlatform('websec');
                localStorage.setItem('aegis_platform', 'websec');
              }}
              title="Open Website Security Monitoring & Vulnerability Assessment Platform"
            >
              <Icon name="globe" size={14} /> Website Security Platform ➔
            </button>
            <span className="live">
              <span className="dot" />
              {connected ? 'LIVE' : 'CONNECTING…'}
            </span>
          </div>
        </div>

        <div className="kpis">
          <Kpi label="Throughput" value={`${stats.pps.toFixed(0)}`} sub={`pps · ${stats.packets.toLocaleString()} packets`} accent="var(--blue)" icon="zap" />
          <Kpi label="Active Flows" value={`${stats.active_flows}`} sub="5-tuple tracked" accent="var(--violet)" icon="link" />
          <Kpi label="High / Critical" value={`${crit}`} sub={`${totalAlerts} total alerts`} accent={crit > 0 ? 'var(--crit)' : 'var(--low)'} icon="alert" />
          <div
            onClick={() => {
              setPlatform('websec');
              localStorage.setItem('aegis_platform', 'websec');
            }}
            style={{ cursor: 'pointer' }}
            title="Click to open Website Security Monitoring & Vulnerability Assessment Platform"
          >
            <Kpi
              label="Web Posture"
              value={`${sites.length} site${sites.length === 1 ? '' : 's'}`}
              sub={
                sites.length > 0
                  ? `${Math.round(sites.reduce((a, b) => a + (b.security_score ?? 100), 0) / sites.length)}/100 avg score`
                  : '+ Click to monitor target'
              }
              accent="var(--blue)"
              icon="globe"
            />
          </div>
        </div>

        {(tab === 'Overview' || tab === 'Network') && (
          <>
            <div className="grid2">
              <div className="card">
                <div className="card-head">
                  <h3><span className="icon"><Icon name="chart" size={16} /></span> Live Throughput</h3>
                  <span className="card-sub">{stats.pps.toFixed(0)} pps · {stats.packets.toLocaleString()} packets</span>
                </div>
                <TrafficChart series={series} pps={stats.pps} packets={stats.packets} />
              </div>
              <div className="card">
                <div className="card-head">
                  <h3><span className="icon"><Icon name="palette" size={16} /></span> Protocol Mix</h3>
                </div>
                <ProtocolDonut protocols={protocols} />
              </div>
            </div>
            <div className="grid2-equal">
              <div className="card">
                <div className="card-head">
                  <h3><span className="icon"><Icon name="chart" size={16} /></span> Attack Mix</h3>
                  <span className="card-sub">this session</span>
                </div>
                <AttackMix mix={attackMix} />
              </div>
              <div className="card">
                <div className="card-head">
                  <h3><span className="icon"><Icon name="radio" size={16} /></span> Top Talkers</h3>
                  <span className="card-sub">by bytes</span>
                </div>
                <TopTalkers />
              </div>
            </div>
          </>
        )}

        {tab === 'Network' && (
          <div className="grid2-equal">
            <div className="card">
              <div className="card-head">
                <h3><span className="icon"><Icon name="target" size={16} /></span> Top Offenders</h3>
                <span className="card-sub">by alert count</span>
              </div>
              <TopOffenders alerts={alerts} />
            </div>
            <div className="card">
              <div className="card-head">
                <h3><span className="icon"><Icon name="shield" size={16} /></span> Detection Coverage</h3>
                <span className="card-sub">{Object.values(attackMix).reduce((a, b) => a + b, 0)} fires</span>
              </div>
              <ThreatMatrix attackMix={attackMix} />
            </div>
          </div>
        )}

        {(tab === 'Overview' || tab === 'Alerts') && (
          <div className="card">
            <div className="card-head">
              <h3><span className="icon"><Icon name="alert" size={16} /></span> Threat Alerts</h3>
              <span className="card-sub">{totalAlerts} total</span>
            </div>
            <AlertFeed alerts={alerts} />
          </div>
        )}

        {tab === 'Overview' && (
          <DashboardWebSecWidget
            sites={sites}
            onOpenAddModal={() => setShowAddSiteModal(true)}
            onOpenAudit={(s) => setAuditSite(s)}
            onNavigateToWebSec={() => {
              setPlatform('websec');
              localStorage.setItem('aegis_platform', 'websec');
            }}
          />
        )}

        {tab === 'Threat Intel' && (
          <div style={{ display: 'grid', gap: 14 }}>
            <div className="card">
              <div className="card-head">
                <h3><span className="icon"><Icon name="shield" size={16} /></span> Detection Coverage</h3>
                <span className="card-sub">{Object.values(attackMix).reduce((a, b) => a + b, 0)} fires this session</span>
              </div>
              <ThreatMatrix attackMix={attackMix} />
            </div>
            <div className="card">
              <div className="card-head">
                <h3><span className="icon"><Icon name="target" size={16} /></span> Top Offenders</h3>
              </div>
              <TopOffenders alerts={alerts} />
            </div>
            <div className="card">
              <div className="card-head">
                <h3><span className="icon"><Icon name="note" size={16} /></span> Analyst Notes</h3>
              </div>
              <p className="notes">
                Every alert carries MITRE ATT&amp;CK mapping, confidence, threat score (0–100) and a
                remediation hint. Signature hits are confirmed by the ML flow model (Isolation Forest +
                statistical ensemble, LSTM/Transformer when torch is installed) to suppress false positives.
                Tune thresholds via <code>NAD_*</code> env vars in <code>backend/config.py</code>.
              </p>
            </div>
          </div>
        )}
      </div>

      {showAddSiteModal && (
        <AddSiteModal
          isOpen={showAddSiteModal}
          onClose={() => setShowAddSiteModal(false)}
          onViewAudit={(site) => setAuditSite(site)}
        />
      )}

      {auditSite && (
        <AuditReportModal
          site={auditSite}
          onClose={() => setAuditSite(null)}
          onScanNow={handleScanNow}
        />
      )}
    </div>
  );
}

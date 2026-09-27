import { useState } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import { TrafficChart } from './TrafficChart';
import { ProtocolDonut } from './ProtocolBreakdown';
import { AttackMix } from './AttackMix';
import { AlertFeed } from './AlertPanel';
import { TopTalkers } from './TopTalkers';
import { TopOffenders } from './TopOffenders';
import { ThreatMatrix } from './ThreatMatrix';

const DETECTOR_GROUPS = [
  'Port / Horizontal Scan', 'Ping Sweep', 'SYN/UDP/ICMP Flood', 'DDoS', 'Slowloris',
  'SSH/FTP/RDP/Telnet/HTTP Brute Force', 'Password Spraying',
  'DNS Tunneling', 'ARP Spoofing', 'C2 + Beaconing', 'SMB Lateral Movement',
  'Cryptominer', 'SQLi / XSS / CMDi', 'Log4Shell', 'SSRF', 'Exfiltration', '+ ML Anomaly',
];

function Kpi({ label, value, sub, accent }: { label: string; value: string; sub: string; accent: string }) {
  return (
    <div className="kpi">
      <div className="label">{label}</div>
      <div className="value" style={{ color: accent }}>{value}</div>
      <div className="sub">{sub}</div>
    </div>
  );
}

export function Dashboard() {
  const [tab, setTab] = useState('Overview');
  const wsUrl = `ws://${window.location.hostname}:8000/ws`;
  const { stats, alerts, counts, attackMix, protocols, series, connected } = useWebSocket(wsUrl);
  const crit = (counts.CRITICAL ?? 0) + (counts.HIGH ?? 0);

  return (
    <div className="soc">
      <aside className="sidebar">
        <div className="brand"><span className="logo">🛡️</span><span>Aegis NAD<br /><small style={{ fontWeight: 400, color: '#8b98b4' }}>SOC Console</small></span></div>
        <nav className="nav">
          {['Overview', 'Alerts', 'Network', 'Threat Intel'].map((t) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t === 'Overview' ? '📊' : t === 'Alerts' ? '🚨' : t === 'Network' ? '🌐' : '🧠'} {t}
            </button>
          ))}
        </nav>
        <div className="detectors">
          <b style={{ color: '#e6edf7' }}>Active detectors</b>
          <div style={{ marginTop: 8 }}>{DETECTOR_GROUPS.map((d) => <span className="pill" key={d}>{d}</span>)}</div>
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <div>
            <h1 style={{ margin: 0 }}>Network Anomaly Detection</h1>
            <small style={{ color: '#8b98b4' }}>Real-time signature + ML correlation · signature⊕ML scoring</small>
          </div>
          <span className="live"><span className="dot" />{connected ? 'LIVE' : 'CONNECTING…'}</span>
        </div>

        <div className="kpis">
          <Kpi label="Throughput" value={`${stats.pps.toFixed(0)} pps`} sub={`${stats.packets.toLocaleString()} packets`} accent="#38bdf8" />
          <Kpi label="Active flows" value={`${stats.active_flows}`} sub="5-tuple tracked" accent="#a78bfa" />
          <Kpi label="High / Critical" value={`${crit}`} sub={`total alerts ${alerts.length}`} accent={crit > 0 ? '#ef4444' : '#22c55e'} />
          <Kpi label="Attack classes" value={`${Object.keys(attackMix).length}`} sub="seen this session" accent="#4ade80" />
        </div>

        {(tab === 'Overview' || tab === 'Network') && (
          <>
            <div className="grid2">
              <TrafficChart series={series} pps={stats.pps} packets={stats.packets} />
              <ProtocolDonut protocols={protocols} />
            </div>
            <div className="grid2">
              <AttackMix mix={attackMix} />
              <TopTalkers />
            </div>
          </>
        )}

        {tab === 'Network' && (
          <div className="grid2">
            <TopOffenders alerts={alerts} />
            <ThreatMatrix attackMix={attackMix} />
          </div>
        )}

        {(tab === 'Overview' || tab === 'Alerts') && <AlertFeed alerts={alerts} />}

        {tab === 'Threat Intel' && (
          <div style={{ display: 'grid', gap: 12 }}>
            <ThreatMatrix attackMix={attackMix} />
            <TopOffenders alerts={alerts} />
            <div className="card">
              <h3>Analyst notes</h3>
              <p style={{ color: '#8b98b4', fontSize: 13 }}>
                Every alert carries MITRE ATT&amp;CK mapping, confidence, threat score (0–100) and a
                remediation hint. Signature hits are confirmed by the ML flow model (Isolation Forest +
                statistical ensemble, LSTM/Transformer when torch is installed) to suppress false positives.
                Tune thresholds via <code>NAD_*</code> env vars in <code>backend/config.py</code>.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

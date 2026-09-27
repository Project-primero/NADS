import { useMemo, useState } from 'react';
import type { Alert } from '../types';
import { CATEGORIES, CATEGORY_COLOR, categoryOf } from '../lib/attackMeta';

export function AlertFeed({ alerts }: { alerts: Alert[] }) {
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('ALL');
  const [cat, setCat] = useState('ALL');
  const filtered = useMemo(() => alerts.filter((a) =>
    (sev === 'ALL' || a.severity === sev) &&
    (cat === 'ALL' || categoryOf(a.attack_type) === cat) &&
    (q === '' || JSON.stringify(a).toLowerCase().includes(q.toLowerCase()))), [alerts, q, sev, cat]);

  return (
    <div className="card">
      <h3>Threat Alerts ({filtered.length})</h3>
      <div className="toolbar">
        <input placeholder="Search IP, type, MITRE…" value={q} onChange={(e) => setQ(e.target.value)} style={{ flex: 1 }} />
        <select value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="ALL">All categories</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="ALL">All severities</option>
          <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
        </select>
      </div>
      <div style={{ maxHeight: 420, overflow: 'auto' }}>
        {filtered.map((a, i) => (
          <div key={a.id ?? i} className={`alert ${a.severity[0] + a.severity.slice(1).toLowerCase()}`}>
            <span className={`sev ${a.severity}`}>{a.severity}</span>{' '}
            <span style={{ fontSize: 11, fontWeight: 700, color: CATEGORY_COLOR[categoryOf(a.attack_type)], border: `1px solid ${CATEGORY_COLOR[categoryOf(a.attack_type)]}`, borderRadius: 12, padding: '2px 8px' }}>
              {categoryOf(a.attack_type).toUpperCase()}
            </span>{' '}
            <b>{a.attack_type}</b>{' '}
            <span style={{ fontSize: 12, color: '#8b98b4' }}>{a.mitre ? `MITRE ${a.mitre}` : ''} · score {a.threat_score ?? '—'} · {a.engine}</span>
            <div>{a.description}</div>
            <div className="meta">{a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port} ({a.protocol}) · {new Date(a.timestamp * 1000).toLocaleTimeString()}</div>
            {a.remediation && <div className="fix">🛠 {a.remediation}</div>}
          </div>
        ))}
        {filtered.length === 0 && <p style={{ color: '#8b98b4' }}>No alerts match — network looks clean.</p>}
      </div>
    </div>
  );
}

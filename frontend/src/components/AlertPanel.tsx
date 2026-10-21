import { useMemo, useState } from 'react';
import type { Alert } from '../types';
import { CATEGORIES, CATEGORY_COLOR, categoryOf } from '../lib/attackMeta';
import { Icon } from './Icon';

export function AlertFeed({ alerts }: { alerts: Alert[] }) {
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('ALL');
  const [cat, setCat] = useState('ALL');
  const filtered = useMemo(() => alerts.filter((a) =>
    (sev === 'ALL' || a.severity === sev) &&
    (cat === 'ALL' || categoryOf(a.attack_type) === cat) &&
    (q === '' || JSON.stringify(a).toLowerCase().includes(q.toLowerCase()))), [alerts, q, sev, cat]);

  return (
    <div>
      <div className="toolbar">
        <input placeholder="Search IP, type, MITRE…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={cat} onChange={(e) => setCat(e.target.value)}>
          <option value="ALL">All categories</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="ALL">All severities</option>
          <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
        </select>
      </div>
      <div className="alert-feed">
        {filtered.map((a, i) => {
          const category = categoryOf(a.attack_type);
          const catColor = CATEGORY_COLOR[category];
          return (
            <div key={a.id ?? i} className={`alert ${a.severity[0] + a.severity.slice(1).toLowerCase()}`}>
              <div className="alert-row">
                <span className={`sev ${a.severity}`}>{a.severity}</span>
                <span className="cat-badge" style={{ color: catColor, borderColor: catColor,
                  background: `color-mix(in srgb, ${catColor} 10%, transparent)` }}>
                  {category.toUpperCase()}
                </span>
                <span className="alert-title">{a.attack_type}</span>
                {a.threat_score != null && (
                  <span className="alert-score">score {a.threat_score}</span>
                )}
              </div>
              <div className="alert-desc">{a.description}</div>
              <div className="alert-meta">
                <code>{a.src_ip}:{a.src_port}</code>
                <span>→</span>
                <code>{a.dst_ip}:{a.dst_port}</code>
                <span>·</span>
                <span>{a.protocol}</span>
                {a.mitre && (<><span>·</span><span>{a.mitre}</span></>)}
                {a.engine && (<><span>·</span><span>{a.engine}</span></>)}
                <span>·</span>
                <span>{new Date(a.timestamp * 1000).toLocaleTimeString()}</span>
              </div>
              {a.remediation && (
                <div className="alert-fix">🛠 {a.remediation}</div>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div className="empty-state">
            <div className="icon"><Icon name="shield" size={28} /></div>
            <p>No alerts match — network looks clean</p>
          </div>
        )}
      </div>
    </div>
  );
}

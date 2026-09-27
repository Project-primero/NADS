import { useMemo } from 'react';
import type { Alert } from '../types';
import { categoryOf } from '../lib/attackMeta';

const SEV_RANK: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

// Top attacker IPs derived from the live alert stream.
export function TopOffenders({ alerts }: { alerts: Alert[] }) {
  const rows = useMemo(() => {
    const m = new Map<string, { count: number; maxSev: string; rank: number; cats: Set<string> }>();
    for (const a of alerts) {
      const e = m.get(a.src_ip) ?? { count: 0, maxSev: 'LOW', rank: 0, cats: new Set<string>() };
      e.count += 1;
      e.cats.add(categoryOf(a.attack_type));
      if ((SEV_RANK[a.severity] ?? 0) > e.rank) { e.rank = SEV_RANK[a.severity]; e.maxSev = a.severity; }
      m.set(a.src_ip, e);
    }
    return [...m.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 8);
  }, [alerts]);
  const max = Math.max(1, ...rows.map(([, r]) => r.count));

  return (
    <div className="card">
      <h3>Top Offenders (by alert count)</h3>
      {rows.length === 0 ? <p style={{ color: '#8b98b4' }}>No offenders yet.</p> : (
        <table className="talkers">
          <thead><tr><th>Attacker IP</th><th>Alerts</th><th>Peak</th><th>Categories</th><th></th></tr></thead>
          <tbody>
            {rows.map(([ip, r]) => (
              <tr key={ip}>
                <td><code>{ip}</code></td>
                <td>{r.count}</td>
                <td><span className={`sev ${r.maxSev}`}>{r.maxSev}</span></td>
                <td style={{ fontSize: 11, color: '#8b98b4' }}>{[...r.cats].join(', ')}</td>
                <td style={{ width: 80 }}><div className="bar" style={{ width: `${(r.count / max) * 100}%` }} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

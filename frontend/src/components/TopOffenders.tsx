import { useMemo } from 'react';
import type { Alert } from '../types';
import { categoryOf } from '../lib/attackMeta';
import { Icon } from './Icon';

const SEV_RANK: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

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

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon"><Icon name="target" size={28} /></div>
        <p>No offenders yet — monitoring…</p>
      </div>
    );
  }

  return (
    <table className="talkers">
      <thead>
        <tr><th>Attacker</th><th>Alerts</th><th>Peak</th><th>Categories</th><th style={{ width: 70 }}></th></tr>
      </thead>
      <tbody>
        {rows.map(([ip, r]) => (
          <tr key={ip}>
            <td><code>{ip}</code></td>
            <td className="num">{r.count}</td>
            <td><span className={`sev ${r.maxSev}`}>{r.maxSev}</span></td>
            <td className="muted">{[...r.cats].join(', ')}</td>
            <td>
              <div className="bar-track">
                <div className="bar" style={{ width: `${(r.count / max) * 100}%` }} />
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

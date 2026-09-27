import { useEffect, useMemo, useState } from 'react';
import { CATEGORIES, CATEGORY_COLOR, categoryOf } from '../lib/attackMeta';

interface Detector { attack: string; severity: string; mitre: string; remediation: string; }

export function ThreatMatrix({ attackMix }: { attackMix: Record<string, number> }) {
  const [detectors, setDetectors] = useState<Detector[]>([]);
  useEffect(() => {
    fetch('/api/catalog').then((r) => r.json()).then((j) => setDetectors(j.detectors ?? [])).catch(() => {});
  }, []);

  const mlFires = useMemo(
    () => Object.entries(attackMix).filter(([k]) => k.startsWith('Anomaly'))
      .reduce((a, [, v]) => a + v, 0),
    [attackMix]);

  const grouped = useMemo(() => {
    const g = new Map<string, Detector[]>();
    for (const d of detectors) {
      const c = categoryOf(d.attack);
      if (!g.has(c)) g.set(c, []);
      g.get(c)!.push(d);
    }
    return g;
  }, [detectors]);

  const totalFires = Object.values(attackMix).reduce((a, b) => a + b, 0);

  return (
    <div className="card">
      <h3>Detection Coverage — {detectors.length} detectors · {totalFires} fires this session</h3>
      {CATEGORIES.map((cat) => {
        const list = grouped.get(cat) ?? [];
        if (list.length === 0 && cat !== 'ML') return null;
        const catFires = cat === 'ML'
          ? mlFires
          : list.reduce((a, d) => a + (attackMix[d.attack] ?? 0), 0);
        return (
          <div key={cat} style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: CATEGORY_COLOR[cat] }} />
              <b style={{ fontSize: 13 }}>{cat}</b>
              <span style={{ fontSize: 12, color: '#8b98b4' }}>
                {cat === 'ML' ? mlFires : `${list.length} detectors`} · {catFires} fires
              </span>
            </div>
            <div className="mitre">
              {list.map((d) => {
                const fires = attackMix[d.attack] ?? 0;
                return (
                  <div className="cell" key={d.attack} style={{ opacity: fires > 0 ? 1 : 0.65 }} title={d.remediation}>
                    <b>{d.attack} {fires > 0 && <span style={{ color: '#4ade80' }}>· {fires}×</span>}</b>
                    <span className={`sev ${d.severity}`} style={{ fontSize: 10 }}>{d.severity}</span>{' '}
                    <span style={{ color: '#8b98b4' }}>{d.mitre}</span>
                  </div>
                );
              })}
              {cat === 'ML' && (
                <div className="cell" title="Isolation Forest ensemble over 41 flow features">
                  <b>ML Anomaly {mlFires > 0 && <span style={{ color: '#4ade80' }}>· {mlFires}×</span>}</b>
                  <span className="sev HIGH" style={{ fontSize: 10 }}>ADAPTIVE</span>{' '}
                  <span style={{ color: '#8b98b4' }}>T1498/T1071</span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

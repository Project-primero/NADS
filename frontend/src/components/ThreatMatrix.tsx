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

  return (
    <div>
      {CATEGORIES.map((cat) => {
        const list = grouped.get(cat) ?? [];
        if (list.length === 0 && cat !== 'ML') return null;
        const catFires = cat === 'ML'
          ? mlFires
          : list.reduce((a, d) => a + (attackMix[d.attack] ?? 0), 0);
        return (
          <div key={cat} className="cat-section">
            <div className="cat-header">
              <span className="cat-dot" style={{ background: CATEGORY_COLOR[cat] }} />
              <span className="cat-name">{cat}</span>
              <span className="cat-meta">
                {cat === 'ML' ? 'adaptive' : `${list.length} detectors`} · {catFires} fires
              </span>
            </div>
            <div className="mitre">
              {list.map((d) => {
                const fires = attackMix[d.attack] ?? 0;
                return (
                  <div className="cell" key={d.attack} style={{ opacity: fires > 0 ? 1 : 0.6 }} title={d.remediation}>
                    <b>{d.attack}{fires > 0 && <span className="fires"> · {fires}×</span>}</b>
                    <span className={`sev ${d.severity}`} style={{ fontSize: 9 }}>{d.severity}</span>{' '}
                    <span className="meta">{d.mitre}</span>
                  </div>
                );
              })}
              {cat === 'ML' && (
                <div className="cell" title="Isolation Forest ensemble over 41 flow features">
                  <b>ML Anomaly{mlFires > 0 && <span className="fires"> · {mlFires}×</span>}</b>
                  <span className="sev HIGH" style={{ fontSize: 9 }}>ADAPTIVE</span>{' '}
                  <span className="meta">T1498/T1071</span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

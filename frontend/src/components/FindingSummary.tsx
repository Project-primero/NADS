import type { SiteFinding } from '../types';
import { Icon } from './Icon';

interface FindingSummaryProps {
  findings: SiteFinding[];
  compact?: boolean;
}

export function FindingSummary({ findings, compact = false }: FindingSummaryProps) {
  const counts: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  for (const f of findings) {
    const s = f.severity?.toUpperCase() || 'LOW';
    counts[s] = (counts[s] ?? 0) + 1;
  }

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
  const activeSeverities = severities.filter((s) => counts[s] > 0);

  if (activeSeverities.length === 0) {
    return (
      <div className="finding-summary-pills clean">
        <span className="sev-pill clean">
          <Icon name="check" size={12} /> Hardened · No Vulnerabilities
        </span>
      </div>
    );
  }

  return (
    <div className={`finding-summary-pills ${compact ? 'compact' : ''}`}>
      {activeSeverities.map((sev) => {
        const count = counts[sev];
        return (
          <span
            key={sev}
            className={`sev-pill sev ${sev}`}
            title={`${count} ${sev} findings`}
          >
            <span className="sev-pill-count">{count}</span>
            <span className="sev-pill-name">{sev}</span>
          </span>
        );
      })}
    </div>
  );
}

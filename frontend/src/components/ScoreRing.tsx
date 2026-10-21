import type { CSSProperties } from 'react';

interface ScoreRingProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  showGrade?: boolean;
  isUp?: boolean | null;
}

export function getGrade(score: number, isUp?: boolean | null): { grade: string; color: string; label: string } {
  if (isUp === false) {
    return { grade: 'F', color: 'var(--crit)', label: 'Host Offline' };
  }
  if (isUp === null || isUp === undefined) {
    return { grade: '—', color: 'var(--muted)', label: 'Pending Audit' };
  }
  if (score >= 95) return { grade: 'A+', color: 'var(--low)', label: 'Hardened' };
  if (score >= 85) return { grade: 'A', color: 'var(--low)', label: 'Strong' };
  if (score >= 70) return { grade: 'B', color: 'var(--med)', label: 'Moderate' };
  if (score >= 50) return { grade: 'C', color: 'var(--med)', label: 'Degraded' };
  if (score >= 35) return { grade: 'D', color: 'var(--high)', label: 'At Risk' };
  return { grade: 'F', color: 'var(--crit)', label: 'Critical Risk' };
}

export function ScoreRing({
  score,
  size = 68,
  strokeWidth = 7,
  showGrade = true,
  isUp,
}: ScoreRingProps) {
  const isOffline = isUp === false;
  const isPending = isUp === null || (isUp === undefined && score === 0);
  const boundedScore = isOffline ? 0 : Math.max(0, Math.min(100, Math.round(score)));
  const { grade, color, label } = getGrade(boundedScore, isUp !== undefined ? isUp : true);
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = isOffline || isPending
    ? circumference
    : circumference - (boundedScore / 100) * circumference;

  return (
    <div
      className="score-ring-container"
      title={`Security Score: ${boundedScore}/100 (${label} - Grade ${grade})`}
      style={{ width: size, height: size, position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
    >
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        {/* Track circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeWidth}
          opacity={0.5}
        />
        {/* Progress Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          style={{
            transition: 'stroke-dashoffset 0.6s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.3s ease',
          }}
        />
      </svg>
      <div
        className="score-ring-label"
        style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none',
        }}
      >
        <span
          style={{
            fontSize: size * 0.28,
            fontWeight: 800,
            lineHeight: 1,
            color,
            fontFamily: 'monospace, system-ui',
          }}
        >
          {isPending ? '—' : boundedScore}
        </span>
        {showGrade && (
          <span
            style={{
              fontSize: size * 0.16,
              fontWeight: 700,
              color: 'var(--muted)',
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
              marginTop: 1,
            }}
          >
            {grade}
          </span>
        )}
      </div>
    </div>
  );
}

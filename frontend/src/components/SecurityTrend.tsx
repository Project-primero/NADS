import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import type { TrendPoint } from '../types';

interface SecurityTrendProps {
  data: TrendPoint[];
  height?: number;
}

export function SecurityTrend({ data, height = 75 }: SecurityTrendProps) {
  if (!data || data.length === 0) {
    return (
      <div className="trend-empty" style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', color: 'var(--muted)' }}>
        No historical audit data yet
      </div>
    );
  }

  // Format data for Recharts
  const formatted = data.map((d) => ({
    time: new Date(d.ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    score: d.score,
    latency: d.latency,
    status: d.up ? 'UP' : 'DOWN',
    findings: d.findings_count ?? 0,
  }));

  const latestScore = data[data.length - 1]?.score ?? 100;
  const strokeColor = latestScore >= 80 ? 'var(--low)' : latestScore >= 50 ? 'var(--med)' : 'var(--crit)';

  return (
    <div className="security-trend-chart" style={{ width: '100%', height }}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={formatted} margin={{ top: 4, right: 6, left: -25, bottom: 0 }}>
          <defs>
            <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={strokeColor} stopOpacity={0.4} />
              <stop offset="95%" stopColor={strokeColor} stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <XAxis dataKey="time" hide />
          <YAxis domain={[0, 100]} hide />
          <Tooltip
            contentStyle={{
              background: 'var(--card2)',
              borderColor: 'var(--border)',
              borderRadius: '6px',
              color: 'var(--text)',
              fontSize: '0.75rem',
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
              padding: '6px 10px',
            }}
            formatter={(value: any, name: string) => {
              if (name === 'score') return [`${value}/100`, 'Security Score'];
              if (name === 'latency') return [`${value}ms`, 'Latency'];
              return [value, name];
            }}
            labelFormatter={(label) => `Scan at ${label}`}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke={strokeColor}
            strokeWidth={2}
            fill="url(#scoreGrad)"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

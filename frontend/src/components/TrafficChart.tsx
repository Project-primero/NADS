import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import type { SeriesPoint } from '../types';

export function TrafficChart({ series }: { series: SeriesPoint[]; pps: number; packets: number }) {
  const data = series.map((s) => ({ t: new Date(s.ts * 1000).toLocaleTimeString(), pps: s.pps }));
  const live = data.length ? data : [{ t: 'now', pps: 0 }];
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={live} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--blue)" stopOpacity={0.35} />
            <stop offset="100%" stopColor="var(--blue)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--border)" strokeDasharray="4 4" vertical={false} />
        <XAxis dataKey="t" tick={{ fill: 'var(--muted)', fontSize: 11 }} minTickGap={40}
          axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} width={50} />
        <Tooltip
          contentStyle={{ background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 10, boxShadow: '0 4px 16px rgba(0,0,0,.08)', color: 'var(--text)', fontSize: 12 }}
          labelStyle={{ color: 'var(--muted)', fontSize: 11 }}
          formatter={(v: number) => [`${v.toFixed(1)} pps`, 'Throughput']}
        />
        <Area type="monotone" dataKey="pps" stroke="var(--blue)" strokeWidth={2.5}
          fill="url(#ppsGrad)" animationDuration={600} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

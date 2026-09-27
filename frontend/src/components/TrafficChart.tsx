import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import type { SeriesPoint } from '../types';

export function TrafficChart({ series, pps, packets }: { series: SeriesPoint[]; pps: number; packets: number }) {
  const data = series.map((s) => ({ t: new Date(s.ts * 1000).toLocaleTimeString(), pps: s.pps }));
  const live = data.length ? data : [{ t: 'now', pps }];
  return (
    <div className="card">
      <h3>Live Throughput — {pps.toFixed(0)} pps · {packets.toLocaleString()} packets</h3>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={live}>
          <CartesianGrid stroke="#16203a" strokeDasharray="3 3" />
          <XAxis dataKey="t" tick={{ fill: '#8b98b4', fontSize: 11 }} minTickGap={30} />
          <YAxis tick={{ fill: '#8b98b4', fontSize: 11 }} />
          <Tooltip contentStyle={{ background: '#0b1220', border: '1px solid #1e2a45' }} />
          <Area type="monotone" dataKey="pps" stroke="#38bdf8" fill="#38bdf833" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

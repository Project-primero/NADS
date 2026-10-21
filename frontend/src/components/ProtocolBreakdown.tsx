import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { Icon } from './Icon';

const COLORS = ['var(--blue)', 'var(--violet)', 'var(--low)', 'var(--med)', 'var(--high)', 'var(--crit)'];

export function ProtocolDonut({ protocols }: { protocols: Record<string, number> }) {
  const data = Object.entries(protocols).map(([name, value]) => ({ name, value }));
  if (data.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon"><Icon name="palette" size={28} /></div>
        <p>Collecting traffic…</p>
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={58} outerRadius={88}
          paddingAngle={3} strokeWidth={0} animationDuration={600}>
          {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip
          contentStyle={{ background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 10, boxShadow: '0 4px 16px rgba(0,0,0,.08)', color: 'var(--text)', fontSize: 12 }}
          formatter={(v: number, name: string) => [v.toLocaleString(), name]}
        />
        <Legend iconType="circle" iconSize={8}
          formatter={(value: string) => <span style={{ color: 'var(--muted)', fontSize: 12 }}>{value}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}

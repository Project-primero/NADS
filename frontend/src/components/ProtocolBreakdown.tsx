import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const COLORS = ['#38bdf8', '#a78bfa', '#4ade80', '#fbbf24', '#f87171', '#94a3b8'];

export function ProtocolDonut({ protocols }: { protocols: Record<string, number> }) {
  const data = Object.entries(protocols).map(([name, value]) => ({ name, value }));
  return (
    <div className="card">
      <h3>Protocol Mix</h3>
      {data.length === 0 ? <p style={{ color: '#8b98b4' }}>Collecting…</p> : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3}>
              {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
            </Pie>
            <Tooltip contentStyle={{ background: '#0b1220', border: '1px solid #1e2a45' }} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

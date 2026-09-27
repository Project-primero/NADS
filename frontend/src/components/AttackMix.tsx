import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';

const colorFor = (n: string) =>
  /DDoS|C2|Exfiltration/i.test(n) ? '#ef4444' : /Brute|SYN|Scan|SQL|Traversal/i.test(n) ? '#f97316' : '#eab308';

export function AttackMix({ mix }: { mix: Record<string, number> }) {
  const data = Object.entries(mix).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([name, count]) => ({ name: name.length > 14 ? name.slice(0, 14) + '…' : name, count, full: name }));
  return (
    <div className="card">
      <h3>Attack Mix (session)</h3>
      {data.length === 0 ? <p style={{ color: '#8b98b4' }}>No attacks yet — monitoring…</p> : (
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={data} layout="vertical">
            <CartesianGrid stroke="#16203a" strokeDasharray="3 3" />
            <XAxis type="number" tick={{ fill: '#8b98b4', fontSize: 11 }} />
            <YAxis type="category" dataKey="name" width={110} tick={{ fill: '#e6edf7', fontSize: 11 }} />
            <Tooltip contentStyle={{ background: '#0b1220', border: '1px solid #1e2a45' }} />
            <Bar dataKey="count">{data.map((d, i) => <Cell key={i} fill={colorFor(d.full)} />)}</Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

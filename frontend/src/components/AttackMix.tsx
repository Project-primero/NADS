import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell } from 'recharts';
import { Icon } from './Icon';

const colorFor = (n: string) =>
  /DDoS|C2|Exfiltration/i.test(n) ? 'var(--crit)' : /Brute|SYN|Scan|SQL|Traversal/i.test(n) ? 'var(--high)' : 'var(--med)';

export function AttackMix({ mix }: { mix: Record<string, number> }) {
  const data = Object.entries(mix).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([name, count]) => ({ name: name.length > 16 ? name.slice(0, 16) + '…' : name, count, full: name }));
  if (data.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon"><Icon name="shield" size={28} /></div>
        <p>No attacks yet — network looks clean</p>
      </div>
    );
  }
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid stroke="var(--border)" strokeDasharray="4 4" horizontal={false} />
        <XAxis type="number" tick={{ fill: 'var(--muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="name" width={120} tick={{ fill: 'var(--text)', fontSize: 11.5 }}
          axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: 'var(--card)', border: '1px solid var(--border)',
            borderRadius: 10, boxShadow: '0 4px 16px rgba(0,0,0,.08)', color: 'var(--text)', fontSize: 12 }}
          formatter={(v: number) => [v.toLocaleString(), 'Fires']}
          labelFormatter={(l: string) => {
            const d = data.find((x) => x.name === l);
            return d?.full ?? l;
          }}
        />
        <Bar dataKey="count" radius={[0, 5, 5, 0]} barSize={16} animationDuration={600}>
          {data.map((d, i) => <Cell key={i} fill={colorFor(d.full)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

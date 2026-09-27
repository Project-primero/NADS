import { useTopTalkers } from '../hooks/useWebSocket';

export function TopTalkers() {
  const talkers = useTopTalkers();
  const max = Math.max(1, ...talkers.map((t) => t.bytes));
  return (
    <div className="card">
      <h3>Top Talkers (by bytes)</h3>
      <table className="talkers">
        <thead><tr><th>IP</th><th>Packets</th><th>Bytes</th><th></th></tr></thead>
        <tbody>
          {talkers.slice(0, 8).map((t) => (
            <tr key={t.ip}>
              <td><code>{t.ip}</code></td><td>{t.packets.toLocaleString()}</td>
              <td>{(t.bytes / 1024).toFixed(1)} KB</td>
              <td style={{ width: 90 }}><div className="bar" style={{ width: `${(t.bytes / max) * 100}%` }} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {talkers.length === 0 && <p style={{ color: '#8b98b4' }}>Collecting…</p>}
    </div>
  );
}

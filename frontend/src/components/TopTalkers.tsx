import { useTopTalkers } from '../hooks/useWebSocket';
import { Icon } from './Icon';

export function TopTalkers() {
  const talkers = useTopTalkers();
  const max = Math.max(1, ...talkers.map((t) => t.bytes));
  if (talkers.length === 0) {
    return (
      <div className="empty-state">
        <div className="icon"><Icon name="radio" size={28} /></div>
        <p>Collecting traffic data…</p>
      </div>
    );
  }
  return (
    <table className="talkers">
      <thead>
        <tr><th>IP Address</th><th>Packets</th><th>Bytes</th><th style={{ width: 90 }}></th></tr>
      </thead>
      <tbody>
        {talkers.slice(0, 8).map((t) => (
          <tr key={t.ip}>
            <td><code>{t.ip}</code></td>
            <td className="num">{t.packets.toLocaleString()}</td>
            <td className="num">{(t.bytes / 1024).toFixed(1)} KB</td>
            <td>
              <div className="bar-track">
                <div className="bar" style={{ width: `${(t.bytes / max) * 100}%` }} />
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

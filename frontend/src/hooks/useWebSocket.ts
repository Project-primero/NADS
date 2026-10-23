import { useEffect, useRef, useState } from 'react';
import type { Alert, ConnectStatus, SeriesPoint, Site } from '../types';

interface Snapshot {
  packets: number; pps: number; active_flows: number;
  alerts: Alert[]; counts: Record<string, number>;
  attack_mix: Record<string, number>; protocols: Record<string, number>;
  series: SeriesPoint[]; sites: Site[];
  connect?: ConnectStatus;
  learning_mode?: boolean;
  online_agents?: number;
  total_agents?: number;
}

export function useWebSocket(url: string) {
  const [stats, setStats] = useState({ packets: 0, pps: 0, active_flows: 0 });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [attackMix, setAttackMix] = useState<Record<string, number>>({});
  const [protocols, setProtocols] = useState<Record<string, number>>({});
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [connectStatus, setConnectStatus] = useState<ConnectStatus | null>(null);
  const [learningMode, setLearningMode] = useState(false);
  const [onlineAgents, setOnlineAgents] = useState(0);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let sock: WebSocket | null = null;
    let closed = false;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout>;
    const connect = () => {
      sock = new WebSocket(url);
      sock.onopen = () => { setConnected(true); attempt = 0; };
      sock.onclose = () => {
        setConnected(false);
        if (!closed) {
          attempt += 1;
          timer = setTimeout(connect, Math.min(1000 * 2 ** attempt, 15000));
        }
      };
      sock.onmessage = (e) => {
        try {
          const m = JSON.parse(e.data);
          if (m.type === 'stats') {
            const s = m as Snapshot;
            setStats({ packets: s.packets, pps: s.pps, active_flows: s.active_flows });
            setAlerts(s.alerts ?? []);
            setCounts(s.counts ?? {});
            setAttackMix(s.attack_mix ?? {});
            setProtocols(s.protocols ?? {});
            setSeries(s.series ?? []);
            setSites(s.sites ?? []);
            if (s.connect) setConnectStatus(s.connect);
            if (typeof s.learning_mode === 'boolean') setLearningMode(s.learning_mode);
            if (typeof s.online_agents === 'number') setOnlineAgents(s.online_agents);
          } else if (m.type === 'alert') {
            setAlerts((a) => [m as Alert, ...a].slice(0, 100));
          }
        } catch { /* ignore */ }
      };
    };
    const ping = setInterval(() => { if (sock && sock.readyState === 1) sock.send('ping'); }, 10000);
    connect();
    return () => { closed = true; clearTimeout(timer); clearInterval(ping); sock?.close(); };
  }, [url]);

  return {
    stats, alerts, counts, attackMix, protocols, series, sites,
    connectStatus, learningMode, onlineAgents, connected
  };
}

export function useTopTalkers() {
  const [talkers, setTalkers] = useState<{ ip: string; bytes: number; packets: number }[]>([]);
  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const r = await fetch('/api/analytics/top-talkers');
        const j = await r.json();
        setTalkers(j.talkers ?? []);
      } catch { /* offline */ }
    }, 3000);
    return () => clearInterval(t);
  }, []);
  return talkers;
}

export function useSiteTrend(siteId: number | null) {
  const [trend, setTrend] = useState<import('../types').TrendPoint[]>([]);
  useEffect(() => {
    if (!siteId) {
      setTrend([]);
      return;
    }
    let cancelled = false;
    const fetchTrend = async () => {
      try {
        const r = await fetch(`/api/sites/${siteId}/trend?limit=48`);
        if (r.ok) {
          const j = await r.json();
          if (!cancelled) setTrend(j.trend ?? []);
        }
      } catch { /* ignore */ }
    };
    fetchTrend();
    const interval = setInterval(fetchTrend, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [siteId]);
}

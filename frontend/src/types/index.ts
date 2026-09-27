export interface Alert {
  id?: number;
  timestamp: number;
  attack_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence?: number;
  mitre?: string;
  remediation?: string;
  description: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  engine?: string;
  anomaly_score?: number;
  threat_score?: number;
}

export interface Stats {
  packets: number;
  pps: number;
  active_flows: number;
}

export interface SeriesPoint { ts: number; pps: number; packets: number; }

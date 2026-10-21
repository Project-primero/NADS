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

export interface SiteFinding {
  title: string;
  severity: string;
  description: string;
  remediation: string;
  mitre: string;
  cwe?: string;
  category?: string;
  evidence?: string;
  confidence?: number;
}

export interface Site {
  id: number;
  name: string;
  url: string;
  enabled: boolean;
  interval: number;
  check_interval_sec?: number;
  up: boolean | null;
  status_code: number;
  latency_ms: number;
  error: string;
  tls_days_left: number;
  tls_issuer: string;
  tls_proto?: string;
  tls_cipher?: string;
  security_score: number;
  server_banner: string;
  technology?: string;
  headers?: Record<string, string>;
  tls_valid?: boolean;
  findings: SiteFinding[];
  uptime_24h: number;
}

export interface SiteCheck {
  id: number;
  site_id: number;
  ts: number;
  up: boolean;
  status_code: number;
  latency_ms: number;
  error: string;
  tls_days_left: number;
  tls_issuer: string;
  tls_valid: boolean;
  tls_proto?: string;
  tls_cipher?: string;
  security_score: number;
  server_banner: string;
  technology?: string;
  headers: Record<string, string>;
  findings: SiteFinding[];
}

export interface TrendPoint {
  id?: number;
  ts: number;
  score: number;
  up: boolean;
  latency: number;
  status_code?: number;
  findings_count?: number;
  critical_high_count?: number;
}

export interface SiteSummaryKpis {
  total_sites: number;
  avg_security_score: number;
  up_count: number;
  down_count: number;
  critical_high_count: number;
  tls_expiring_count: number;
  avg_uptime_24h: number;
}

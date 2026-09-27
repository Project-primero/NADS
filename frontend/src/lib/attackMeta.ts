// Shared attack metadata: category + color per attack type.
// Backend names ("Port Scan", "Anomaly (HIGH)", …) map to SOC categories.

export const CATEGORIES = [
  'Recon', 'DoS', 'Auth', 'DNS & Exfil', 'Lateral & C2', 'Web', 'ML',
] as const;

export type Category = (typeof CATEGORIES)[number];

export const CATEGORY_COLOR: Record<Category, string> = {
  Recon: '#38bdf8',
  DoS: '#ef4444',
  Auth: '#f97316',
  'DNS & Exfil': '#a78bfa',
  'Lateral & C2': '#f43f5e',
  Web: '#eab308',
  ML: '#22c55e',
};

const MAP: Record<string, Category> = {
  'Port Scan': 'Recon',
  'Horizontal Scan': 'Recon',
  'Ping Sweep': 'Recon',
  'Null/Xmas Scan': 'Recon',
  'SYN Flood': 'DoS',
  'UDP Flood': 'DoS',
  'UDP Amplification': 'DoS',
  'ICMP Flood': 'DoS',
  Slowloris: 'DoS',
  DDoS: 'DoS',
  'SSH Brute Force': 'Auth',
  'FTP Brute Force': 'Auth',
  'RDP Brute Force': 'Auth',
  'Telnet Brute Force': 'Auth',
  'HTTP Brute Force': 'Auth',
  'Password Spraying': 'Auth',
  'DNS Tunneling': 'DNS & Exfil',
  'DNS Exfiltration': 'DNS & Exfil',
  'Data Exfiltration': 'DNS & Exfil',
  'ARP Spoofing': 'Lateral & C2',
  'Malware C2': 'Lateral & C2',
  'C2 Beaconing': 'Lateral & C2',
  'SMB Lateral Movement': 'Lateral & C2',
  Cryptominer: 'Lateral & C2',
  'SQL Injection': 'Web',
  'XSS Attempt': 'Web',
  'Path Traversal': 'Web',
  'Command Injection': 'Web',
  Log4Shell: 'Web',
  'SSRF Attempt': 'Web',
};

export function categoryOf(attack: string): Category {
  if (attack.startsWith('Anomaly')) return 'ML';
  return MAP[attack] ?? 'ML';
}

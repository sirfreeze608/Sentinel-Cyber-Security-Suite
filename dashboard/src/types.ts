export interface Threat {
  id: string;
  type: 'Malware' | 'Phishing' | 'Network' | 'Social';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  timestamp: string;
  source: string;
  status: 'Detected' | 'Analyzing' | 'Mitigated';
  description: string;
}

export interface NetworkLog {
  timestamp: string;
  sourceIp: string;
  destIp: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  threatLevel: number;
}

export interface OSINTTool {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'Infrastructure' | 'Identity' | 'Intelligence';
  isActive: boolean;
}

export interface Agent {
  id: number;
  agent_id: string;
  hostname: string;
  os_platform: string;
  agent_version: string;
  is_online: boolean;
  last_seen: string | null;
  total_scans: number;
  total_threats: number;
  total_quarantined: number;
  created_at: string | null;
}

export interface ScanResult {
  id: number;
  agent_id: string;
  file_path: string;
  file_name: string;
  file_hash: string;
  file_size: number;
  status: string;
  threat_level: string;
  positives: number;
  total: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  action: string;
  quarantine_path: string | null;
  scanned_at: string | null;
}

export interface QuarantineItem {
  id: number;
  agent_id: string;
  original_path: string;
  quarantine_path: string;
  file_hash: string;
  reason: string;
  quarantined_at: string | null;
  restored: boolean;
  restored_at: string | null;
}

export interface Policy {
  id: number;
  name: string;
  description: string | null;
  auto_quarantine: boolean;
  skip_system_dirs: boolean;
  max_file_size_mb: number;
  cache_ttl_hours: number;
  malicious_threshold: number;
  high_risk_threshold: number;
  critical_threshold: number;
  is_active: boolean;
  applies_to: string;
  created_at: string | null;
  updated_at: string | null;
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string | null;
  last_login: string | null;
}

export interface DashboardStats {
  total_agents: number;
  online_agents: number;
  total_scans: number;
  total_threats: number;
  total_quarantined: number;
  by_status: Record<string, number>;
  by_threat_level: Record<string, number>;
  recent_scans: ScanResult[];
}

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
}

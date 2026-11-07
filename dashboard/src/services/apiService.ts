import axios, { AxiosInstance } from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const api: AxiosInstance = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token');
  if (token) {
    config.headers.Authorization = 'Bearer ' + token;
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sentinel_token');
      localStorage.removeItem('sentinel_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  },
);

// ---- Auth ----
export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: AuthUser;
}

export function login(creds: LoginCredentials): Promise<LoginResponse> {
  return api.post('/api/auth/login', creds).then((r) => r.data);
}

export function getMe(): Promise<{ user: AuthUser }> {
  return api.get('/api/auth/me').then((r) => r.data);
}

export function getRoles(): Promise<{ roles: Record<string, string> }> {
  return api.get('/api/auth/roles').then((r) => r.data);
}

// ---- Users ----
export interface UserListResponse { users: AuthUser[]; }
export function listUsers(): Promise<UserListResponse> {
  return api.get('/api/users').then((r) => r.data);
}
export function createUser(data: { username: string; email: string; password: string; role: string }): Promise<{ user: AuthUser }> {
  return api.post('/api/users', data).then((r) => r.data);
}
export function updateUser(id: number, data: any): Promise<{ user: AuthUser }> {
  return api.put('/api/users/' + id, data).then((r) => r.data);
}
export function deleteUser(id: number): Promise<{ message: string }> {
  return api.delete('/api/users/' + id).then((r) => r.data);
}

// ---- Agents ----
export interface AgentListResponse { agents: Agent[]; }
export function listAgents(): Promise<AgentListResponse> {
  return api.get('/api/agents').then((r) => r.data);
}
export function getAgent(agentId: string): Promise<{ agent: Agent }> {
  return api.get('/api/agents/' + agentId).then((r) => r.data);
}

// ---- Scans ----
export interface ScanListResponse {
  scans: ScanResult[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}
export function listScans(params?: {
  page?: number; per_page?: number; status?: string;
  threat_level?: string; agent_id?: string;
}): Promise<ScanListResponse> {
  return api.get('/api/scans', { params }).then((r) => r.data);
}
export function getScan(id: number): Promise<{ scan: ScanResult }> {
  return api.get('/api/scans/' + id).then((r) => r.data);
}

// ---- Quarantine ----
export interface QuarantineListResponse { quarantine: QuarantineItem[]; }
export function listQuarantine(agentId?: string): Promise<QuarantineListResponse> {
  return api.get('/api/quarantine', { params: agentId ? { agent_id: agentId } : undefined })
    .then((r) => r.data);
}
export function restoreQuarantine(id: number, destination: string): Promise<{ message: string; item: QuarantineItem }> {
  return api.post('/api/quarantine/' + id + '/restore', { destination }).then((r) => r.data);
}
export function deleteQuarantine(id: number): Promise<{ message: string }> {
  return api.post('/api/quarantine/' + id + '/delete').then((r) => r.data);
}

// ---- Policies ----
export interface PolicyListResponse { policies: Policy[]; }
export function listPolicies(): Promise<PolicyListResponse> {
  return api.get('/api/policies').then((r) => r.data);
}
export function createPolicy(data: any): Promise<{ policy: Policy }> {
  return api.post('/api/policies', data).then((r) => r.data);
}
export function updatePolicy(id: number, data: any): Promise<{ policy: Policy }> {
  return api.put('/api/policies/' + id, data).then((r) => r.data);
}
export function deletePolicy(id: number): Promise<{ message: string }> {
  return api.delete('/api/policies/' + id).then((r) => r.data);
}

// ---- Dashboard ----
export function getDashboardStats(): Promise<DashboardStats> {
  return api.get('/api/dashboard/stats').then((r) => r.data);
}

// ---- Audit ----
export interface AuditListResponse { audit: AuditLog[]; }
export interface AuditLog {
  id: number;
  user_id: number | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: string | null;
}
export function listAudit(limit?: number): Promise<AuditListResponse> {
  return api.get('/api/audit', { params: limit ? { limit } : undefined }).then((r) => r.data);
}

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string | null;
  last_login: string | null;
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

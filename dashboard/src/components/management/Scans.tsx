import React from 'react';
import { BarChart3, Filter, RefreshCw, ArrowUpRight } from 'lucide-react';
import { listScans, ScanResult } from '@/src/services/apiService';
import { cn } from '@/src/lib/utils';

const STATUS_COLORS: Record<string, string> = {
  clean: 'bg-brand-primary/20 text-brand-primary',
  malicious: 'bg-brand-danger/20 text-brand-danger',
  suspicious: 'bg-orange-500/20 text-orange-500',
  unknown: 'bg-gray-600/20 text-gray-500',
  whitelisted: 'bg-brand-secondary/20 text-brand-secondary',
  skipped: 'bg-gray-600/20 text-gray-500',
};

export function Scans() {
  const [scans, setScans] = React.useState<ScanResult[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [statusFilter, setStatusFilter] = React.useState('');

  React.useEffect(() => {
    loadScans();
  }, [statusFilter]);

  async function loadScans() {
    setLoading(true);
    const params: any = { per_page: 100 };
    if (statusFilter) params.status = statusFilter;
    const data = await listScans(params);
    setScans(data.scans);
    setLoading(false);
  }

  const scanStats = [
    { label: 'Total Scans', value: scans.length, icon: BarChart3, color: 'text-white' },
    { label: 'Malicious', value: scans.filter(s => s.status === 'malicious').length, icon: ArrowUpRight, color: 'text-brand-danger' },
    { label: 'Suspicious', value: scans.filter(s => s.status === 'suspicious').length, icon: ArrowUpRight, color: 'text-orange-500' },
    { label: 'Quarantined', value: scans.filter(s => s.action === 'quarantined').length, icon: BarChart3, color: 'text-brand-primary' },
  ];

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-surface-border pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <BarChart3 className="text-brand-secondary" /> Scan Results
          </h1>
          <p className="text-gray-500 text-sm">VirusTotal scan results ingested from Sentinel Agents.</p>
        </div>
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="form-input text-xs"
          >
            <option value="">All Status</option>
            <option value="clean">Clean</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="unknown">Unknown</option>
            <option value="whitelisted">Whitelisted</option>
          </select>
          <button
            onClick={() => {
              setLoading(true);
              loadScans();
            }}
            className="btn-secondary text-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {scanStats.map((stat, i) => (
          <div key={i} className="dashboard-card">
            <div className="flex justify-between items-start mb-3">
              <span className="text-xs font-mono tracking-widest text-gray-500 uppercase">{stat.label}</span>
              <stat.icon className="h-4 w-4 opacity-50" />
            </div>
            <h3 className="text-2xl font-bold font-mono">{stat.value}</h3>
          </div>
        ))}
      </div>

      {/* Scans Table */}
      <div className="dashboard-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="bg-surface-hover/50 text-gray-500 border-b border-surface-border sticky top-0 z-10">
              <tr>
                <th className="px-4 py-3">TIME</th>
                <th className="px-4 py-3">AGENT</th>
                <th className="px-4 py-3">FILE</th>
                <th className="px-4 py-3">HASH</th>
                <th className="px-4 py-3">STATUS</th>
                <th className="px-4 py-3">THREAT</th>
                <th className="px-4 py-3">DETECTIONS</th>
                <th className="px-4 py-3">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {loading ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">Loading scans...</td></tr>
              ) : scans.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">No scan results yet.</td></tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-brand-primary/5 transition-colors">
                    <td className="px-4 py-3 text-gray-500">
                      {s.scanned_at ? new Date(s.scanned_at).toLocaleTimeString() : '-'}
                    </td>
                    <td className="px-4 py-3 text-gray-300 truncate max-w-[120px]">{s.agent_id}</td>
                    <td className="px-4 py-3 text-white truncate max-w-[200px]">{s.file_name}</td>
                    <td className="px-4 py-3 text-gray-500 truncate max-w-[120px]">{s.file_hash?.slice(0, 16) + '...'}</td>
                    <td className="px-4 py-3">
                      <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold uppercase", STATUS_COLORS[s.status] || STATUS_COLORS.unknown)}>
                        {s.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold",
                        s.threat_level === 'critical' ? 'bg-brand-danger text-black' :
                        s.threat_level === 'high' ? 'bg-orange-500 text-black' :
                        s.threat_level === 'medium' ? 'bg-yellow-500 text-black' :
                        s.threat_level === 'low' ? 'bg-orange-500/20 text-orange-500' :
                        'bg-brand-primary/20 text-brand-primary'
                      )}>
                        {s.threat_level}
                      </span>
                    </td>
                    <td className="px-4 py-3">{s.positives} / {s.total}</td>
                    <td className="px-4 py-3">
                      <span className={s.action === 'quarantined' ? 'text-brand-danger font-bold' : 'text-gray-500'}>
                        {s.action}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

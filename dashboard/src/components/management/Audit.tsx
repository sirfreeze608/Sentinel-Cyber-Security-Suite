import React from 'react';
import { Terminal, RefreshCw, User, Clock } from 'lucide-react';
import { listAudit, AuditLog } from '@/src/services/apiService';
import { cn } from '@/src/lib/utils';

export function Audit() {
  const [logs, setLogs] = React.useState<AuditLog[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    loadAudit();
  }, []);

  async function loadAudit() {
    setLoading(true);
    const data = await listAudit(200);
    setLogs(data.audit);
    setLoading(false);
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-surface-border pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Terminal className="text-brand-secondary" /> Audit Log
          </h1>
          <p className="text-gray-500 text-sm">CS Department administrative audit trail.</p>
        </div>
        <button
          onClick={() => { setLoading(true); loadAudit(); }}
          className="btn-secondary text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      <div className="dashboard-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="bg-surface-hover/50 text-gray-500 border-b border-surface-border sticky top-0 z-10">
              <tr>
                <th className="px-4 py-3">TIME</th>
                <th className="px-4 py-3">USER</th>
                <th className="px-4 py-3">ACTION</th>
                <th className="px-4 py-3">TARGET</th>
                <th className="px-4 py-3">DETAILS</th>
                <th className="px-4 py-3">IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Loading audit log...</td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No audit entries.</td></tr>
              ) : (
                logs.map((l) => (
                  <tr key={l.id} className="hover:bg-brand-primary/5 transition-colors">
                    <td className="px-4 py-3 text-gray-500">
                      {l.created_at ? new Date(l.created_at).toLocaleString() : '-'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <User className="h-3 w-3 text-gray-500" />
                        <span className="text-gray-300 truncate max-w-[120px]">{l.user_id ? 'User #' + l.user_id : 'System'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 font-bold text-white">{l.action}</td>
                    <td className="px-4 py-3 text-gray-400 truncate max-w-[120px]">
                      {l.target_type || '-'} {l.target_id ? ('#' + l.target_id) : ''}
                    </td>
                    <td className="px-4 py-3 text-gray-500 truncate max-w-[200px]">{l.details || '-'}</td>
                    <td className="px-4 py-3 text-gray-500">{l.ip_address || '-'}</td>
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

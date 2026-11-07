import React from 'react';
import { ShieldAlert, RefreshCw, Globe, User, Terminal, Activity } from 'lucide-react';
import { listAgents, Agent } from '@/src/services/apiService';
import { cn } from '@/src/lib/utils';

export function Agents() {
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    listAgents().then((data) => {
      setAgents(data.agents);
      setLoading(false);
    });
  }, []);

  const agentStats = [
    { label: 'Total Agents', value: agents.length, icon: User, color: 'text-brand-primary' },
    { label: 'Online', value: agents.filter(a => a.is_online).length, icon: Activity, color: 'text-brand-secondary' },
    { label: 'Total Scans', value: agents.reduce((s, a) => s + a.total_scans, 0), icon: Terminal, color: 'text-brand-primary' },
    { label: 'Total Threats', value: agents.reduce((s, a) => s + a.total_threats, 0), icon: ShieldAlert, color: 'text-brand-danger' },
  ];

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-surface-border pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <UsersIcon className="text-brand-secondary" /> Managed Agents
          </h1>
          <p className="text-gray-500 text-sm">Endpoint agents registered with Sentinel CS.</p>
        </div>
        <button
          onClick={() => {
            setLoading(true);
            listAgents().then((d) => { setAgents(d.agents); setLoading(false); });
          }}
          className="btn-secondary text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {agentStats.map((stat, i) => (
          <div key={i} className="dashboard-card">
            <div className="flex justify-between items-start mb-3">
              <span className="text-xs font-mono tracking-widest text-gray-500 uppercase">{stat.label}</span>
              <stat.icon className="h-4 w-4 opacity-50" />
            </div>
            <h3 className="text-2xl font-bold font-mono">{stat.value}</h3>
          </div>
        ))}
      </div>

      {/* Agents Table */}
      <div className="dashboard-card overflow-hidden">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <h3 className="text-sm font-bold uppercase tracking-wider flex items-center gap-2">
            <Globe className="h-4 w-4 text-gray-500" />
            Agent Registry
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="bg-surface-hover/50 text-gray-500 border-b border-surface-border">
              <tr>
                <th className="px-4 py-3">AGENT ID</th>
                <th className="px-4 py-3">HOSTNAME</th>
                <th className="px-4 py-3">PLATFORM</th>
                <th className="px-4 py-3">STATUS</th>
                <th className="px-4 py-3">VERSION</th>
                <th className="px-4 py-3">SCANS</th>
                <th className="px-4 py-3">THREATS</th>
                <th className="px-4 py-3">QUARANTINED</th>
                <th className="px-4 py-3">LAST SEEN</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {loading ? (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-gray-500">Loading agents...</td></tr>
              ) : agents.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-gray-500">No agents registered. Deploy Sentinel Agent to endpoints.</td></tr>
              ) : (
                agents.map((a) => (
                  <tr key={a.agent_id} className="hover:bg-brand-primary/5 transition-colors">
                    <td className="px-4 py-3 font-bold text-white truncate max-w-[150px]">{a.agent_id}</td>
                    <td className="px-4 py-3 text-gray-300">{a.hostname}</td>
                    <td className="px-4 py-3">{a.os_platform}</td>
                    <td className="px-4 py-3">
                      <span className={cn(
                        "px-2 py-0.5 rounded text-[10px] font-bold",
                        a.is_online ? 'bg-brand-primary/20 text-brand-primary' : 'bg-surface-hover text-gray-500'
                      )}>
                        {a.is_online ? 'ONLINE' : 'OFFLINE'}
                      </span>
                    </td>
                    <td className="px-4 py-3">{a.agent_version}</td>
                    <td className="px-4 py-3">{a.total_scans}</td>
                    <td className="px-4 py-3">{a.total_threats}</td>
                    <td className="px-4 py-3">{a.total_quarantined}</td>
                    <td className="px-4 py-3 text-gray-500">
                      {a.last_seen ? new Date(a.last_seen).toLocaleString() : 'Never'}
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

function UsersIcon(props: any) {
  return <User {...props} />;
}

import React from 'react';
import { ShieldCheck, RefreshCw, FolderOpen, Delete, Trash2, Play } from 'lucide-react';
import { listQuarantine, restoreQuarantine, deleteQuarantine, QuarantineItem } from '@/src/services/apiService';
import { cn } from '@/src/lib/utils';

export function Quarantine() {
  const [items, setItems] = React.useState<QuarantineItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [restoreDest, setRestoreDest] = React.useState('');
  const [restoringId, setRestoringId] = React.useState<number | null>(null);

  React.useEffect(() => {
    loadQuarantine();
  }, []);

  async function loadQuarantine() {
    setLoading(true);
    const data = await listQuarantine();
    setItems(data.quarantine);
    setLoading(false);
  }

  async function handleRestore(id: number) {
    setRestoringId(id);
    try {
      await restoreQuarantine(id, restoreDest || '/tmp/sentinel_restore');
      setItems(items.map((i) => i.id === id ? { ...i, restored: true } : i));
    } finally {
      setRestoringId(null);
    }
  }

  async function handleDelete(id: number) {
    if (!window.confirm('Permanently delete this quarantined file?')) return;
    await deleteQuarantine(id);
    setItems(items.filter((i) => i.id !== id));
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-surface-border pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <ShieldCheck className="text-brand-primary" /> Quarantine Vault
          </h1>
          <p className="text-gray-500 text-sm">Infected files isolated by Sentinel Agents.</p>
        </div>
        <button
          onClick={() => { setLoading(true); loadQuarantine(); }}
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
                <th className="px-4 py-3">AGENT</th>
                <th className="px-4 py-3">ORIGINAL PATH</th>
                <th className="px-4 py-3">HASH</th>
                <th className="px-4 py-3">REASON</th>
                <th className="px-4 py-3">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {loading ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Loading quarantine...</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No quarantined files.</td></tr>
              ) : (
                items.map((q) => (
                  <tr key={q.id} className="hover:bg-brand-primary/5 transition-colors">
                    <td className="px-4 py-3 text-gray-500">
                      {q.quarantined_at ? new Date(q.quarantined_at).toLocaleString() : '-'}
                    </td>
                    <td className="px-4 py-3 text-gray-300 truncate max-w-[120px]">{q.agent_id}</td>
                    <td className="px-4 py-3 text-white truncate max-w-[250px]">{q.original_path}</td>
                    <td className="px-4 py-3 text-gray-500 truncate max-w-[120px]">{q.file_hash?.slice(0, 16) + '...'}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-brand-danger/20 text-brand-danger">
                        {q.reason}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleRestore(q.id)}
                          disabled={restoringId === q.id}
                          className="btn-secondary text-xs px-3"
                        >
                          {restoringId === q.id ? 'Restoring...' : <Play className="h-3 w-3 fill-black" />}
                        </button>
                        <button
                          onClick={() => handleDelete(q.id)}
                          className="btn-secondary text-xs px-3 text-brand-danger border-brand-danger/30"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="dashboard-card p-6">
        <h3 className="text-xs font-bold text-gray-500 uppercase mb-4">Restore Quarantined File</h3>
        <div className="space-y-3">
          <input
            type="text"
            value={restoreDest}
            onChange={(e) => setRestoreDest(e.target.value)}
            placeholder="Restore destination path (e.g., C:\\Users\\Public\\restored.exe)"
            className="form-input"
          />
          <div className="flex gap-2">
            <button
              onClick={() => {
                const id = items[0]?.id;
                if (id) handleRestore(id);
              }}
              className="btn-primary text-xs"
            >
              Restore Selected
            </button>
            <p className="text-xs text-gray-500">Leave destination empty to use default restore path.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

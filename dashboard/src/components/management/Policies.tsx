import React from 'react';
import { ShieldAlert, RefreshCw, Save, Trash2 } from 'lucide-react';
import { listPolicies, createPolicy, updatePolicy, deletePolicy, Policy } from '@/src/services/apiService';
import { cn } from '@/src/lib/utils';

export function Policies() {
  const [policies, setPolicies] = React.useState<Policy[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [form, setForm] = React.useState({
    name: '', description: '', auto_quarantine: false, skip_system_dirs: true,
    max_file_size_mb: 32, cache_ttl_hours: 24, malicious_threshold: 1,
    high_risk_threshold: 5, critical_threshold: 10, is_active: true, applies_to: 'all',
  });
  const [editingId, setEditingId] = React.useState<number | null>(null);

  React.useEffect(() => {
    loadPolicies();
  }, []);

  async function loadPolicies() {
    setLoading(true);
    const data = await listPolicies();
    setPolicies(data.policies);
    setLoading(false);
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (editingId) {
      await updatePolicy(editingId, form);
      setEditingId(null);
    } else {
      await createPolicy(form);
    }
    setForm({
      name: '', description: '', auto_quarantine: false, skip_system_dirs: true,
      max_file_size_mb: 32, cache_ttl_hours: 24, malicious_threshold: 1,
      high_risk_threshold: 5, critical_threshold: 10, is_active: true, applies_to: 'all',
    });
    loadPolicies();
  }

  async function handleDelete(id: number) {
    if (!window.confirm('Delete this policy?')) return;
    await deletePolicy(id);
    loadPolicies();
  }

  function edit(p: Policy) {
    setEditingId(p.id);
    setForm({
      name: p.name, description: p.description || '', auto_quarantine: p.auto_quarantine,
      skip_system_dirs: p.skip_system_dirs, max_file_size_mb: p.max_file_size_mb,
      cache_ttl_hours: p.cache_ttl_hours, malicious_threshold: p.malicious_threshold,
      high_risk_threshold: p.high_risk_threshold, critical_threshold: p.critical_threshold,
      is_active: p.is_active, applies_to: p.applies_to,
    });
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-surface-border pb-6">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <ShieldAlert className="text-brand-secondary" /> Scan Policies
          </h1>
          <p className="text-gray-500 text-sm">Configure intelligent scan policies pushed to Sentinel Agents.</p>
        </div>
        <button
          onClick={() => { setLoading(true); loadPolicies(); }}
          className="btn-secondary text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Policy Form */}
      <div className="dashboard-card">
        <h3 className="text-sm font-bold text-white mb-4">
          {editingId ? 'Edit Policy' : 'Create New Policy'}
        </h3>
        <form onSubmit={handleSave} className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Policy Name</label>
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="form-input" required />
          </div>
          <div className="flex flex-col gap-2 md:col-span-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Description</label>
            <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="form-input" />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Max File Size (MB)</label>
            <input type="number" value={form.max_file_size_mb} onChange={(e) => setForm({ ...form, max_file_size_mb: parseInt(e.target.value) || 32 })} className="form-input" />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Cache TTL (Hours)</label>
            <input type="number" value={form.cache_ttl_hours} onChange={(e) => setForm({ ...form, cache_ttl_hours: parseInt(e.target.value) || 24 })} className="form-input" />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Malicious Threshold</label>
            <input type="number" value={form.malicious_threshold} onChange={(e) => setForm({ ...form, malicious_threshold: parseInt(e.target.value) || 1 })} className="form-input" />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">High Risk Threshold</label>
            <input type="number" value={form.high_risk_threshold} onChange={(e) => setForm({ ...form, high_risk_threshold: parseInt(e.target.value) || 5 })} className="form-input" />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Critical Threshold</label>
            <input type="number" value={form.critical_threshold} onChange={(e) => setForm({ ...form, critical_threshold: parseInt(e.target.value) || 10 })} className="form-input" />
          </div>
          <div className="flex items-end gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={form.auto_quarantine} onChange={(e) => setForm({ ...form, auto_quarantine: e.target.checked })} className="rounded" /> Auto-Quarantine
            </label>
            <label className="text-xs text-gray-500 font-mono uppercase flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={form.skip_system_dirs} onChange={(e) => setForm({ ...form, skip_system_dirs: e.target.checked })} className="rounded" /> Skip System Dirs
            </label>
            <label className="text-xs text-gray-500 font-mono uppercase flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={form.is_active} onChange={(e) => setForm({ ...form, is_active: e.target.checked })} className="rounded" /> Active
            </label>
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-xs text-gray-500 font-mono uppercase">Applies To</label>
            <select value={form.applies_to} onChange={(e) => setForm({ ...form, applies_to: e.target.value })} className="form-input">
              <option value="all">All Agents</option>
            </select>
          </div>
          <div className="md:col-span-3 flex gap-3">
            <button type="submit" disabled={loading} className="btn-primary">
              {loading ? 'Saving...' : (editingId ? 'Update Policy' : 'Create Policy')}
            </button>
            {editingId && (
              <button type="button" onClick={() => { setEditingId(null); loadPolicies(); }} className="btn-secondary">
                Cancel
              </button>
            )}
          </div>
        </form>
      </div>

      {/* Policies List */}
      <div className="dashboard-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[11px]">
            <thead className="bg-surface-hover/50 text-gray-500 border-b border-surface-border sticky top-0 z-10">
              <tr>
                <th className="px-4 py-3">NAME</th>
                <th className="px-4 py-3">DESCRIPTION</th>
                <th className="px-4 py-3">AUTO-QUAR</th>
                <th className="px-4 py-3">MAX SIZE</th>
                <th className="px-4 py-3">THRESHOLDS</th>
                <th className="px-4 py-3">STATUS</th>
                <th className="px-4 py-3">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {loading ? (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">Loading policies...</td></tr>
              ) : policies.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-500">No policies defined.</td></tr>
              ) : (
                policies.map((p) => (
                  <tr key={p.id} className="hover:bg-brand-primary/5 transition-colors">
                    <td className="px-4 py-3 font-bold text-white">{p.name}</td>
                    <td className="px-4 py-3 text-gray-400 truncate max-w-[200px]">{p.description || '-'}</td>
                    <td className="px-4 py-3">
                      <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold",
                        p.auto_quarantine ? 'bg-brand-primary/20 text-brand-primary' : 'bg-surface-hover text-gray-500')}>
                        {p.auto_quarantine ? 'ON' : 'OFF'}
                      </span>
                    </td>
                    <td className="px-4 py-3">{p.max_file_size_mb} MB</td>
                    <td className="px-4 py-3">
                      <span className="text-[10px] font-mono text-gray-500">
                        M:{p.malicious_threshold} H:{p.high_risk_threshold} C:{p.critical_threshold}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold",
                        p.is_active ? 'bg-brand-primary/20 text-brand-primary' : 'bg-surface-hover text-gray-500')}>
                        {p.is_active ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button onClick={() => edit(p)} className="btn-secondary text-xs px-3">
                          <Save className="h-3 w-3 fill-black" />
                        </button>
                        <button onClick={() => handleDelete(p.id)} className="btn-secondary text-xs px-3 text-brand-danger border-brand-danger/30">
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
    </div>
  );
}

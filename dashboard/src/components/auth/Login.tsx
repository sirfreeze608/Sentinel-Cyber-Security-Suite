import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ShieldAlert, Terminal, User, Lock } from 'lucide-react';
import { login } from '@/src/services/apiService';

export function Login() {
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await login({ username, password });
      localStorage.setItem('sentinel_token', data.token);
      localStorage.setItem('sentinel_user', JSON.stringify(data.user));
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Login failed. Check credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-base">
      <div className="dashboard-card w-full max-w-md">
        <div className="flex items-center gap-3 mb-6">
          <Terminal className="text-brand-primary h-8 w-8" />
          <span className="text-white font-bold tracking-tighter text-xl">SENTINEL CS</span>
        </div>
        <h2 className="text-xl font-bold mb-2">CS Department Sign-In</h2>
        <p className="text-gray-500 text-sm mb-6">Access the Sentinel Cyber Security Suite management console.</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-500" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="form-input pl-10"
                required
              />
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="form-input pl-10"
                required
              />
            </div>
          </div>
          {error && (
            <div className="p-3 rounded bg-brand-danger/10 border border-brand-danger/30 text-brand-danger text-xs">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
        <div className="mt-6 pt-6 border-t border-surface-border">
          <p className="text-xs text-gray-500 text-center mb-4">Default credentials:</p>
          <div className="space-y-1 text-[10px] font-mono text-gray-400">
            <div>cs_admin / SentinelAdmin2026!</div>
            <div>cs_analyst / SentinelAnalyst2026!</div>
            <div>cs_viewer / SentinelViewer2026!</div>
          </div>
        </div>
      </div>
    </div>
  );
}

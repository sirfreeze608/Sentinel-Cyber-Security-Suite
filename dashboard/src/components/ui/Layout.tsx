import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  ShieldAlert, Activity, MailWarning, Puzzle, Terminal, Settings,
  Bell, Menu, X, User, LogOut, ShieldCheck, Users, BarChart3,
} from 'lucide-react';
import { cn } from '@/src/lib/utils';
import { motion, AnimatePresence } from 'motion/react';

const navigation = [
  { name: 'Threat Monitor', href: '/', icon: ShieldAlert },
  { name: 'Network Pulse', href: '/network', icon: Activity },
  { name: 'Phishing Shield', href: '/phishing', icon: MailWarning },
  { name: 'OSINT Addons', href: '/osint', icon: Puzzle },
];

const mgmtNavigation = [
  { name: 'Agents', href: '/agents', icon: Users },
  { name: 'Scan Results', href: '/scans', icon: BarChart3 },
  { name: 'Quarantine', href: '/quarantine', icon: ShieldCheck },
  { name: 'Policies', href: '/policies', icon: ShieldAlert },
  { name: 'Audit Log', href: '/audit', icon: Terminal },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);
  const userStr = localStorage.getItem('sentinel_user');
  const user = userStr ? JSON.parse(userStr) : null;
  const isMgmt = location.pathname.startsWith('/agents') ||
                 location.pathname.startsWith('/scans') ||
                 location.pathname.startsWith('/quarantine') ||
                 location.pathname.startsWith('/policies') ||
                 location.pathname.startsWith('/audit');

  const handleLogout = () => {
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_user');
    navigate('/login');
  };

  const navItems = isMgmt ? mgmtNavigation : navigation;

  return (
    <div className="min-h-screen bg-surface-base text-gray-400">
      <div className="cyber-grid fixed inset-0 z-0 opacity-20 pointer-events-none" />

      {/* Sidebar */}
      <aside className="hidden lg:flex flex-col w-64 fixed inset-y-0 z-50 border-r border-surface-border bg-surface-base/80 backdrop-blur-md">
        <div className="flex h-20 items-center gap-3 px-6 border-b border-surface-border">
          <Terminal className="text-brand-primary h-8 w-8" />
          <span className="text-white font-bold tracking-tighter text-xl">SENTINEL</span>
        </div>

        <nav className="flex-1 space-y-1 px-4 py-6">
          {navItems.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  "group flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-lg transition-colors",
                  isActive
                    ? "bg-brand-primary/10 text-brand-primary border border-brand-primary/20"
                    : "text-gray-400 hover:text-white hover:bg-surface-hover"
                )}
              >
                <item.icon className={cn("h-5 w-5", isActive ? "text-brand-primary" : "text-gray-400 group-hover:text-white")} />
                {item.name}
                {isActive && (
                  <motion.div
                    layoutId="active-indicator"
                    className="ml-auto w-1 h-4 bg-brand-primary rounded-full shadow-[0_0_8px_rgba(0,255,156,0.5)]"
                  />
                )}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-surface-border">
          <div className="flex items-center gap-3 p-3 rounded-lg bg-surface-hover/50">
            <div className="h-8 w-8 rounded-full bg-brand-secondary/20 flex items-center justify-center">
              <User className="h-5 w-5 text-brand-secondary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-mono text-gray-500 uppercase truncate">SENTINEL CS</p>
              {user && (
                <>
                  <p className="text-sm font-medium text-white truncate">{user.username}</p>
                  <p className="text-xs text-gray-500 truncate">{user.role.toUpperCase()}</p>
                </>
              )}
            </div>
            <button onClick={handleLogout} className="h-4 w-4 text-gray-500 hover:text-white cursor-pointer">
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Header */}
      <header className="lg:pl-64 sticky top-0 z-40 bg-surface-base/80 backdrop-blur-md border-b border-surface-border">
        <div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-4 lg:hidden">
            <button onClick={() => setIsMobileMenuOpen(true)}>
              <Menu className="h-6 w-6 text-white" />
            </button>
            <span className="text-white font-bold tracking-tighter">SENTINEL</span>
          </div>

          <div className="flex flex-1 justify-center lg:justify-start px-4">
            <div className="w-full max-w-lg relative group">
              <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                <span className="text-xs font-mono text-brand-primary opacity-50">$</span>
              </div>
              <div className="w-full bg-surface-hover/50 border border-surface-border rounded-full py-1.5 pl-8 pr-4 text-xs font-mono text-gray-500 select-none overflow-hidden">
                <div className="scrolling-text">
                  [SENTINEL CS] - FIRMWARE v4.2.0 - HEARTBEAT OK - MONITORING AGENTS...
                </div>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button className="relative p-2 text-gray-400 hover:text-white">
              <Bell className="h-5 w-5" />
              <span className="absolute top-2 right-2 h-2 w-2 bg-brand-danger rounded-full" />
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <div className="fixed inset-0 z-50 lg:hidden">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/80 backdrop-blur-sm"
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              className="fixed inset-y-0 left-0 w-full max-w-xs bg-surface-base border-r border-surface-border p-6 shadow-2xl"
            >
              <div className="flex items-center justify-between mb-8">
                <span className="text-white font-bold tracking-tighter text-xl underline decoration-brand-primary underline-offset-4">SENTINEL</span>
                <button onClick={() => setIsMobileMenuOpen(false)}>
                  <X className="h-6 w-6 text-white" />
                </button>
              </div>
              <nav className="space-y-2">
                {navItems.map((item) => {
                  const isActive = location.pathname === item.href;
                  return (
                    <Link
                      key={item.name}
                      to={item.href}
                      onClick={() => setIsMobileMenuOpen(false)}
                      className={cn(
                        "flex items-center gap-4 px-4 py-3 rounded-xl text-lg font-medium",
                        isActive ? "bg-brand-primary text-black" : "text-gray-400 hover:text-white hover:bg-surface-hover"
                      )}
                    >
                      <item.icon className="h-6 w-6" />
                      {item.name}
                    </Link>
                  );
                })}
              </nav>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main className="lg:pl-64 min-h-[calc(100vh-64px)] relative">
        <div className="max-w-[1600px] mx-auto p-4 sm:p-6 lg:p-8 relative z-10">
          {children}
        </div>
      </main>
    </div>
  );
}

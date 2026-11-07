import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/ui/Layout';
import { ThreatMonitor } from './components/ThreatMonitor';
import { NetworkActivity } from './components/NetworkActivity';
import { PhishingShield } from './components/PhishingShield';
import { OSINTAddons } from './components/OSINTAddons';
import { Login } from './components/auth/Login';
import { Agents } from './components/management/Agents';
import { Scans } from './components/management/Scans';
import { Quarantine } from './components/management/Quarantine';
import { Policies } from './components/management/Policies';
import { Audit } from './components/management/Audit';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('sentinel_token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function RoleRoute({ children, allowedRoles }: { children: React.ReactNode; allowedRoles: string[] }) {
  const token = localStorage.getItem('sentinel_token');
  const userStr = localStorage.getItem('sentinel_user');
  const user = userStr ? JSON.parse(userStr) : null;
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (!user || !allowedRoles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<ProtectedRoute><Layout><ThreatMonitor /></Layout></ProtectedRoute>} />
        <Route path="/network" element={<ProtectedRoute><Layout><NetworkActivity /></Layout></ProtectedRoute>} />
        <Route path="/phishing" element={<ProtectedRoute><Layout><PhishingShield /></Layout></ProtectedRoute>} />
        <Route path="/osint" element={<ProtectedRoute><Layout><OSINTAddons /></Layout></ProtectedRoute>} />

        {/* CS Department Management Routes */}
        <Route path="/agents" element={<ProtectedRoute><RoleRoute allowedRoles={['cs_admin', 'cs_analyst', 'cs_viewer']}><Layout><Agents /></Layout></RoleRoute></ProtectedRoute>} />
        <Route path="/scans" element={<ProtectedRoute><RoleRoute allowedRoles={['cs_admin', 'cs_analyst', 'cs_viewer']}><Layout><Scans /></Layout></RoleRoute></ProtectedRoute>} />
        <Route path="/quarantine" element={<ProtectedRoute><RoleRoute allowedRoles={['cs_admin', 'cs_analyst']}><Layout><Quarantine /></Layout></RoleRoute></ProtectedRoute>} />
        <Route path="/policies" element={<ProtectedRoute><RoleRoute allowedRoles={['cs_admin']}><Layout><Policies /></Layout></RoleRoute></ProtectedRoute>} />
        <Route path="/audit" element={<ProtectedRoute><RoleRoute allowedRoles={['cs_admin', 'cs_analyst']}><Layout><Audit /></Layout></RoleRoute></ProtectedRoute>} />
      </Routes>
    </Router>
  );
}

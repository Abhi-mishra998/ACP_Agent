import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { AuthContext } from './context/AuthContext';
import { AgentProvider } from './context/AgentContext';
import ProtectedRoute from './components/Layout/ProtectedRoute';
import ErrorBoundary from './components/Common/ErrorBoundary';
import IncidentOverlay from './components/Common/IncidentOverlay';
import { onAuthFailure } from './lib/authEvents';
import { clearSessionMetadata } from './services/api';

import Login from './pages/Login';
import ExecutiveDashboard from './pages/ExecutiveDashboard';
import Agents from './pages/Agents';
import KillSwitch from './pages/KillSwitch';
import Forensics from './pages/Forensics';
import AuditLogs from './pages/AuditLogs';
import Billing from './pages/Billing';
import SecurityDashboard from './pages/SecurityDashboard';
import RiskEngine from './pages/RiskEngine';
import AgentPlayground from './pages/AgentPlayground';
import DeveloperPanel from './pages/DeveloperPanel';
import Observability from './pages/Observability';
import SystemHealth from './pages/SystemHealth';
import PolicyBuilder from './pages/PolicyBuilder';
import RBAC from './pages/RBAC';
import Incidents from './pages/Incidents';
import AttackSimulation from './pages/AttackSimulation';
import AutoResponse from './pages/AutoResponse';
import Toast from './components/Common/Toast';

// Auth state is based on session metadata (tenant_id + expiry), not the token itself.
// The JWT lives exclusively in the httpOnly cookie.
const readSessionState = () => {
  const tenantId = localStorage.getItem('tenant_id');
  const expiry   = parseInt(localStorage.getItem('acp_token_expiry') || '0', 10);
  const isValid  = !!tenantId && expiry > Date.now();
  return {
    isAuthenticated: isValid,
    user:            localStorage.getItem('user_email'),
    tenant_id:       isValid ? tenantId : null,
    role:            isValid ? (localStorage.getItem('user_role') || null) : null,
    token:           null,
  };
};

// Inner component — needs access to useNavigate (must be inside BrowserRouter)
function AuthEventHandler({ onIncident }) {
  const navigate = useNavigate()

  useEffect(() => {
    const unsub = onAuthFailure((e) => {
      // Surface the SOC-grade incident overlay before resetting state
      onIncident(e.detail)
    })
    return unsub
  }, [onIncident])

  return null
}

function App() {
  const [auth,     setAuth]     = useState(readSessionState);
  const [toasts,   setToasts]   = useState([]);
  const [incident, setIncident] = useState(null);

  const updateAuth = (newAuth) => setAuth((prev) => ({ ...prev, ...newAuth }));

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  };

  const removeToast = (id) => setToasts((prev) => prev.filter((t) => t.id !== id));

  // Called by AuthEventHandler when auth:failure fires
  const handleIncident = useCallback((detail) => {
    clearSessionMetadata();
    setAuth({ isAuthenticated: false, user: null, tenant_id: null, token: null });
    setIncident(detail);
  }, []);

  // Dismiss overlay → navigate to login
  const handleIncidentDismiss = useCallback(() => {
    setIncident(null);
    // Navigate after state clears — the Routes below will redirect to /login automatically
    // since isAuthenticated is now false, but we also push imperatively just in case
    if (window.location.pathname !== '/login') {
      window.location.href = '/login';
    }
  }, []);

  // Multi-tab sync (other tabs calling logout / expiry)
  useEffect(() => {
    const handleStorage = () => setAuth(readSessionState());
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  // Proactive client-side expiry timer
  useEffect(() => {
    const expiry    = parseInt(localStorage.getItem('acp_token_expiry') || '0', 10);
    const remaining = expiry - Date.now();
    if (remaining <= 0) return;
    const timer = setTimeout(() => {
      clearSessionMetadata();
      setAuth({ isAuthenticated: false, user: null, tenant_id: null, token: null });
      setIncident({
        incidentId:  crypto.randomUUID(),
        reason:      'session_expired',
        reasonLabel: 'Session Expired',
        url:         window.location.pathname,
        statusCode:  null,
        timestamp:   new Date().toISOString(),
      });
    }, remaining);
    return () => clearTimeout(timer);
  }, [auth.isAuthenticated]);

  return (
    <ErrorBoundary>
      <AuthContext.Provider value={{ ...auth, updateAuth, addToast }}>
        <AgentProvider>
          <BrowserRouter>
            {/* Wires auth event bus → incident overlay (needs Router context for useNavigate) */}
            <AuthEventHandler onIncident={handleIncident} />

            <Routes>
              <Route path="/login" element={auth.isAuthenticated ? <Navigate to="/dashboard" /> : <Login />} />

              <Route path="/"               element={<Navigate to="/dashboard" />} />
              <Route path="/dashboard"      element={<ProtectedRoute><ExecutiveDashboard /></ProtectedRoute>} />
              <Route path="/agents"         element={<ProtectedRoute><Agents /></ProtectedRoute>} />
              <Route path="/security"       element={<ProtectedRoute><SecurityDashboard /></ProtectedRoute>} />
              <Route path="/risk"           element={<ProtectedRoute><RiskEngine /></ProtectedRoute>} />
              <Route path="/audit-logs"     element={<ProtectedRoute><AuditLogs /></ProtectedRoute>} />
              <Route path="/forensics"      element={<ProtectedRoute><Forensics /></ProtectedRoute>} />
              <Route path="/policy-builder" element={<ProtectedRoute><PolicyBuilder /></ProtectedRoute>} />
              <Route path="/rbac"           element={<ProtectedRoute><RBAC /></ProtectedRoute>} />
              <Route path="/playground"     element={<ProtectedRoute><AgentPlayground /></ProtectedRoute>} />
              <Route path="/billing"        element={<ProtectedRoute><Billing /></ProtectedRoute>} />
              <Route path="/developer"      element={<ProtectedRoute><DeveloperPanel /></ProtectedRoute>} />
              <Route path="/incidents"       element={<ProtectedRoute><Incidents /></ProtectedRoute>} />
              <Route path="/attack-sim"      element={<ProtectedRoute><AttackSimulation /></ProtectedRoute>} />
              <Route path="/auto-response"   element={<ProtectedRoute><AutoResponse /></ProtectedRoute>} />
              <Route path="/kill-switch"    element={<ProtectedRoute><KillSwitch /></ProtectedRoute>} />
              <Route path="/observability"  element={<ProtectedRoute><Observability /></ProtectedRoute>} />
              <Route path="/system-health"  element={<ProtectedRoute><SystemHealth /></ProtectedRoute>} />

              <Route path="*" element={<Navigate to="/dashboard" />} />
            </Routes>
          </BrowserRouter>
        </AgentProvider>

        {/* Toast stack */}
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
          {toasts.map((toast) => (
            <div key={toast.id} className="pointer-events-auto">
              <Toast message={toast.message} type={toast.type} onClose={() => removeToast(toast.id)} />
            </div>
          ))}
        </div>

        {/* SOC Incident Overlay — renders above everything including ErrorBoundary siblings */}
        <IncidentOverlay incident={incident} onDismiss={handleIncidentDismiss} />
      </AuthContext.Provider>
    </ErrorBoundary>
  );
}

export default App;

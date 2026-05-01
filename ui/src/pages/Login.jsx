import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, setSessionMetadata } from '../services/api';
import { Shield, AlertCircle, Eye, EyeOff, Lock } from 'lucide-react';
import Button from '../components/Common/Button';
import { useAuth } from '../hooks/useAuth';

export default function Login() {
  const navigate = useNavigate();
  const { updateAuth } = useAuth();

  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please enter your email and password.');
      return;
    }
    setLoading(true);
    setError('');

    try {
      const res = await api.login({ email, password });
      const tenantId  = res?.data?.tenant_id;
      const expiresIn = res?.data?.expires_in;

      if (!tenantId) {
        setError('Invalid credentials. Please try again.');
        return;
      }

      const role = res?.data?.role;
      setSessionMetadata({ tenant_id: tenantId, expires_in: expiresIn, user_email: email, role });
      localStorage.setItem('user_email', email);

      // Agent fleet is loaded by AgentContext on auth state change — no manual fetch needed here.

      updateAuth({
        isAuthenticated: true,
        user: email,
        tenant_id: tenantId,
        role: res?.data?.role || null,
        token: null,
      });

      navigate('/dashboard', { replace: true });
    } catch (err) {
      const msg = err?.response?.data?.detail || err?.message;
      setError(msg || 'Authentication failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#030303] flex flex-col items-center justify-center px-4 relative overflow-hidden">
      {/* Background texture */}
      <div className="absolute inset-0 grid-baseline opacity-[0.06] pointer-events-none" aria-hidden="true" />
      <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" aria-hidden="true" />

      <div className="w-full max-w-sm relative z-10 animate-scale-in">
        {/* Logo */}
        <div className="flex flex-col items-center gap-4 mb-8">
          <div className="w-12 h-12 rounded-xl bg-white flex items-center justify-center shadow-[0_0_24px_rgba(255,255,255,0.15)]">
            <Shield size={24} className="text-black" aria-hidden="true" />
          </div>
          <div className="text-center space-y-1">
            <h1 className="text-2xl font-bold tracking-tight text-white">
              AgentControl
            </h1>
            <p className="text-xs text-neutral-500 font-medium tracking-wide">
              Secure Gateway · v5.0
            </p>
          </div>
        </div>

        {/* Form card */}
        <div className="bg-[#0a0a0a] border border-white/[0.07] rounded-2xl p-8 shadow-2xl space-y-5">
          {/* Error alert */}
          {error && (
            <div
              role="alert"
              className="flex items-start gap-3 p-3.5 rounded-xl bg-red-500/[0.08] border border-red-500/20 animate-scale-in"
            >
              <AlertCircle
                className="text-red-400 shrink-0 mt-0.5"
                size={15}
                aria-hidden="true"
              />
              <p className="text-xs text-red-400 leading-snug">{error}</p>
            </div>
          )}

          <form className="space-y-4" onSubmit={handleLogin} noValidate>
            {/* Email */}
            <div className="space-y-1.5">
              <label htmlFor="email" className="label-standard">
                Email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="input-standard h-11"
                aria-describedby={error ? 'login-error' : undefined}
              />
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label htmlFor="password" className="label-standard">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPw ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="input-standard h-11 pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((v) => !v)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-neutral-600 hover:text-neutral-400 transition-colors rounded"
                >
                  {showPw
                    ? <EyeOff size={15} aria-hidden="true" />
                    : <Eye    size={15} aria-hidden="true" />
                  }
                </button>
              </div>
            </div>

            {/* Submit */}
            <div className="pt-2">
              <Button
                type="submit"
                loading={loading}
                disabled={loading}
                className="w-full h-11 text-sm font-semibold"
              >
                Sign In
              </Button>
            </div>
          </form>

          {/* Footer note */}
          <div className="flex items-center justify-center gap-2 pt-1">
            <Lock size={11} className="text-neutral-700" aria-hidden="true" />
            <p className="text-xs text-neutral-700">Encrypted · Authorized Personnel Only</p>
          </div>
        </div>
      </div>
    </div>
  );
}

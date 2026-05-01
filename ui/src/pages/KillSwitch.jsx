import React, { useState, useEffect } from 'react'
import { killSwitchService } from '../services/api'
import {
  AlertTriangle, Power, ShieldCheck, AlertOctagon,
  ShieldAlert, Zap, Lock, RefreshCw,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import Modal from '../components/Common/Modal'
import { useAuth } from '../hooks/useAuth'
import { useRole } from '../hooks/useRole'

/* ── Status row ─────────────────────────────────────────────────────────────── */
function StatusRow({ label, isActive, activeLabel, idleLabel }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-neutral-500">{label}</span>
        <span className={`text-xs font-bold ${isActive ? 'text-red-400' : 'text-green-400'}`}>
          {isActive ? activeLabel : idleLabel}
        </span>
      </div>
      <div className="h-1 bg-white/[0.05] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${isActive ? 'bg-red-500 w-full' : 'bg-green-500 w-1/4'}`}
        />
      </div>
    </div>
  )
}

/* ── Component ──────────────────────────────────────────────────────────────── */
export default function KillSwitch() {
  const { tenant_id, addToast } = useAuth()
  const { canViewKillSwitch } = useRole()
  const [loading,       setLoading]       = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [isActive,      setIsActive]      = useState(false)
  const [error,         setError]         = useState('')
  const [confirmOpen,   setConfirmOpen]   = useState(false)

  const fetchStatus = async () => {
    if (!tenant_id) return
    try {
      const res = await killSwitchService.getStatus(tenant_id)
      setIsActive(res.data?.status === 'engaged' || res.data?.is_active === true)
      setError('')
    } catch (err) {
      setError(err.message || 'Could not reach kill switch service.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30_000)
    return () => clearInterval(interval)
  }, [tenant_id]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleToggle = async () => {
    setConfirmOpen(false)
    if (!tenant_id) return
    const action = isActive ? 'disengage' : 'engage'
    setActionLoading(true)
    try {
      await killSwitchService.toggle(tenant_id, action)
      setIsActive(action === 'engage')
      addToast?.(
        action === 'engage' ? 'System isolation enforced.' : 'System recovery initialized.',
        action === 'engage' ? 'error' : 'success',
      )
      await fetchStatus()
    } catch (err) {
      addToast?.(err.message || 'Kill switch operation failed.', 'error')
    } finally {
      setActionLoading(false)
    }
  }

  if (!canViewKillSwitch) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="page-header">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl border bg-white/[0.02] border-white/[0.06]">
              <AlertOctagon size={20} className="text-neutral-400" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Emergency Kill Switch</h1>
              <p className="text-xs text-neutral-500 mt-0.5">Instantly isolate all AI agents in this tenant</p>
            </div>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center py-20 gap-5">
          <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <Lock size={24} className="text-red-400" aria-hidden="true" />
          </div>
          <div className="text-center space-y-2">
            <h2 className="text-lg font-bold text-white">Access Restricted</h2>
            <p className="text-sm text-neutral-500 max-w-sm">
              Kill Switch controls are restricted to administrators only.
              Contact your tenant admin if you need emergency access.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-fade-in">

      {/* ── Header ── */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          <div className={`p-2.5 rounded-xl border transition-all duration-500 ${
            isActive
              ? 'bg-red-500/10 border-red-500/30'
              : 'bg-white/[0.02] border-white/[0.06]'
          }`}>
            <AlertOctagon size={20} className={isActive ? 'text-red-400' : 'text-neutral-400'} aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Emergency Kill Switch</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Instantly isolate all AI agents in this tenant</p>
          </div>
        </div>
        <button
          type="button"
          onClick={fetchStatus}
          aria-label="Refresh kill switch status"
          className="p-2 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.05] transition-colors"
        >
          <RefreshCw size={15} aria-hidden="true" />
        </button>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="error-banner" role="alert">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-400 shrink-0" aria-hidden="true" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* ── Main action card ── */}
        <div className="xl:col-span-2">
          <Card className={`relative overflow-hidden transition-all duration-700 ${isActive ? 'border-red-500/20' : ''}`}>
            {isActive && (
              <div className="absolute inset-0 bg-gradient-to-br from-red-500/[0.06] via-transparent to-transparent pointer-events-none" aria-hidden="true" />
            )}

            <div className="relative flex flex-col items-center text-center space-y-8 py-6">
              {/* Status indicator */}
              <div className={`w-32 h-32 rounded-full border-2 flex items-center justify-center transition-all duration-700 ${
                isActive
                  ? 'border-red-500 bg-red-500/15 text-red-400'
                  : 'border-white/[0.08] bg-white/[0.02] text-neutral-600'
              }`}>
                <Power size={52} className={isActive ? 'animate-pulse' : ''} aria-hidden="true" />
              </div>

              {/* Status text */}
              <div className="space-y-3">
                <p className="label-standard">Global Containment Status</p>
                <h2 className={`text-3xl font-black tracking-tight uppercase ${isActive ? 'text-red-400' : 'text-white'}`}>
                  {isActive ? 'System Isolated' : 'All Systems Nominal'}
                </h2>
                <div className="flex items-center justify-center gap-3 flex-wrap">
                  <span className="px-3 py-1 rounded-full bg-white/[0.04] border border-white/[0.06] text-xs text-neutral-400">
                    Tenant: {tenant_id || 'SYS_GLOBAL'}
                  </span>
                  <span className="px-3 py-1 rounded-full bg-white/[0.04] border border-white/[0.06] text-xs text-neutral-400 flex items-center gap-1.5">
                    <Lock size={10} aria-hidden="true" /> AES-256
                  </span>
                </div>
              </div>

              {/* Description */}
              <p className="text-xs text-neutral-500 max-w-md leading-relaxed">
                {isActive
                  ? 'Isolation is active across all microservices. The gateway is returning 403 for all tenant ingress.'
                  : 'Activating the kill switch sends a high-priority interrupt to the OPA cluster, instantly suspending all agent behaviors.'}
              </p>

              {/* Action button */}
              <div className="w-full max-w-xs">
                {loading ? (
                  <div className="h-12 rounded-xl bg-white/[0.04] animate-pulse" />
                ) : (
                  <Button
                    variant={isActive ? 'secondary' : 'danger'}
                    loading={actionLoading}
                    onClick={() => setConfirmOpen(true)}
                    className="w-full h-12 rounded-xl text-sm font-bold"
                  >
                    {isActive ? (
                      <><RefreshCw size={16} aria-hidden="true" /> Restore Systems</>
                    ) : (
                      <><ShieldAlert size={16} aria-hidden="true" /> Trigger Global Isolation</>
                    )}
                  </Button>
                )}
              </div>
            </div>
          </Card>
        </div>

        {/* ── Side panels ── */}
        <div className="space-y-4">
          <Card title="Containment Status">
            <div className="space-y-5">
              <StatusRow label="Edge Gateway"    isActive={isActive} activeLabel="BLOCKED"   idleLabel="NOMINAL" />
              <StatusRow label="Behavior Kernel" isActive={isActive} activeLabel="SUSPENDED" idleLabel="NOMINAL" />
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-neutral-500">Redis State Sync</span>
                  <div className="flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-500" aria-hidden="true" />
                    <span className="text-xs font-bold text-green-400">SYNCHRONIZED</span>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          <Card title="Protocol Integrity">
            <div className="flex items-start gap-3 p-3 bg-blue-500/[0.04] border border-blue-500/10 rounded-xl">
              <Zap size={15} className="text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-xs text-blue-400/80 leading-relaxed">
                Isolation status is cryptographically signed and stored in the global audit chain. Any toggle event triggers forensic capture.
              </p>
            </div>
          </Card>
        </div>
      </div>

      {/* ── Confirmation modal ── */}
      <Modal
        isOpen={confirmOpen}
        title={isActive ? 'Restore Systems?' : 'Trigger Global Isolation?'}
        onClose={() => setConfirmOpen(false)}
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setConfirmOpen(false)}>Cancel</Button>
            <Button
              variant={isActive ? 'secondary' : 'danger'}
              size="sm"
              onClick={handleToggle}
            >
              {isActive ? 'Restore Systems' : 'Confirm Isolation'}
            </Button>
          </>
        }
      >
        {isActive ? (
          <>
            <p className="text-sm text-neutral-300">
              This will lift the isolation barrier and restore connectivity for all agents in this tenant.
            </p>
            <p className="text-xs text-neutral-500 mt-2">
              Agents will resume normal operation. Verify that the threat has been resolved before proceeding.
            </p>
          </>
        ) : (
          <>
            <div className="flex items-start gap-3 p-3 rounded-xl bg-red-500/[0.06] border border-red-500/15 mb-4">
              <AlertTriangle size={15} className="text-red-400 shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-xs text-red-400">
                This will immediately block all AI agent traffic for this tenant across all services.
              </p>
            </div>
            <p className="text-sm text-neutral-300">
              Confirm global isolation for tenant <span className="font-bold text-white">{tenant_id || 'SYS_GLOBAL'}</span>?
            </p>
            <p className="text-xs text-neutral-500 mt-2">
              This action requires admin intervention to reverse. It will be logged in the audit chain.
            </p>
          </>
        )}
      </Modal>
    </div>
  )
}

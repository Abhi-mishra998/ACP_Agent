import React, { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, Copy, CheckCircle2, LogIn, Clock, AlertTriangle } from 'lucide-react'

const COUNTDOWN_SECONDS = 12

export default function IncidentOverlay({ incident, onDismiss }) {
  const [countdown, setCountdown]   = useState(COUNTDOWN_SECONDS)
  const [copied,    setCopied]      = useState(false)
  const [dismissed, setDismissed]   = useState(false)

  // Auto-countdown
  useEffect(() => {
    if (!incident) return
    setCountdown(COUNTDOWN_SECONDS)
    setDismissed(false)
    setCopied(false)

    const tick = setInterval(() => {
      setCountdown((n) => {
        if (n <= 1) {
          clearInterval(tick)
          onDismiss?.()
          return 0
        }
        return n - 1
      })
    }, 1000)

    return () => clearInterval(tick)
  }, [incident, onDismiss])

  const copyReport = useCallback(async () => {
    if (!incident) return
    const report = [
      `ACP SECURITY INCIDENT REPORT`,
      `──────────────────────────────`,
      `Incident ID : ${incident.incidentId}`,
      `Timestamp   : ${incident.timestamp}`,
      `Reason      : ${incident.reasonLabel} (${incident.reason})`,
      `Path        : ${incident.url}`,
      `Status      : ${incident.statusCode ?? 'N/A'}`,
    ].join('\n')
    await navigator.clipboard.writeText(report).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2500)
  }, [incident])

  const handleReauth = useCallback(() => {
    setDismissed(true)
    onDismiss?.()
  }, [onDismiss])

  if (!incident || dismissed) return null

  const progressPct = (countdown / COUNTDOWN_SECONDS) * 100

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="incident-title"
      aria-describedby="incident-desc"
    >
      {/* Backdrop with red edge glow */}
      <div
        className="absolute inset-0 bg-black/90"
        style={{
          background: 'radial-gradient(ellipse at 50% 0%, rgba(239,68,68,0.12) 0%, rgba(0,0,0,0.95) 60%)',
        }}
        aria-hidden="true"
      />

      {/* Corner scanlines effect */}
      <div
        className="absolute inset-0 pointer-events-none"
        aria-hidden="true"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(239,68,68,0.015) 2px, rgba(239,68,68,0.015) 4px)',
        }}
      />

      {/* Panel */}
      <div
        className="relative w-full max-w-lg mx-4 rounded-2xl overflow-hidden"
        style={{
          background:  'rgba(8, 4, 4, 0.98)',
          border:      '1px solid rgba(239,68,68,0.25)',
          boxShadow:   '0 0 80px rgba(239,68,68,0.15), 0 0 0 1px rgba(239,68,68,0.1), inset 0 1px 0 rgba(255,255,255,0.04)',
        }}
      >
        {/* Countdown progress bar */}
        <div
          className="h-0.5 bg-red-500/20 relative overflow-hidden"
          aria-hidden="true"
        >
          <div
            className="absolute inset-y-0 left-0 bg-red-500 transition-none"
            style={{ width: `${progressPct}%`, boxShadow: '0 0 8px rgba(239,68,68,0.8)' }}
          />
        </div>

        {/* Header */}
        <div className="flex items-start gap-4 p-6 border-b border-red-500/10">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 bg-red-500/10 border border-red-500/20"
            style={{ boxShadow: '0 0 20px rgba(239,68,68,0.2)' }}
            aria-hidden="true"
          >
            <ShieldAlert size={20} className="text-red-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span
                className="text-[10px] font-bold uppercase tracking-[0.2em] text-red-500"
                style={{ textShadow: '0 0 12px rgba(239,68,68,0.5)' }}
              >
                Security Incident
              </span>
              <div className="w-1.5 h-1.5 rounded-full bg-red-500 pulse-critical" aria-hidden="true" />
            </div>
            <h2
              id="incident-title"
              className="text-base font-bold text-white leading-tight"
            >
              {incident.reasonLabel}
            </h2>
            <p
              id="incident-desc"
              className="text-xs text-neutral-500 mt-0.5"
            >
              Authentication boundary violated — session terminated
            </p>
          </div>
        </div>

        {/* Incident details */}
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Incident ID',  value: incident.incidentId?.slice(0, 18) + '…', mono: true },
              { label: 'Timestamp',    value: new Date(incident.timestamp).toLocaleTimeString(), mono: true },
              { label: 'Reason Code',  value: incident.reason, mono: true },
              { label: 'Request Path', value: incident.url, mono: true },
            ].map(({ label, value, mono }) => (
              <div key={label} className="space-y-1">
                <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">{label}</p>
                <p className={`text-xs text-neutral-300 truncate ${mono ? 'font-mono' : ''}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Security context note */}
          <div className="flex items-start gap-2.5 p-3 rounded-xl bg-red-500/[0.04] border border-red-500/10">
            <AlertTriangle size={13} className="text-red-400 shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-[11px] text-red-300/70 leading-relaxed">
              This event has been recorded in the audit log. If you believe this is unauthorized access,
              contact your security team with the incident ID above.
            </p>
          </div>

          {/* Countdown */}
          <div className="flex items-center gap-2">
            <Clock size={12} className="text-neutral-600" aria-hidden="true" />
            <span className="text-xs text-neutral-600">
              Redirecting to login in{' '}
              <span
                className={`font-mono font-bold ${countdown <= 3 ? 'text-red-400' : 'text-neutral-400'}`}
                aria-live="polite"
                aria-atomic="true"
              >
                {countdown}s
              </span>
            </span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 px-6 py-4 border-t border-red-500/10 bg-red-500/[0.02]">
          <button
            onClick={handleReauth}
            className="
              flex-1 flex items-center justify-center gap-2
              px-4 py-2.5 rounded-xl text-xs font-bold text-white
              bg-red-500/20 border border-red-500/30
              hover:bg-red-500/30 hover:border-red-500/50
              transition-all active:scale-[0.98]
            "
            style={{ boxShadow: '0 0 20px rgba(239,68,68,0.1)' }}
            aria-label="Re-authenticate now"
          >
            <LogIn size={13} aria-hidden="true" />
            Re-authenticate
          </button>
          <button
            onClick={copyReport}
            className="
              flex items-center justify-center gap-2
              px-4 py-2.5 rounded-xl text-xs font-bold
              bg-white/[0.04] border border-white/[0.08]
              hover:bg-white/[0.07] hover:border-white/[0.14]
              transition-all active:scale-[0.98]
              shrink-0
            "
            style={{ color: copied ? '#22c55e' : '#71717a' }}
            aria-label={copied ? 'Incident report copied' : 'Copy incident report'}
          >
            {copied
              ? <><CheckCircle2 size={13} aria-hidden="true" /> Copied</>
              : <><Copy size={13} aria-hidden="true" /> Copy Report</>
            }
          </button>
        </div>
      </div>
    </div>
  )
}

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, AlertTriangle, Shield, Activity, Check, X, ChevronRight } from 'lucide-react'
import { eventBus } from '../../lib/eventBus'

const MAX_ALERTS = 50

const ALERT_META = {
  risk_updated:    { icon: Activity,      color: 'text-amber-400', label: 'Risk Update' },
  tool_executed:   { icon: Activity,      color: 'text-blue-400',  label: 'Tool Executed' },
  policy_decision: { icon: Shield,        color: 'text-purple-400',label: 'Policy Decision' },
  alert:           { icon: AlertTriangle, color: 'text-red-400',   label: 'Security Alert' },
  agent_changed:   { icon: Activity,      color: 'text-green-400', label: 'Agent Changed' },
  insight_generated: { icon: Shield,      color: 'text-blue-400',  label: 'New Insight' },
}

function timeAgo(ts) {
  const diff = Date.now() - ts
  if (diff < 60_000)   return `${Math.floor(diff / 1000)}s ago`
  if (diff < 3_600_000)return `${Math.floor(diff / 60_000)}m ago`
  return `${Math.floor(diff / 3_600_000)}h ago`
}

export default function NotificationCenter() {
  const navigate         = useNavigate()
  const [open, setOpen]  = useState(false)
  const [alerts, setAlerts] = useState([])
  const panelRef         = useRef(null)

  const addAlert = useCallback((type, data) => {
    setAlerts((prev) => {
      const entry = {
        id:           crypto.randomUUID(),
        type,
        data,
        ts:           Date.now(),
        acknowledged: false,
      }
      return [entry, ...prev].slice(0, MAX_ALERTS)
    })
  }, [])

  useEffect(() => {
    const unsubs = Object.keys(ALERT_META).map((event) =>
      eventBus.on(event, (data) => addAlert(event, data))
    )
    return () => unsubs.forEach((fn) => fn())
  }, [addAlert])

  useEffect(() => {
    if (!open) return
    const handle = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [open])

  useEffect(() => {
    if (!open) return
    const handle = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('keydown', handle)
    return () => document.removeEventListener('keydown', handle)
  }, [open])

  const unread = alerts.filter((a) => !a.acknowledged).length

  const acknowledge = (id) => {
    setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a))
  }

  const acknowledgeAll = () => {
    setAlerts((prev) => prev.map((a) => ({ ...a, acknowledged: true })))
  }

  const dismiss = (id) => {
    setAlerts((prev) => prev.filter((a) => a.id !== id))
  }

  const handleDrillDown = (alert) => {
    acknowledge(alert.id)
    setOpen(false)
    const agentId = alert.data?.agent_id
    if (agentId) navigate(`/forensics?agent=${agentId}`)
    else navigate('/security')
  }

  return (
    <div className="relative" ref={panelRef}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label={`Notifications — ${unread} unread`}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="relative p-2 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.06] transition-colors"
      >
        <Bell size={16} aria-hidden="true" />
        {unread > 0 && (
          <span
            className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-red-500 flex items-center justify-center text-[9px] font-bold text-white"
            aria-hidden="true"
            style={{ boxShadow: '0 0 8px rgba(239,68,68,0.6)' }}
          >
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Notification center"
          className="
            absolute right-0 mt-2 w-96 max-h-[520px] flex flex-col
            bg-[var(--bg-surface-elevated)] border border-[var(--border-default)]
            rounded-xl shadow-2xl overflow-hidden
            animate-slide-down z-50
          "
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)] shrink-0">
            <div className="flex items-center gap-2">
              <Bell size={13} className="text-neutral-500" aria-hidden="true" />
              <span className="text-xs font-bold text-white uppercase tracking-wide">Notifications</span>
              {unread > 0 && (
                <span className="text-[10px] font-bold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded-full">
                  {unread} new
                </span>
              )}
            </div>
            {alerts.length > 0 && (
              <button
                onClick={acknowledgeAll}
                className="text-xs text-neutral-500 hover:text-white transition-colors"
                aria-label="Acknowledge all notifications"
              >
                Mark all read
              </button>
            )}
          </div>

          {/* List */}
          <div className="overflow-y-auto flex-1">
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 gap-3 text-neutral-700">
                <Bell size={28} className="opacity-30" aria-hidden="true" />
                <p className="text-xs">No notifications yet</p>
              </div>
            ) : (
              alerts.map((alert) => {
                const meta = ALERT_META[alert.type] ?? ALERT_META.alert
                const Icon = meta.icon
                return (
                  <div
                    key={alert.id}
                    className={`
                      group flex items-start gap-3 px-4 py-3 border-b border-[var(--border-subtle)]
                      hover:bg-white/[0.03] transition-colors
                      ${!alert.acknowledged ? 'bg-white/[0.015]' : ''}
                    `}
                  >
                    {!alert.acknowledged && (
                      <div
                        className="mt-1.5 w-1.5 h-1.5 rounded-full bg-red-500 shrink-0 animate-pulse"
                        aria-hidden="true"
                      />
                    )}
                    {alert.acknowledged && <div className="mt-1.5 w-1.5 h-1.5 shrink-0" aria-hidden="true" />}

                    <div className={`p-1.5 rounded-lg bg-white/[0.04] shrink-0 mt-0.5 ${meta.color}`}>
                      <Icon size={12} aria-hidden="true" />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2 mb-0.5">
                        <span className="text-[11px] font-bold text-white uppercase tracking-wide">
                          {meta.label}
                        </span>
                        <span className="text-[10px] text-neutral-600 shrink-0">{timeAgo(alert.ts)}</span>
                      </div>
                      {alert.data?.agent_id && (
                        <p className="text-[11px] text-neutral-500 font-mono truncate">
                          Agent: {alert.data.agent_id?.slice(0, 16)}…
                        </p>
                      )}
                      {alert.data?.reason && (
                        <p className="text-[11px] text-neutral-500 truncate italic">
                          "{alert.data.reason}"
                        </p>
                      )}
                      <div className="flex items-center gap-2 mt-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={() => handleDrillDown(alert)}
                          className="text-[10px] text-neutral-400 hover:text-white flex items-center gap-1 transition-colors"
                          aria-label="Drill down to forensics"
                        >
                          Investigate <ChevronRight size={10} />
                        </button>
                        <button
                          onClick={() => acknowledge(alert.id)}
                          className="text-[10px] text-neutral-600 hover:text-green-400 flex items-center gap-1 transition-colors"
                          aria-label="Acknowledge notification"
                        >
                          <Check size={10} /> Ack
                        </button>
                        <button
                          onClick={() => dismiss(alert.id)}
                          className="text-[10px] text-neutral-600 hover:text-red-400 flex items-center gap-1 transition-colors"
                          aria-label="Dismiss notification"
                        >
                          <X size={10} />
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>

          {/* Footer */}
          {alerts.length > 0 && (
            <div className="px-4 py-2 border-t border-[var(--border-subtle)] shrink-0 flex items-center justify-between">
              <span className="text-[10px] text-neutral-600">{alerts.length} total</span>
              <button
                onClick={() => { setAlerts([]); setOpen(false) }}
                className="text-[10px] text-neutral-600 hover:text-red-400 transition-colors"
              >
                Clear all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

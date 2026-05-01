import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Server,
  Clock,
  Activity,
} from 'lucide-react'
import { dashboardService } from '../services/api'

const STATUS_CONFIG = {
  healthy:     { icon: CheckCircle,   color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/20',  label: 'Healthy' },
  degraded:    { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', label: 'Degraded' },
  unreachable: { icon: XCircle,       color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/20',    label: 'Unreachable' },
  unknown:     { icon: Activity,      color: 'text-neutral-400',bg: 'bg-neutral-500/10',border: 'border-neutral-500/20',label: 'Unknown' },
}

const OVERALL_CONFIG = {
  healthy:  { color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30',  label: 'All Systems Operational' },
  degraded: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', label: 'Partial Outage' },
  down:     { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    label: 'Major Outage' },
  unknown:  { color: 'text-neutral-400',bg: 'bg-neutral-500/10',border: 'border-neutral-500/20',label: 'Checking...' },
}

function ServiceCard({ name, info }) {
  const cfg = STATUS_CONFIG[info?.status] || STATUS_CONFIG.unknown
  const Icon = cfg.icon
  const latency = info?.latency_ms

  return (
    <div className={`rounded-xl border ${cfg.border} ${cfg.bg} p-4 flex flex-col gap-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">
            <Server size={15} className="text-neutral-400" />
          </div>
          <span className="text-sm font-semibold text-white capitalize">{name}</span>
        </div>
        <div className={`flex items-center gap-1.5 ${cfg.color}`}>
          <Icon size={14} />
          <span className="text-xs font-medium">{cfg.label}</span>
        </div>
      </div>

      <div className="flex items-center gap-4 text-xs text-neutral-500">
        {latency !== undefined && (
          <span className="flex items-center gap-1">
            <Clock size={11} />
            {latency}ms
          </span>
        )}
        {info?.error && (
          <span className="text-red-400/80 truncate">{info.error}</span>
        )}
      </div>

      {latency !== undefined && (
        <div className="h-1 rounded-full bg-white/5 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-700 ${
              latency < 100 ? 'bg-green-500' :
              latency < 300 ? 'bg-yellow-500' : 'bg-red-500'
            }`}
            style={{ width: `${Math.min(100, (latency / 500) * 100)}%` }}
          />
        </div>
      )}
    </div>
  )
}

function OverallBanner({ status, healthy, total, lastChecked }) {
  const cfg = OVERALL_CONFIG[status] || OVERALL_CONFIG.unknown
  const Icon = status === 'healthy' ? CheckCircle : status === 'degraded' ? AlertTriangle : XCircle

  return (
    <div className={`rounded-2xl border ${cfg.border} ${cfg.bg} p-6 flex items-center justify-between`}>
      <div className="flex items-center gap-4">
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${cfg.bg} border ${cfg.border}`}>
          <Icon size={22} className={cfg.color} />
        </div>
        <div>
          <p className={`text-lg font-bold ${cfg.color}`}>{cfg.label}</p>
          <p className="text-sm text-neutral-400 mt-0.5">
            {healthy}/{total} services operational
          </p>
        </div>
      </div>
      {lastChecked && (
        <p className="text-xs text-neutral-600 font-mono">
          Last checked {new Date(lastChecked * 1000).toLocaleTimeString()}
        </p>
      )}
    </div>
  )
}

export default function SystemHealth() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const intervalRef = useRef(null)

  const fetchHealth = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true)
    else if (!data) setLoading(true)

    try {
      const res = await dashboardService.getSystemHealth()
      setData(res)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [data])

  useEffect(() => {
    fetchHealth()
    intervalRef.current = setInterval(() => fetchHealth(), 30_000)
    return () => clearInterval(intervalRef.current)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const services = data?.services || {}
  const gateway = data?.gateway || null

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">System Health</h1>
          <p className="text-xs text-neutral-500 mt-1">
            Live health status for all ACP backend services
          </p>
        </div>
        <button
          onClick={() => fetchHealth(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/5 border border-white/10
                     text-xs text-neutral-300 hover:text-white hover:bg-white/10 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
          {refreshing ? 'Checking...' : 'Refresh'}
        </button>
      </div>

      {/* Overall Banner */}
      {loading && !data ? (
        <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6 animate-pulse h-24" />
      ) : error ? (
        <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6">
          <p className="text-sm text-red-400">Failed to fetch health: {error}</p>
        </div>
      ) : (
        <OverallBanner
          status={data?.status || 'unknown'}
          healthy={data?.healthy ?? 0}
          total={data?.total ?? 0}
          lastChecked={data?.ts}
        />
      )}

      {/* Service Grid */}
      {loading && !data ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 9 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-white/5 bg-white/[0.02] p-4 animate-pulse h-28" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {gateway && <ServiceCard name="gateway" info={gateway} />}
          {Object.entries(services).map(([name, info]) => (
            <ServiceCard key={name} name={name} info={info} />
          ))}
        </div>
      )}

      {/* Auto-refresh note */}
      <p className="text-xs text-neutral-700 text-center">
        Auto-refreshes every 30 seconds
      </p>
    </div>
  )
}

import React, { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { auditService } from '../services/api'
import { useAuth } from '../hooks/useAuth'
import { eventBus } from '../lib/eventBus'
import {
  ShieldCheck, ShieldAlert, AlertCircle, Search, RefreshCw,
  ChevronLeft, ChevronRight, ChevronDown, ChevronUp,
  Activity, FileText, Hash, Clock, Filter, Eye,
  ToggleLeft, ToggleRight, CheckCircle2, XCircle,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import SkeletonLoader from '../components/Common/SkeletonLoader'

/* ── Decision badge ────────────────────────────────────────────────────────── */
const DECISION_STYLES = {
  allow:    'text-green-400  bg-green-500/10  border-green-500/20',
  deny:     'text-red-400    bg-red-500/10    border-red-500/20',
  monitor:  'text-blue-400   bg-blue-500/10   border-blue-500/20',
  throttle: 'text-amber-400  bg-amber-500/10  border-amber-500/20',
  escalate: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  kill:     'text-red-600    bg-red-900/20    border-red-800/40',
}

function DecisionBadge({ decision }) {
  const d = (decision || 'unknown').toLowerCase()
  return (
    <span className={`status-badge ${DECISION_STYLES[d] ?? 'text-neutral-400 bg-white/5 border-white/10'}`}>
      {d.toUpperCase()}
    </span>
  )
}

/* ── Risk pill ─────────────────────────────────────────────────────────────── */
function RiskPill({ score }) {
  const n = Number(score) || 0
  const color =
    n < 30 ? 'text-green-400 bg-green-500/10 border-green-500/20' :
    n < 70 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' :
             'text-red-400   bg-red-500/10   border-red-500/20'
  return (
    <span className={`status-badge ${color}`}>
      <Activity size={10} aria-hidden="true" />
      {n}
    </span>
  )
}

/* ── Expanded row ──────────────────────────────────────────────────────────── */
function ExpandedRow({ log }) {
  let meta = null
  try { meta = typeof log.metadata_json === 'string' ? JSON.parse(log.metadata_json) : log.metadata_json } catch {}

  return (
    <div className="px-5 py-4 bg-white/[0.015] border-t border-white/5 space-y-4 animate-fade-in">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          { label: 'Request ID',  value: log.request_id },
          { label: 'Event Hash',  value: log.event_hash },
          { label: 'Prev Hash',   value: log.prev_hash },
          { label: 'Reason',      value: log.reason ? `"${log.reason}"` : null, italic: true },
        ].map(({ label, value, italic }) => (
          <div key={label} className="space-y-1.5">
            <p className="label-standard">{label}</p>
            <p className={`font-mono text-xs text-neutral-300 break-all ${italic ? 'italic text-neutral-400' : ''}`}>
              {value || '—'}
            </p>
          </div>
        ))}
      </div>
      {meta && (
        <div className="space-y-1.5">
          <p className="label-standard">Metadata</p>
          <pre className="font-mono text-xs text-neutral-400 bg-black/30 border border-white/5 rounded-xl p-4 overflow-x-auto leading-relaxed">
            {JSON.stringify(meta, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

/* ── Constants ─────────────────────────────────────────────────────────────── */
const PAGE_SIZE = 20
const AUTO_REFRESH_MS = 30_000
const DECISION_OPTIONS = ['all', 'allow', 'deny', 'monitor', 'throttle', 'escalate', 'kill']

/* ── Component ─────────────────────────────────────────────────────────────── */
export default function AuditLogs() {
  useAuth()
  const navigate = useNavigate()

  const [searchParams] = useSearchParams()
  const urlAgent = searchParams.get('agent') || ''

  const [summary,        setSummary]        = useState(null)
  const [summaryLoading, setSummaryLoading] = useState(true)
  const [logs,           setLogs]           = useState([])
  const [logsLoading,    setLogsLoading]    = useState(true)
  const [logsError,      setLogsError]      = useState('')
  const [totalCount,     setTotalCount]     = useState(0)
  const [page,           setPage]           = useState(0)

  const [filterAgentId,  setFilterAgentId]  = useState(urlAgent)
  const [filterDecision, setFilterDecision] = useState('all')
  const [filterTool,     setFilterTool]     = useState('')
  const [filterFrom,     setFilterFrom]     = useState('')
  const [filterTo,       setFilterTo]       = useState('')
  const [isSearching,    setIsSearching]    = useState(false)
  const [hasSearched,    setHasSearched]    = useState(false)

  const [expandedId,       setExpandedId]       = useState(null)
  const [integrityStatus,  setIntegrityStatus]  = useState(null)
  const [integrityMessage, setIntegrityMessage] = useState('')
  const [autoRefresh,      setAutoRefresh]      = useState(false)

  const autoRefreshRef = useRef(null)
  const mountedRef     = useRef(true)

  const fetchSummary = useCallback(async () => {
    try {
      const res = await auditService.getSummary()
      if (mountedRef.current) { setSummary(res?.data || res || {}); setSummaryLoading(false) }
    } catch {
      if (mountedRef.current) setSummaryLoading(false)
    }
  }, [])

  const fetchLogs = useCallback(async (currentPage = 0) => {
    setLogsLoading(true)
    setLogsError('')
    try {
      const res = await auditService.getLogs(PAGE_SIZE, currentPage * PAGE_SIZE)
      if (!mountedRef.current) return
      const data  = res?.data || res || {}
      const items = Array.isArray(data) ? data : (data.logs || data.items || [])
      setLogs(items)
      setTotalCount(data.total || items.length)
    } catch (err) {
      if (mountedRef.current) setLogsError(err.message || 'Failed to load audit logs.')
    } finally {
      if (mountedRef.current) setLogsLoading(false)
    }
  }, [])

  const handleSearch = useCallback(async (currentPage = 0) => {
    setIsSearching(true)
    setLogsError('')
    setHasSearched(true)
    try {
      const params = { limit: PAGE_SIZE, offset: currentPage * PAGE_SIZE }
      if (filterAgentId.trim())      params.agent_id   = filterAgentId.trim()
      if (filterDecision !== 'all')  params.decision   = filterDecision
      if (filterTool.trim())         params.tool       = filterTool.trim()
      if (filterFrom)                params.start_date = filterFrom
      if (filterTo)                  params.end_date   = filterTo

      const res = await auditService.searchLogs(params)
      if (!mountedRef.current) return
      const data  = res?.data || res || {}
      const items = Array.isArray(data) ? data : (data.logs || data.items || [])
      setLogs(items)
      setTotalCount(data.total || items.length)
    } catch (err) {
      if (mountedRef.current) setLogsError(err.message || 'Search failed.')
    } finally {
      if (mountedRef.current) setIsSearching(false)
    }
  }, [filterAgentId, filterDecision, filterTool, filterFrom, filterTo])

  const handleVerifyIntegrity = async () => {
    setIntegrityStatus('checking')
    try {
      const res = await auditService.verifyIntegrity()
      const d = res?.data || res || {}
      if (mountedRef.current) {
        setIntegrityStatus(d.valid ? 'valid' : 'broken')
        setIntegrityMessage(d.error || '')
      }
    } catch (err) {
      if (mountedRef.current) {
        setIntegrityStatus('broken')
        setIntegrityMessage(err.message || 'Verification failed.')
      }
    }
  }

  const handlePageChange = (newPage) => {
    setPage(newPage)
    hasSearched ? handleSearch(newPage) : fetchLogs(newPage)
    setExpandedId(null)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const refreshTick = useCallback(() => {
    fetchSummary()
    hasSearched ? handleSearch(page) : fetchLogs(page)
  }, [fetchSummary, fetchLogs, handleSearch, hasSearched, page])

  useEffect(() => {
    if (autoRefresh) { autoRefreshRef.current = setInterval(refreshTick, AUTO_REFRESH_MS) }
    else { clearInterval(autoRefreshRef.current) }
    return () => clearInterval(autoRefreshRef.current)
  }, [autoRefresh, refreshTick])

  useEffect(() => {
    mountedRef.current = true
    fetchSummary()
    if (urlAgent) { setHasSearched(true) } else { fetchLogs(0) }
    return () => { mountedRef.current = false }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (urlAgent) handleSearch(0)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Real-time: refresh summary + latest page when the SSE bus fires a new decision/tool event
  useEffect(() => {
    const refresh = () => {
      fetchSummary()
      if (!hasSearched) fetchLogs(0)
    }
    const u1 = eventBus.on('tool_executed',    refresh)
    const u2 = eventBus.on('policy_decision',  refresh)
    const u3 = eventBus.on('risk_updated',     () => fetchSummary())
    return () => { u1(); u2(); u3() }
  }, [fetchSummary, fetchLogs, hasSearched])

  /* ── Loading skeleton ── */
  if (summaryLoading && logsLoading) return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => <SkeletonLoader key={i} variant="card" />)}
      </div>
      <SkeletonLoader variant="card" />
      <SkeletonLoader variant="row" count={6} />
    </div>
  )

  const s           = summary || {}
  const totalCalls  = s.total_calls   ?? 0
  const totalDenials = s.total_denials ?? 0
  const activeAgents = s.active_agents ?? 0
  const avgRiskScore = typeof s.avg_risk_score === 'number' ? s.avg_risk_score.toFixed(1) : '—'
  const totalPages   = Math.max(1, Math.ceil(totalCount / PAGE_SIZE))

  return (
    <div className="space-y-6 animate-fade-in">

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Audit Logs</h1>
          <p className="text-xs text-neutral-500 mt-0.5">Immutable chain-verified event stream</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Auto-refresh toggle */}
          <button
            type="button"
            onClick={() => setAutoRefresh(v => !v)}
            aria-pressed={autoRefresh}
            aria-label={autoRefresh ? 'Disable auto-refresh' : 'Enable auto-refresh'}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.02] border border-white/5 hover:border-white/[0.12] transition-colors text-xs text-neutral-400"
          >
            {autoRefresh
              ? <ToggleRight size={16} className="text-green-400" aria-hidden="true" />
              : <ToggleLeft  size={16} className="text-neutral-600" aria-hidden="true" />}
            Auto-Refresh
          </button>

          {/* Chain integrity */}
          <button
            type="button"
            onClick={handleVerifyIntegrity}
            disabled={integrityStatus === 'checking'}
            aria-label="Verify audit chain integrity"
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs transition-colors ${
              integrityStatus === 'valid'
                ? 'bg-green-500/10 border-green-500/20 text-green-400'
                : integrityStatus === 'broken'
                ? 'bg-red-500/10 border-red-500/20 text-red-400'
                : 'bg-white/[0.02] border-white/5 text-neutral-400 hover:border-white/[0.12] hover:text-white'
            }`}
          >
            {integrityStatus === 'checking' ? (
              <RefreshCw size={13} className="animate-spin" aria-hidden="true" />
            ) : integrityStatus === 'valid' ? (
              <CheckCircle2 size={13} aria-hidden="true" />
            ) : integrityStatus === 'broken' ? (
              <XCircle size={13} aria-hidden="true" />
            ) : (
              <ShieldCheck size={13} aria-hidden="true" />
            )}
            {integrityStatus === 'checking' ? 'Verifying…'  :
             integrityStatus === 'valid'    ? 'Chain Valid'  :
             integrityStatus === 'broken'   ? 'Chain Broken' :
             'Verify Integrity'}
          </button>
          {integrityStatus === 'broken' && integrityMessage && (
            <span className="text-xs text-red-400 font-mono" role="alert">{integrityMessage}</span>
          )}
        </div>
      </div>

      {/* ── Summary KPIs ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <Card title="Total API Calls"  value={totalCalls.toLocaleString()}  icon={Activity}   subtitle="All logged gateway events" />
        <Card title="Total Denials"    value={totalDenials.toLocaleString()} icon={ShieldAlert} subtitle="Blocked request events" />
        <Card title="Active Agents"    value={activeAgents.toLocaleString()} icon={FileText}    subtitle="Distinct agent identities" />
        <Card title="Avg Risk Score"   value={avgRiskScore}                  icon={Hash}        subtitle="Across all audit events" />
      </div>

      {/* ── Filter / Search ── */}
      <Card title="Search &amp; Filter" icon={Filter}>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          <div className="space-y-1.5">
            <label htmlFor="filter-agent" className="label-standard">Agent ID</label>
            <input
              id="filter-agent"
              type="text"
              value={filterAgentId}
              onChange={e => setFilterAgentId(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch(0)}
              placeholder="UUID or partial…"
              className="input-standard h-9 font-mono"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="filter-decision" className="label-standard">Decision</label>
            <select
              id="filter-decision"
              value={filterDecision}
              onChange={e => setFilterDecision(e.target.value)}
              className="input-standard h-9 uppercase"
            >
              {DECISION_OPTIONS.map(d => (
                <option key={d} value={d} className="bg-[#080808]">{d}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <label htmlFor="filter-tool" className="label-standard">Tool</label>
            <input
              id="filter-tool"
              type="text"
              value={filterTool}
              onChange={e => setFilterTool(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSearch(0)}
              placeholder="Tool name…"
              className="input-standard h-9 font-mono"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="filter-from" className="label-standard">From</label>
            <input
              id="filter-from"
              type="date"
              value={filterFrom}
              onChange={e => setFilterFrom(e.target.value)}
              className="input-standard h-9"
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="filter-to" className="label-standard">To</label>
            <input
              id="filter-to"
              type="date"
              value={filterTo}
              onChange={e => setFilterTo(e.target.value)}
              className="input-standard h-9"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 pt-4 mt-2 border-t border-white/5">
          <Button
            size="sm"
            loading={isSearching}
            onClick={() => { setPage(0); handleSearch(0) }}
          >
            <Search size={13} aria-hidden="true" />
            Search
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setFilterAgentId('')
              setFilterDecision('all')
              setFilterTool('')
              setFilterFrom('')
              setFilterTo('')
              setHasSearched(false)
              setPage(0)
              fetchLogs(0)
            }}
          >
            Clear Filters
          </Button>
          <span className="ml-auto text-xs text-neutral-600">
            {totalCount.toLocaleString()} record{totalCount !== 1 ? 's' : ''}
          </span>
        </div>
      </Card>

      {/* ── Error ── */}
      {logsError && (
        <div className="error-banner" role="alert">
          <div className="flex items-center gap-2">
            <AlertCircle size={14} className="text-red-400 shrink-0" aria-hidden="true" />
            <p className="text-xs text-red-400">{logsError}</p>
          </div>
          <button
            type="button"
            onClick={() => hasSearched ? handleSearch(page) : fetchLogs(page)}
            className="text-xs text-red-400 underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Log table ── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="section-header">
            <Clock size={14} className="text-neutral-600" aria-hidden="true" />
            Event Stream
            {autoRefresh && (
              <div className="flex items-center gap-1.5 ml-2">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
                <span className="text-xs text-green-500">Live</span>
              </div>
            )}
          </div>
          <span className="text-xs text-neutral-600">
            Page {page + 1} / {totalPages}
          </span>
        </div>

        {logsLoading || isSearching ? (
          <SkeletonLoader variant="row" count={8} />
        ) : (
          <div className="table-container" role="table" aria-label="Audit log entries">
            <div className="table-scroll">
              <table className="table-base min-w-[700px]">
                <thead>
                  <tr>
                    {['Timestamp', 'Agent ID', 'Tool', 'Decision', 'Risk', 'Reason', 'Request ID', '', ''].map((h, i) => (
                      <th key={i} className="table-th first:pl-5">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {logs.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-14 text-center">
                        <div className="flex flex-col items-center gap-3 opacity-40">
                          <FileText size={32} className="text-neutral-700" aria-hidden="true" />
                          <p className="text-xs text-neutral-500">No audit records found</p>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    logs.map((log, idx) => {
                      const isExpanded = expandedId === (log.id || idx)
                      const ts = log.timestamp
                        ? new Date(log.timestamp).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
                        : '—'
                      const agentShort = log.agent_id
                        ? `${log.agent_id.slice(0, 8)}…${log.agent_id.slice(-4)}`
                        : '—'
                      const reqShort = log.request_id ? `${log.request_id.slice(0, 8)}…` : '—'
                      const rowId = log.id || idx

                      return (
                        <React.Fragment key={rowId}>
                          <tr
                            className="table-row cursor-pointer"
                            onClick={() => setExpandedId(isExpanded ? null : rowId)}
                            onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpandedId(isExpanded ? null : rowId) } }}
                            tabIndex={0}
                            aria-expanded={isExpanded}
                            role="row"
                          >
                            <td className="table-td first:pl-5 font-mono whitespace-nowrap">{ts}</td>
                            <td className="table-td font-mono">{agentShort}</td>
                            <td className="table-td font-bold">{log.tool || '—'}</td>
                            <td className="table-td"><DecisionBadge decision={log.decision} /></td>
                            <td className="table-td"><RiskPill score={log.risk_score} /></td>
                            <td className="table-td max-w-[160px] truncate text-neutral-500 italic">
                              {log.reason ? `"${log.reason}"` : '—'}
                            </td>
                            <td className="table-td font-mono text-neutral-600">{reqShort}</td>
                            <td className="table-td pr-2">
                              {log.agent_id && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); navigate(`/forensics?agent=${log.agent_id}`) }}
                                  aria-label={`Investigate agent ${agentShort}`}
                                  className="flex items-center gap-1 text-[10px] text-neutral-600 hover:text-blue-400 transition-colors px-2 py-1 rounded border border-transparent hover:border-blue-500/20 hover:bg-blue-500/[0.04]"
                                >
                                  <Eye size={11} aria-hidden="true" /> Investigate
                                </button>
                              )}
                            </td>
                            <td className="table-td pr-4 text-neutral-500">
                              {isExpanded
                                ? <ChevronUp size={13} aria-hidden="true" />
                                : <ChevronDown size={13} aria-hidden="true" />}
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr role="row">
                              <td colSpan={9} className="p-0">
                                <ExpandedRow log={log} />
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Pagination ── */}
        {totalPages > 1 && !logsLoading && !isSearching && (
          <div className="flex items-center justify-between pt-1">
            <Button
              variant="ghost"
              size="sm"
              disabled={page === 0}
              onClick={() => handlePageChange(page - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft size={14} aria-hidden="true" /> Prev
            </Button>

            <div className="flex items-center gap-1" role="navigation" aria-label="Pagination">
              {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                let p
                if (totalPages <= 7)       p = i
                else if (page < 4)         p = i
                else if (page > totalPages - 5) p = totalPages - 7 + i
                else                       p = page - 3 + i
                return (
                  <button
                    key={p}
                    type="button"
                    onClick={() => handlePageChange(p)}
                    aria-label={`Page ${p + 1}`}
                    aria-current={p === page ? 'page' : undefined}
                    className={`w-7 h-7 rounded text-xs font-bold transition-colors ${
                      p === page
                        ? 'bg-white text-black'
                        : 'text-neutral-600 hover:text-white hover:bg-white/[0.05]'
                    }`}
                  >
                    {p + 1}
                  </button>
                )
              })}
            </div>

            <Button
              variant="ghost"
              size="sm"
              disabled={page >= totalPages - 1}
              onClick={() => handlePageChange(page + 1)}
              aria-label="Next page"
            >
              Next <ChevronRight size={14} aria-hidden="true" />
            </Button>
          </div>
        )}
      </div>
    </div>
  )
}

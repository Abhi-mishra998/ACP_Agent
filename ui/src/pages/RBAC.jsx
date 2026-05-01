import React, { useState, useEffect, useCallback, useRef } from 'react'
import {
  Lock, Plus, Trash2, RefreshCw, Users,
  ShieldCheck, AlertTriangle, ChevronDown, ChevronUp,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import SkeletonLoader from '../components/Common/SkeletonLoader'
import { registryService } from '../services/api'
import { eventBus } from '../lib/eventBus'

const TOOL_OPTIONS = [
  'read_file', 'write_file', 'delete_file',
  'execute_command', 'network_request', 'database_query',
  'send_email', 'list_directory', '*',
]

const ACTION_OPTIONS = ['ALLOW', 'DENY']

const ACTION_STYLES = {
  ALLOW: 'text-green-400 bg-green-500/10 border-green-500/20',
  DENY:  'text-red-400   bg-red-500/10   border-red-500/20',
  allow: 'text-green-400 bg-green-500/10 border-green-500/20',
  deny:  'text-red-400   bg-red-500/10   border-red-500/20',
}

const ROLE_BADGE = {
  ADMIN:            'text-red-400    bg-red-500/10    border-red-500/20',
  SECURITY_OFFICER: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
  ANALYST:          'text-blue-400   bg-blue-500/10   border-blue-500/20',
  VIEWER:           'text-neutral-400 bg-white/[0.04] border-white/[0.08]',
}

function AgentRow({ agent }) {
  const [expanded,    setExpanded]    = useState(false)
  const [permissions, setPermissions] = useState([])
  const [permLoading, setPermLoading] = useState(false)
  const [addOpen,     setAddOpen]     = useState(false)
  const [form,        setForm]        = useState({ tool_name: 'read_file', action: 'ALLOW' })
  const [saving,      setSaving]      = useState(false)
  const [revoking,    setRevoking]    = useState(null)
  const [error,       setError]       = useState('')
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    return () => { mountedRef.current = false }
  }, [])

  const loadPermissions = useCallback(async () => {
    setPermLoading(true)
    setError('')
    try {
      const res  = await registryService.listPermissions(agent.id)
      const list = Array.isArray(res)     ? res
                 : Array.isArray(res?.data) ? res.data
                 : []
      if (mountedRef.current) setPermissions(list)
    } catch (err) {
      if (mountedRef.current) setError(err.message || 'Failed to load permissions.')
    } finally {
      if (mountedRef.current) setPermLoading(false)
    }
  }, [agent.id])

  const handleExpand = () => {
    if (!expanded) loadPermissions()
    setExpanded(v => !v)
  }

  const handleAdd = async () => {
    setSaving(true)
    setError('')
    try {
      await registryService.addPermission(agent.id, form)
      await loadPermissions()
      setAddOpen(false)
      setForm({ tool_name: 'read_file', action: 'ALLOW' })
    } catch (err) {
      setError(err.message || 'Failed to add permission.')
    } finally {
      setSaving(false)
    }
  }

  const handleRevoke = async (permId) => {
    setRevoking(permId)
    setError('')
    try {
      await registryService.revokePermission(agent.id, permId)
      await loadPermissions()
    } catch (err) {
      setError(err.message || 'Failed to revoke permission.')
    } finally {
      setRevoking(null)
    }
  }

  const agentRole = (agent.metadata?.role || agent.role || 'VIEWER').toUpperCase()
  const agentStatus = (agent.status || 'unknown').toLowerCase()

  return (
    <div className="border border-[var(--border-subtle)] rounded-xl overflow-hidden bg-[var(--bg-surface)]">
      {/* Agent header row */}
      <button
        onClick={handleExpand}
        aria-expanded={expanded}
        className="w-full flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
      >
        <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-[var(--border-subtle)] flex items-center justify-center shrink-0">
          <Users size={14} className="text-neutral-500" aria-hidden="true" />
        </div>
        <div className="flex-1 text-left min-w-0">
          <p className="text-xs font-bold text-white truncate">{agent.name}</p>
          <p className="text-[11px] text-neutral-600 font-mono">{agent.id?.slice(0, 20)}…</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`status-badge ${
            agentStatus === 'active' ? 'text-green-400 bg-green-500/10 border-green-500/20' :
            'text-neutral-500 bg-white/[0.03] border-white/[0.06]'
          }`}>
            {agentStatus}
          </span>
          <span className={`status-badge ${ROLE_BADGE[agentRole] ?? ROLE_BADGE.VIEWER}`}>
            {agentRole}
          </span>
          {expanded
            ? <ChevronUp size={14} className="text-neutral-500" aria-hidden="true" />
            : <ChevronDown size={14} className="text-neutral-500" aria-hidden="true" />
          }
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border-subtle)] p-5 space-y-4 animate-fade-in">
          {error && (
            <div className="flex items-center gap-2 p-2.5 rounded-lg bg-red-500/[0.06] border border-red-500/15" role="alert">
              <AlertTriangle size={12} className="text-red-400 shrink-0" aria-hidden="true" />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          {/* Permissions list */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">Permissions</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={loadPermissions}
                  aria-label="Refresh permissions"
                  className="p-1 text-neutral-600 hover:text-white transition-colors"
                >
                  <RefreshCw size={11} aria-hidden="true" />
                </button>
                <button
                  onClick={() => setAddOpen(v => !v)}
                  className="flex items-center gap-1 text-[11px] text-neutral-400 hover:text-white px-2 py-1 rounded-lg border border-[var(--border-subtle)] hover:border-[var(--border-strong)] transition-colors"
                >
                  <Plus size={11} aria-hidden="true" /> Add
                </button>
              </div>
            </div>

            {permLoading ? (
              <SkeletonLoader variant="row" count={2} />
            ) : permissions.length === 0 ? (
              <div className="py-6 text-center text-xs text-neutral-600 border border-dashed border-[var(--border-subtle)] rounded-xl">
                No permissions configured
              </div>
            ) : (
              <div className="space-y-2">
                {permissions.map((p) => (
                  <div
                    key={p.id}
                    className="flex items-center gap-3 p-3 rounded-lg bg-white/[0.02] border border-[var(--border-subtle)] hover:border-[var(--border-default)] transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono text-white">{p.tool_name || '*'}</span>
                        <span className={`status-badge ${ACTION_STYLES[p.action] ?? 'text-neutral-400 bg-white/5 border-white/10'}`}>
                          {(p.action || 'unknown').toUpperCase()}
                        </span>
                      </div>
                      {p.description && (
                        <p className="text-[11px] text-neutral-600 mt-0.5 truncate">{p.description}</p>
                      )}
                    </div>
                    <button
                      onClick={() => handleRevoke(p.id)}
                      disabled={revoking === p.id}
                      aria-label={`Revoke permission ${p.id}`}
                      className="p-1.5 text-neutral-600 hover:text-red-400 disabled:opacity-40 transition-colors shrink-0"
                    >
                      {revoking === p.id
                        ? <RefreshCw size={12} className="animate-spin" aria-hidden="true" />
                        : <Trash2 size={12} aria-hidden="true" />}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Add permission form */}
          {addOpen && (
            <div className="p-4 rounded-xl bg-white/[0.02] border border-[var(--border-default)] space-y-3 animate-fade-in">
              <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">New Permission</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="label-standard">Tool</label>
                  <select
                    value={form.tool_name}
                    onChange={(e) => setForm(f => ({ ...f, tool_name: e.target.value }))}
                    className="input-standard input-compact h-8 text-xs"
                  >
                    {TOOL_OPTIONS.map(t => (
                      <option key={t} value={t} className="bg-[#080808]">{t}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <label className="label-standard">Action</label>
                  <select
                    value={form.action}
                    onChange={(e) => setForm(f => ({ ...f, action: e.target.value }))}
                    className="input-standard input-compact h-8 text-xs"
                  >
                    {ACTION_OPTIONS.map(a => (
                      <option key={a} value={a} className="bg-[#080808]">{a.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" loading={saving} onClick={handleAdd}>
                  <ShieldCheck size={12} aria-hidden="true" /> Apply
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setAddOpen(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function RBAC() {
  const [agents,  setAgents]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')
  const [search,  setSearch]  = useState('')
  const mountedRef = useRef(true)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res  = await registryService.listAgents()
      const list = Array.isArray(res)         ? res
                 : Array.isArray(res?.data)   ? res.data
                 : Array.isArray(res?.data?.data) ? res.data.data
                 : []
      if (mountedRef.current) setAgents(list)
    } catch (err) {
      if (mountedRef.current) setError(err.message || 'Failed to load agents.')
    } finally {
      if (mountedRef.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    load()
    // 30-second polling to keep agent/permission list current
    const interval = setInterval(load, 30_000)
    return () => { mountedRef.current = false; clearInterval(interval) }
  }, [load])

  // Real-time: reload agent list when agents are registered or updated via SSE
  useEffect(() => {
    const unsub = eventBus.on('agent_changed', load)
    return unsub
  }, [load])

  const filtered = search.trim()
    ? agents.filter(a =>
        a.name?.toLowerCase().includes(search.toLowerCase()) ||
        a.id?.toLowerCase().includes(search.toLowerCase())
      )
    : agents

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Lock size={22} className="text-neutral-400" aria-hidden="true" />
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">RBAC Manager</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Manage agent roles and tool permissions</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-neutral-500">{agents.length} agents</span>
          <button
            onClick={load}
            aria-label="Refresh agent list"
            className="p-2 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.05] transition-colors"
          >
            <RefreshCw size={15} aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* Role legend */}
      <div className="flex items-center gap-3 flex-wrap p-4 rounded-xl bg-white/[0.01] border border-[var(--border-subtle)]">
        <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600 mr-2">Roles</span>
        {Object.entries(ROLE_BADGE).map(([role, style]) => (
          <span key={role} className={`status-badge ${style}`}>{role}</span>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search agents by name or ID…"
          className="input-standard h-9 pl-4 text-xs w-full max-w-md"
          aria-label="Search agents"
        />
      </div>

      {error && (
        <div className="error-banner" role="alert">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-red-400 shrink-0" aria-hidden="true" />
            <p className="text-xs text-red-400">{error}</p>
          </div>
          <button onClick={load} className="text-xs text-red-400 underline">Retry</button>
        </div>
      )}

      {loading ? (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => <SkeletonLoader key={i} variant="card" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-16 text-center text-xs text-neutral-600">
          {search ? 'No agents match your search.' : 'No agents registered.'}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(agent => (
            <AgentRow key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </div>
  )
}

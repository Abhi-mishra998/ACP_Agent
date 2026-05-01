import React, { useState, useEffect, useCallback, useContext } from 'react'
import {
  Zap, Plus, Trash2, ToggleLeft, ToggleRight, FlaskConical,
  ChevronRight, RefreshCw, AlertTriangle, CheckCircle2, Clock,
  Shield, Activity, Eye, History, BarChart2, ThumbsDown, UserCheck,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import Modal from '../components/Common/Modal'
import SkeletonLoader from '../components/Common/SkeletonLoader'
import { autoResponseService } from '../services/api'
import { AuthContext } from '../context/AuthContext'
import { eventBus } from '../lib/eventBus'

// ─── Constants ────────────────────────────────────────────────────────────────

const ACTION_TYPES = [
  { value: 'KILL_AGENT',    label: 'Kill Agent',    color: 'text-red-400' },
  { value: 'ISOLATE_AGENT', label: 'Isolate Agent', color: 'text-orange-400' },
  { value: 'BLOCK_TOOL',    label: 'Block Tool',    color: 'text-amber-400' },
  { value: 'THROTTLE',      label: 'Throttle',      color: 'text-blue-400' },
  { value: 'ALERT',         label: 'Alert',         color: 'text-purple-400' },
]

const ACTION_COLOR = Object.fromEntries(ACTION_TYPES.map(a => [a.value, a.color]))

const WINDOW_OPTIONS = ['1m', '5m', '15m', '1h']
const SEV_OPTIONS    = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const TIME_RANGES    = ['1h', '6h', '24h', '7d']

const MODE_CONFIG = {
  auto:    { label: 'Auto',    cls: 'text-green-400  border-green-500/30',  desc: 'Execute immediately' },
  manual:  { label: 'Manual',  cls: 'text-amber-400  border-amber-500/30',  desc: 'Require human approval' },
  suggest: { label: 'Suggest', cls: 'text-blue-400   border-blue-500/30',   desc: 'Log only, no action' },
}

function makeBlankRule() {
  return {
    name: '',
    priority: 50,
    is_active: true,
    stop_on_match: true,
    mode: 'auto',
    cooldown_seconds: 300,
    max_triggers_per_hour: 10,
    conditions: {
      window: '5m',
      min_violations: 2,
      severity_in: ['CRITICAL', 'HIGH'],
      risk_score_gte: 0.75,
      tool_in: [],
      agent_id: '*',
      repeat_offender: false,
    },
    actions: [{ type: 'ALERT', channel: 'slack' }],
  }
}

function normalizeRule(initial) {
  if (!initial) return makeBlankRule()
  const blank = makeBlankRule()
  return {
    ...blank,
    ...initial,
    conditions: {
      ...blank.conditions,
      ...initial.conditions,
      severity_in: Array.isArray(initial.conditions?.severity_in) ? initial.conditions.severity_in : blank.conditions.severity_in,
      tool_in:     Array.isArray(initial.conditions?.tool_in)     ? initial.conditions.tool_in     : blank.conditions.tool_in,
    },
    actions: Array.isArray(initial.actions) && initial.actions.length > 0 ? initial.actions : blank.actions,
  }
}

// ─── Priority badge ───────────────────────────────────────────────────────────

function PriBadge({ n }) {
  const cls = n >= 80 ? 'text-red-400 border-red-500/30' : n >= 40 ? 'text-amber-400 border-amber-500/30' : 'text-neutral-500 border-white/10'
  return <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${cls}`}>P{n}</span>
}

// ─── Rule Form Modal ──────────────────────────────────────────────────────────

function RuleFormModal({ initial, onSave, onClose }) {
  const [form, setForm]   = useState(() => normalizeRule(initial))
  const [saving, setSaving] = useState(false)
  const [err, setErr]     = useState('')

  const setField  = (path, val) => setForm(prev => deepSet({ ...prev }, path, val))
  const setCond   = (k, v)      => setForm(prev => ({ ...prev, conditions: { ...prev.conditions, [k]: v } }))

  const addAction = () => setForm(prev => ({ ...prev, actions: [...prev.actions, { type: 'ALERT' }] }))
  const setAction = (i, k, v) => setForm(prev => {
    const acts = [...prev.actions]
    acts[i] = { ...acts[i], [k]: v }
    return { ...prev, actions: acts }
  })
  const removeAction = (i) => setForm(prev => ({ ...prev, actions: prev.actions.filter((_, idx) => idx !== i) }))

  const handleSave = async () => {
    if (!form.name.trim()) { setErr('Rule name is required.'); return }
    if (!form.actions.length) { setErr('At least one action required.'); return }
    setSaving(true)
    setErr('')
    try {
      await onSave(form)
      onClose()
    } catch (e) {
      setErr(e.message || 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  const toggleSev = (s) => {
    const sevIn = form.conditions?.severity_in || []
    setCond('severity_in', sevIn.includes(s) ? sevIn.filter(x => x !== s) : [...sevIn, s])
  }

  return (
    <Modal
      isOpen
      onClose={onClose}
      title={initial ? 'Edit Rule' : 'New ARE Rule'}
      size="full"
      footer={
        <>
          {err && (
            <div className="flex items-center gap-2 mr-auto">
              <AlertTriangle size={12} className="text-red-400 shrink-0" />
              <p className="text-xs text-red-400">{err}</p>
            </div>
          )}
          <Button variant="secondary" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" loading={saving} onClick={handleSave}>Save Rule</Button>
        </>
      }
    >
      <div className="space-y-5">

        {/* Basic info */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="md:col-span-2">
            <label className="text-[11px] font-bold text-neutral-500 uppercase tracking-widest block mb-1.5">Rule Name</label>
            <input
              className="input-standard h-10 text-sm w-full"
              value={form.name}
              onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
              placeholder="e.g. Auto-kill critical threats"
            />
          </div>
          <div>
            <label className="text-[11px] font-bold text-neutral-500 uppercase tracking-widest block mb-1.5">Priority (0-1000)</label>
            <input
              type="number" min="0" max="1000"
              className="input-standard h-10 text-sm w-full font-mono"
              value={form.priority}
              onChange={e => setForm(p => ({ ...p, priority: Number(e.target.value) }))}
            />
          </div>
        </div>

        {/* Conditions */}
        <div className="border border-white/[0.06] rounded-xl p-4 space-y-3">
          <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500 mb-2">IF (conditions)</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Detection Window</label>
              <div className="flex gap-1.5">
                {WINDOW_OPTIONS.map(w => (
                  <button key={w} onClick={() => setCond('window', w)}
                    className={`px-3 py-1.5 rounded text-[12px] font-mono border transition-colors ${form.conditions.window === w ? 'text-purple-300 bg-purple-500/10 border-purple-500/30' : 'text-neutral-500 border-white/[0.06] hover:text-neutral-300'}`}>
                    {w}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Min violations in window</label>
              <input type="number" min="1" max="100"
                className="input-standard h-9 text-sm w-full"
                value={form.conditions.min_violations}
                onChange={e => setCond('min_violations', Number(e.target.value))}
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Severity (select any)</label>
            <div className="flex gap-2">
              {SEV_OPTIONS.map(s => {
                const active = (form.conditions?.severity_in || []).includes(s)
                const cls = { CRITICAL: 'red', HIGH: 'orange', MEDIUM: 'amber', LOW: 'green' }[s]
                return (
                  <button key={s} onClick={() => toggleSev(s)}
                    className={`px-3 py-1.5 rounded text-[11px] font-bold border transition-colors ${
                      active ? `text-${cls}-300 bg-${cls}-500/10 border-${cls}-500/30` : 'text-neutral-500 border-white/[0.06] hover:text-neutral-300'
                    }`}>
                    {s}
                  </button>
                )
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Min risk score</label>
              <input type="number" min="0" max="1" step="0.05"
                className="input-standard h-9 text-sm w-full font-mono"
                value={form.conditions.risk_score_gte}
                onChange={e => setCond('risk_score_gte', Number(e.target.value))}
              />
            </div>
            <div>
              <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Agent ID (* = any)</label>
              <input type="text"
                className="input-standard h-9 text-sm w-full font-mono"
                value={form.conditions.agent_id}
                onChange={e => setCond('agent_id', e.target.value)}
              />
            </div>
            <div>
              <label className="text-[11px] text-neutral-500 font-medium block mb-1.5">Tool filter (comma-sep)</label>
              <input type="text"
                className="input-standard h-9 text-sm w-full font-mono"
                placeholder="payments.write,data.export"
                value={(form.conditions.tool_in || []).join(',')}
                onChange={e => setCond('tool_in', e.target.value ? e.target.value.split(',').map(s => s.trim()) : [])}
              />
            </div>
          </div>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox"
              checked={form.conditions.repeat_offender}
              onChange={e => setCond('repeat_offender', e.target.checked)}
              className="accent-purple-500"
            />
            <span className="text-xs text-neutral-400">Repeat offender only (violation count ≥ 2)</span>
          </label>
        </div>

        {/* Actions */}
        <div className="border border-white/[0.06] rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-500">THEN (actions, executed in order)</p>
            <button onClick={addAction} className="flex items-center gap-1 text-[11px] text-neutral-500 hover:text-white transition-colors">
              <Plus size={11} /> Add action
            </button>
          </div>
          {form.actions.map((act, i) => (
            <div key={i} className="flex items-center gap-3">
              <select value={act.type}
                onChange={e => setAction(i, 'type', e.target.value)}
                className="input-standard h-10 text-sm w-48">
                {ACTION_TYPES.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
              </select>
              {act.type === 'BLOCK_TOOL' && (
                <input type="text" placeholder="tool name"
                  value={act.tool || ''} onChange={e => setAction(i, 'tool', e.target.value)}
                  className="input-standard h-10 text-sm w-48 font-mono" />
              )}
              {act.type === 'THROTTLE' && (
                <input type="text" placeholder="5/m"
                  value={act.rate || ''} onChange={e => setAction(i, 'rate', e.target.value)}
                  className="input-standard h-10 text-sm w-32 font-mono" />
              )}
              <button onClick={() => removeAction(i)}
                className="p-1.5 rounded-lg bg-red-500/5 text-neutral-600 hover:text-red-400 hover:bg-red-500/10 transition-colors ml-auto">
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>

        {/* Mode + stop_on_match */}
        <div className="flex items-center gap-4">
          <div>
            <label className="text-[10px] text-neutral-500 uppercase tracking-widest block mb-1.5">Execution Mode</label>
            <div className="flex gap-1.5">
              {Object.entries(MODE_CONFIG).map(([m, cfg]) => (
                <button key={m} onClick={() => setForm(p => ({ ...p, mode: m }))}
                  className={`px-2.5 py-1 rounded text-[11px] border transition-colors ${form.mode === m ? cfg.cls : 'text-neutral-600 border-white/[0.06] hover:text-neutral-400'}`}
                  title={cfg.desc}>
                  {cfg.label}
                </button>
              ))}
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer select-none mt-4">
            <input type="checkbox" checked={form.stop_on_match}
              onChange={e => setForm(p => ({ ...p, stop_on_match: e.target.checked }))}
              className="accent-purple-500" />
            <span className="text-xs text-neutral-400">Stop on first match</span>
          </label>
        </div>

        {/* Limits */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-[11px] text-neutral-500 uppercase tracking-widest block mb-1.5">Cooldown (seconds)</label>
            <input type="number" min="0"
              className="input-standard h-10 text-sm w-full font-mono"
              value={form.cooldown_seconds}
              onChange={e => setForm(p => ({ ...p, cooldown_seconds: Number(e.target.value) }))}
            />
          </div>
          <div>
            <label className="text-[11px] text-neutral-500 uppercase tracking-widest block mb-1.5">Max triggers / hour</label>
            <input type="number" min="1"
              className="input-standard h-10 text-sm w-full font-mono"
              value={form.max_triggers_per_hour}
              onChange={e => setForm(p => ({ ...p, max_triggers_per_hour: Number(e.target.value) }))}
            />
          </div>
        </div>

      </div>
    </Modal>
  )
}

function deepSet(obj, path, val) { obj[path] = val; return obj }

// ─── Simulate Modal ───────────────────────────────────────────────────────────

function SimulateModal({ rule, onClose }) {
  const { addToast } = useContext(AuthContext)
  const [timeRange, setTimeRange] = useState('24h')
  const [result,    setResult]    = useState(null)
  const [running,   setRunning]   = useState(false)

  const run = async () => {
    setRunning(true)
    setResult(null)
    try {
      const res = await autoResponseService.simulate({ rule_id: rule.id, time_range: timeRange })
      setResult(res?.data || res)
    } catch (e) {
      addToast('Simulation failed: ' + (e.message || ''), 'error')
    } finally {
      setRunning(false)
    }
  }

  return (
    <Modal isOpen onClose={onClose} title={`Simulate — ${rule.name}`} size="lg">
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-neutral-500">Replay window:</span>
          <div className="flex gap-1">
            {TIME_RANGES.map(r => (
              <button key={r} onClick={() => setTimeRange(r)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono border transition-colors ${timeRange === r ? 'text-purple-300 bg-purple-500/10 border-purple-500/30' : 'text-neutral-600 border-white/[0.06] hover:text-neutral-400'}`}>
                {r}
              </button>
            ))}
          </div>
          <Button size="sm" onClick={run} loading={running} className="ml-auto">
            <FlaskConical size={12} /> Run
          </Button>
        </div>

        {result && (
          <div className="space-y-4">
            {/* Stats */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Total incidents', val: result.total_events, cls: 'text-white' },
                { label: 'Would trigger',   val: result.would_trigger, cls: 'text-red-400' },
                { label: '% mitigated',     val: `${result.mitigated_pct}%`, cls: 'text-amber-400' },
              ].map(({ label, val, cls }) => (
                <div key={label} className="text-center p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                  <p className={`text-xl font-bold ${cls}`}>{val}</p>
                  <p className="text-[10px] text-neutral-600 mt-0.5">{label}</p>
                </div>
              ))}
            </div>

            {/* Actions preview */}
            <div>
              <p className="text-[10px] uppercase tracking-widest text-neutral-600 mb-2">Actions that would execute</p>
              <div className="flex gap-2 flex-wrap">
                {result.actions_preview.map((a, i) => (
                  <span key={i} className={`text-xs px-2 py-0.5 rounded border border-white/[0.08] ${ACTION_COLOR[a.type] || 'text-neutral-400'}`}>
                    {a.type}{a.tool ? `:${a.tool}` : ''}{a.rate ? `:${a.rate}` : ''}
                  </span>
                ))}
              </div>
            </div>

            {/* Affected agents */}
            {result.affected_agents?.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-widest text-neutral-600 mb-2">Affected agents ({result.affected_agents.length})</p>
                <div className="flex gap-2 flex-wrap">
                  {result.affected_agents.map(a => (
                    <code key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.03] border border-white/[0.06] text-neutral-400 font-mono">
                      {a.slice(0, 8)}
                    </code>
                  ))}
                </div>
              </div>
            )}

            {/* Sample matches */}
            {result.sample_matches?.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-widest text-neutral-600 mb-2">Sample matched incidents</p>
                <div className="space-y-1.5 max-h-40 overflow-y-auto">
                  {result.sample_matches.map(m => (
                    <div key={m.incident_id} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-white/[0.02] border border-white/[0.04]">
                      <span className={`font-medium ${m.severity === 'CRITICAL' ? 'text-red-400' : m.severity === 'HIGH' ? 'text-orange-400' : 'text-amber-400'}`}>{m.severity}</span>
                      <span className="text-neutral-600 font-mono">{m.agent_id.slice(0,8)}</span>
                      <span className="text-neutral-500">{m.tool || 'N/A'}</span>
                      <span className="ml-auto text-neutral-700 font-mono">{(m.risk_score * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.total_events === 0 && (
              <p className="text-xs text-neutral-500 text-center py-2">No incidents in the selected window.</p>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}

// ─── Rule Card ────────────────────────────────────────────────────────────────

function RuleCard({ rule, onEdit, onDelete, onSimulate, onToggle, onFeedback, onHistory }) {
  const lastTriggered = rule.last_triggered_at
    ? new Date(rule.last_triggered_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'Never'
  const modeCfg = MODE_CONFIG[rule.mode] || MODE_CONFIG.auto

  return (
    <div className={`border rounded-xl overflow-hidden transition-opacity ${rule.is_active ? 'border-[var(--border-default)]' : 'border-white/[0.04] opacity-60'} bg-[var(--bg-surface)]`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.02] border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2">
          <PriBadge n={rule.priority} />
          <span className="text-xs font-semibold text-white">{rule.name}</span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded border ${modeCfg.cls}`}>{modeCfg.label}</span>
          {rule.false_positive_count > 0 && (
            <span className="text-[10px] text-amber-600 font-mono">{rule.false_positive_count} FP</span>
          )}
          {!rule.is_active && <span className="text-[10px] text-neutral-600">(disabled)</span>}
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => onHistory(rule)} className="p-1 rounded text-neutral-600 hover:text-blue-400 transition-colors" title={`v${rule.version} — history`}>
            <History size={12} />
          </button>
          <button onClick={() => onSimulate(rule)} className="p-1 rounded text-neutral-600 hover:text-purple-400 transition-colors" title="Simulate">
            <FlaskConical size={12} />
          </button>
          <button onClick={() => onEdit(rule)} className="p-1 rounded text-neutral-600 hover:text-white transition-colors" title="Edit">
            <Eye size={12} />
          </button>
          <button onClick={() => onFeedback(rule)} className="p-1 rounded text-neutral-600 hover:text-amber-400 transition-colors" title="Report false positive">
            <ThumbsDown size={12} />
          </button>
          <button onClick={() => onToggle(rule)} className="p-1 rounded transition-colors" title={rule.is_active ? 'Disable' : 'Enable'}>
            {rule.is_active
              ? <ToggleRight size={16} className="text-green-400" />
              : <ToggleLeft  size={16} className="text-neutral-600" />}
          </button>
          <button onClick={() => onDelete(rule.id)} className="p-1 rounded text-neutral-600 hover:text-red-400 transition-colors" title="Delete">
            <Trash2 size={12} />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-3">
        {/* Conditions summary */}
        <div className="flex flex-wrap gap-1.5 text-[10px]">
          {rule.conditions.window && (
            <span className="px-2 py-0.5 rounded border border-white/[0.06] text-neutral-500 font-mono">⏱ {rule.conditions.window}</span>
          )}
          {rule.conditions.severity_in?.map(s => (
            <span key={s} className={`px-2 py-0.5 rounded border border-white/[0.08] font-medium ${s === 'CRITICAL' ? 'text-red-400' : s === 'HIGH' ? 'text-orange-400' : 'text-amber-400'}`}>{s}</span>
          ))}
          {rule.conditions.risk_score_gte > 0 && (
            <span className="px-2 py-0.5 rounded border border-white/[0.06] text-neutral-500 font-mono">risk≥{(rule.conditions.risk_score_gte * 100).toFixed(0)}%</span>
          )}
          {rule.conditions.min_violations > 1 && (
            <span className="px-2 py-0.5 rounded border border-white/[0.06] text-neutral-500 font-mono">{rule.conditions.min_violations}+ violations</span>
          )}
          {rule.conditions.repeat_offender && (
            <span className="px-2 py-0.5 rounded border border-amber-500/20 text-amber-500">repeat offender</span>
          )}
        </div>

        {/* Actions */}
        <div className="flex flex-wrap gap-1.5">
          {rule.actions.map((a, i) => (
            <span key={i} className={`text-[10px] px-2 py-0.5 rounded border border-white/[0.08] font-medium ${ACTION_COLOR[a.type] || 'text-neutral-400'}`}>
              {a.type}{a.tool ? `:${a.tool}` : ''}{a.rate ? ` @${a.rate}` : ''}
            </span>
          ))}
        </div>

        {/* Meta */}
        <div className="flex items-center gap-4 text-[10px] text-neutral-700 pt-1 border-t border-white/[0.04]">
          <span className="flex items-center gap-1"><Zap size={9} /> {rule.trigger_count} triggers</span>
          <span className="flex items-center gap-1"><Clock size={9} /> {lastTriggered}</span>
          <span className="flex items-center gap-1 ml-auto">cooldown {rule.cooldown_seconds}s</span>
          <span>{rule.max_triggers_per_hour}/h max</span>
        </div>
      </div>
    </div>
  )
}

// ─── History Modal ────────────────────────────────────────────────────────────

function HistoryModal({ rule, onClose, onRollback }) {
  const { addToast } = useContext(AuthContext)
  const [history,    setHistory]    = useState([])
  const [loading,    setLoading]    = useState(true)
  const [rolling,    setRolling]    = useState(null)

  useEffect(() => {
    autoResponseService.getHistory(rule.id)
      .then(r => setHistory(r?.data || []))
      .catch(() => addToast('Failed to load history', 'error'))
      .finally(() => setLoading(false))
  }, [rule.id, addToast])

  const handleRollback = async (version) => {
    setRolling(version)
    try {
      await autoResponseService.rollback(rule.id, version)
      addToast(`Rolled back to v${version}`, 'success')
      onRollback()
      onClose()
    } catch (e) {
      addToast('Rollback failed: ' + (e.message || ''), 'error')
    } finally {
      setRolling(null)
    }
  }

  return (
    <Modal isOpen onClose={onClose} title={`Version History — ${rule.name} (current v${rule.version})`} size="lg">
      {loading ? <SkeletonLoader count={4} /> : history.length === 0 ? (
        <p className="text-xs text-neutral-500 text-center py-6">No version history yet.</p>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {history.map(h => (
            <div key={h.version} className="flex items-start gap-3 p-3 rounded-lg bg-white/[0.02] border border-white/[0.05]">
              <div className="shrink-0">
                <span className="text-[10px] font-mono text-neutral-500 border border-white/[0.08] px-1.5 py-0.5 rounded">v{h.version}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-[10px] text-neutral-600 font-mono">{new Date(h.changed_at).toLocaleString()} by <span className="text-neutral-400">{h.changed_by}</span></p>
                <div className="flex gap-2 mt-1 flex-wrap text-[10px]">
                  {h.snapshot && Object.entries(h.snapshot).slice(0, 4).map(([k, v]) => (
                    <span key={k} className="text-neutral-700">{k}: <span className="text-neutral-500">{typeof v === 'object' ? '…' : String(v)}</span></span>
                  ))}
                </div>
              </div>
              <Button size="sm" variant="secondary" onClick={() => handleRollback(h.version)} loading={rolling === h.version}>
                Restore
              </Button>
            </div>
          ))}
        </div>
      )}
    </Modal>
  )
}

// ─── Feedback Modal ───────────────────────────────────────────────────────────

function FeedbackModal({ rule, onClose, onDone }) {
  const { addToast } = useContext(AuthContext)
  const [reason,     setReason]     = useState('')
  const [suppress,   setSuppress]   = useState(60)
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async () => {
    setSubmitting(true)
    try {
      await autoResponseService.feedback(rule.id, { trigger_ref: '', reason, suppress_min: suppress })
      addToast(`Feedback recorded — rule suppressed ${suppress}m`, 'success')
      onDone()
      onClose()
    } catch (e) {
      addToast('Feedback failed: ' + (e.message || ''), 'error')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal isOpen onClose={onClose} title={`False Positive — ${rule.name}`} size="sm">
      <div className="space-y-4">
        <p className="text-xs text-neutral-400">This trigger was a false positive. Suppress the rule temporarily and increment the FP counter.</p>
        <div>
          <label className="text-[10px] text-neutral-500 uppercase tracking-widest block mb-1">Reason</label>
          <textarea rows={2} value={reason} onChange={e => setReason(e.target.value)}
            className="input-standard w-full text-xs resize-none" placeholder="Why was this a false positive?" />
        </div>
        <div>
          <label className="text-[10px] text-neutral-500 uppercase tracking-widest block mb-1">Suppress for (minutes, 0 = no suppression)</label>
          <input type="number" min="0" max="1440" value={suppress} onChange={e => setSuppress(Number(e.target.value))}
            className="input-standard input-compact h-8 text-xs w-full" />
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" loading={submitting} onClick={handleSubmit}>Submit Feedback</Button>
        </div>
      </div>
    </Modal>
  )
}

// ─── Metrics Panel ────────────────────────────────────────────────────────────

function MetricsPanel() {
  const { addToast } = useContext(AuthContext)
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)

  const fetch = useCallback(async () => {
    setLoading(true)
    try {
      const res = await autoResponseService.getMetrics()
      setData(res?.data || null)
    } catch {
      addToast('Failed to load metrics', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => { fetch() }, [fetch])

  if (loading) return <Card><div className="p-4"><SkeletonLoader count={4} /></div></Card>
  if (!data)   return null

  const perRule = Object.entries(data.metrics || {})
    .filter(([k]) => k.startsWith('triggers_total:'))
    .map(([k, v]) => ({ rule: k.replace('triggers_total:', ''), count: v }))
    .sort((a, b) => b.count - a.count)

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Total Triggers',    val: data.triggers_total,    cls: 'text-red-400' },
          { label: 'Suggestions',       val: data.suggestions_total, cls: 'text-blue-400' },
          { label: 'Suppressed',        val: data.suppressed_total,  cls: 'text-amber-400' },
          { label: 'Pending Approval',  val: data.manual_pending,    cls: 'text-purple-400' },
        ].map(({ label, val, cls }) => (
          <Card key={label} className="p-4 text-center">
            <p className={`text-2xl font-bold ${cls}`}>{val ?? 0}</p>
            <p className="text-[10px] text-neutral-600 mt-1">{label}</p>
          </Card>
        ))}
      </div>

      {perRule.length > 0 && (
        <Card title="Triggers per Rule" icon={BarChart2}>
          <div className="space-y-2">
            {perRule.map(({ rule, count }) => (
              <div key={rule} className="flex items-center gap-3">
                <code className="text-[10px] text-neutral-500 font-mono w-20 shrink-0 truncate">{rule}</code>
                <div className="flex-1 h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
                  <div className="h-full bg-red-500/60 rounded-full" style={{ width: `${Math.min(100, (count / (perRule[0]?.count || 1)) * 100)}%` }} />
                </div>
                <span className="text-[10px] text-neutral-500 w-6 text-right">{count}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="flex justify-end">
        <button onClick={fetch} className="text-[10px] text-neutral-600 hover:text-neutral-400 transition-colors flex items-center gap-1">
          <RefreshCw size={10} /> Refresh
        </button>
      </div>
    </div>
  )
}

// ─── Pending Approvals Panel ──────────────────────────────────────────────────

function PendingPanel() {
  const { addToast } = useContext(AuthContext)
  const [items,   setItems]   = useState([])
  const [loading, setLoading] = useState(true)

  const fetch = useCallback(async () => {
    setLoading(true)
    try {
      const res = await autoResponseService.listPending()
      setItems(res?.data || [])
    } catch {
      addToast('Failed to load pending', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => { fetch() }, [fetch])

  const handle = async (item, approved) => {
    const key = item.approval_key || `${item.rule_id}:${item.incident?.request_id || ''}`
    try {
      await autoResponseService.approvePending(key, { approved, note: '' })
      addToast(approved ? 'Approved — re-queued' : 'Rejected', 'success')
      fetch()
    } catch (e) {
      addToast('Failed: ' + (e.message || ''), 'error')
    }
  }

  if (loading) return <Card><div className="p-4"><SkeletonLoader count={3} /></div></Card>

  return (
    <div className="space-y-3">
      {items.length === 0 ? (
        <Card>
          <div className="flex flex-col items-center justify-center py-12">
            <CheckCircle2 size={28} className="text-green-600 mb-2" />
            <p className="text-sm text-neutral-500">No pending approvals</p>
          </div>
        </Card>
      ) : items.map((item, i) => (
        <Card key={i} className="p-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-xs font-medium text-white">{item.incident?.title || 'Unnamed incident'}</p>
              <p className="text-[10px] text-neutral-500 mt-0.5 font-mono">
                agent {String(item.incident?.agent_id || '').slice(0, 8)} · risk {(parseFloat(item.incident?.risk_score || 0) * 100).toFixed(0)}%
              </p>
              <div className="flex gap-1.5 mt-2 flex-wrap">
                {(item.actions || []).map((a, j) => (
                  <span key={j} className={`text-[10px] px-1.5 py-0.5 rounded border border-white/[0.08] ${ACTION_COLOR[a.type] || 'text-neutral-400'}`}>
                    {a.type}
                  </span>
                ))}
              </div>
              <p className="text-[10px] text-neutral-700 mt-1">{item.created_at ? new Date(item.created_at).toLocaleString() : ''}</p>
            </div>
            <div className="flex gap-2 shrink-0">
              <Button size="sm" onClick={() => handle(item, true)}>
                <UserCheck size={12} /> Approve
              </Button>
              <Button size="sm" variant="secondary" onClick={() => handle(item, false)}>Reject</Button>
            </div>
          </div>
        </Card>
      ))}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AutoResponse() {
  const { addToast } = useContext(AuthContext)

  const [activeTab,   setActiveTab]   = useState('rules')
  const [rules,       setRules]       = useState([])
  const [areEnabled,  setAreEnabled]  = useState(true)
  const [loading,     setLoading]     = useState(true)
  const [editRule,    setEditRule]    = useState(null)
  const [simRule,     setSimRule]     = useState(null)
  const [histRule,    setHistRule]    = useState(null)
  const [feedRule,    setFeedRule]    = useState(null)
  const [liveEvents,  setLiveEvents]  = useState([])

  const fetchAll = useCallback(async () => {
    setLoading(true)
    try {
      const [rulesRes, statusRes] = await Promise.all([
        autoResponseService.listRules(),
        autoResponseService.getStatus(),
      ])
      setRules((rulesRes?.data || []).sort((a, b) => b.priority - a.priority))
      setAreEnabled(statusRes?.data?.enabled ?? true)
    } catch {
      addToast('Failed to load ARE rules', 'error')
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => {
    fetchAll()
    // 30-second polling for rule updates and status
    const interval = setInterval(fetchAll, 30_000)
    return () => clearInterval(interval)
  }, [fetchAll])

  // Live ARE event feed
  useEffect(() => {
    const unsub = eventBus.on('auto_response_executed', (payload) => {
      setLiveEvents(prev => [payload, ...prev].slice(0, 20))
      addToast(`ARE: ${payload.actions?.join(', ')} on agent ${String(payload.agent_id || '').slice(0, 8)}`, 'info')
    })
    return unsub
  }, [addToast])

  const handleToggleAre = async () => {
    try {
      const res = await autoResponseService.toggle(!areEnabled)
      setAreEnabled(res?.data?.enabled ?? !areEnabled)
      addToast(`ARE ${!areEnabled ? 'enabled' : 'disabled'}`, 'success')
    } catch {
      addToast('Toggle failed', 'error')
    }
  }

  const handleSaveRule = async (form) => {
    if (editRule && editRule !== true) {
      await autoResponseService.updateRule(editRule.id, form)
      addToast('Rule updated', 'success')
    } else {
      await autoResponseService.createRule(form)
      addToast('Rule created', 'success')
    }
    fetchAll()
  }

  const handleToggleRule = async (rule) => {
    try {
      await autoResponseService.updateRule(rule.id, { is_active: !rule.is_active })
      addToast(`Rule ${rule.is_active ? 'disabled' : 'enabled'}`, 'success')
      fetchAll()
    } catch {
      addToast('Update failed', 'error')
    }
  }

  const handleDelete = async (id) => {
    try {
      await autoResponseService.deleteRule(id)
      addToast('Rule deleted', 'success')
      fetchAll()
    } catch {
      addToast('Delete failed', 'error')
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          <Zap size={22} className="text-purple-400" />
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Autonomous Response Engine</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Governed, explainable, auditable auto-mitigation</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {/* Global toggle */}
          <button
            onClick={handleToggleAre}
            className={`flex items-center gap-2 px-3 py-2 text-xs rounded-lg border transition-colors ${
              areEnabled
                ? 'text-green-400 bg-green-500/[0.06] border-green-500/20 hover:border-green-500/40'
                : 'text-neutral-500 bg-white/[0.02] border-white/[0.06] hover:border-white/10'
            }`}
          >
            {areEnabled ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
            ARE {areEnabled ? 'Enabled' : 'Disabled'}
          </button>
          <Button variant="secondary" size="sm" onClick={fetchAll} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </Button>
          <Button size="sm" onClick={() => setEditRule(true)}>
            <Plus size={13} /> New Rule
          </Button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 p-1 bg-white/[0.02] border border-white/[0.06] rounded-lg w-fit">
        {[
          { id: 'rules',    label: 'Rules',    icon: Zap },
          { id: 'metrics',  label: 'Metrics',  icon: BarChart2 },
          { id: 'pending',  label: 'Pending',  icon: UserCheck },
        ].map(({ id, label, icon: Icon }) => (
          <button key={id} onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${activeTab === id ? 'bg-white/[0.08] text-white' : 'text-neutral-500 hover:text-neutral-300'}`}>
            <Icon size={12} />{label}
          </button>
        ))}
      </div>

      {activeTab === 'metrics' && <MetricsPanel />}
      {activeTab === 'pending' && <PendingPanel />}

      {/* Info banner */}
      {activeTab === 'rules' && !areEnabled && (
        <div className="flex items-center gap-3 p-4 rounded-xl bg-amber-500/[0.04] border border-amber-500/15">
          <AlertTriangle size={14} className="text-amber-400 shrink-0" />
          <p className="text-xs text-amber-300/70">
            ARE is globally disabled for this tenant. Rules will not fire until re-enabled.
          </p>
        </div>
      )}

      {activeTab === 'rules' && (
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Rules list */}
        <div className="xl:col-span-2 space-y-3">
          {loading ? (
            <Card><div className="p-4"><SkeletonLoader count={4} /></div></Card>
          ) : rules.length === 0 ? (
            <Card>
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <Shield size={32} className="text-neutral-700 mb-3" />
                <p className="text-sm text-neutral-400">No ARE rules yet</p>
                <p className="text-xs text-neutral-600 mt-1">Create a rule to start auto-mitigating threats</p>
                <Button size="sm" className="mt-4" onClick={() => setEditRule(true)}>
                  <Plus size={13} /> Create first rule
                </Button>
              </div>
            </Card>
          ) : (
            rules.map(rule => (
              <RuleCard
                key={rule.id}
                rule={rule}
                onEdit={setEditRule}
                onDelete={handleDelete}
                onSimulate={setSimRule}
                onToggle={handleToggleRule}
                onFeedback={setFeedRule}
                onHistory={setHistRule}
              />
            ))
          )}
        </div>

        {/* Right panel */}
        <div className="space-y-4">
          {/* Stats */}
          <Card title="Summary" icon={Activity}>
            <div className="space-y-2">
              {[
                { label: 'Total rules',   val: rules.length },
                { label: 'Active rules',  val: rules.filter(r => r.is_active).length, cls: 'text-green-400' },
                { label: 'Total triggers',val: rules.reduce((s, r) => s + (r.trigger_count || 0), 0), cls: 'text-amber-400' },
              ].map(({ label, val, cls = 'text-white' }) => (
                <div key={label} className="flex items-center justify-between py-1.5 border-b border-white/[0.04] last:border-0">
                  <span className="text-xs text-neutral-500">{label}</span>
                  <span className={`text-xs font-bold ${cls}`}>{val}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Evaluation order */}
          <Card title="Evaluation Order" icon={ChevronRight}>
            <div className="space-y-1">
              {rules.slice(0, 8).map((r, i) => (
                <div key={r.id} className="flex items-center gap-2 py-1 text-[10px]">
                  <span className="text-neutral-700 w-4 text-right">{i + 1}</span>
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${r.is_active ? 'bg-green-500' : 'bg-neutral-700'}`} />
                  <span className="text-neutral-400 truncate flex-1">{r.name}</span>
                  <PriBadge n={r.priority} />
                </div>
              ))}
              {rules.length > 8 && (
                <p className="text-[10px] text-neutral-700 text-center pt-1">+{rules.length - 8} more</p>
              )}
            </div>
          </Card>

          {/* Live event feed */}
          {liveEvents.length > 0 && (
            <Card title="Live Triggers" icon={Zap}>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {liveEvents.map((ev, i) => (
                  <div key={i} className="text-[10px] p-2 rounded bg-white/[0.02] border border-white/[0.04]">
                    <div className="flex items-center justify-between mb-0.5">
                      <span className={`font-medium ${ev.severity === 'CRITICAL' ? 'text-red-400' : 'text-orange-400'}`}>
                        {ev.severity || 'HIGH'}
                      </span>
                      <span className="text-neutral-700 font-mono">
                        {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ''}
                      </span>
                    </div>
                    <p className="text-neutral-500 font-mono">agent {String(ev.agent_id || '').slice(0, 8)}</p>
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {(ev.actions || []).map((a, j) => (
                        <span key={j} className={`px-1.5 py-0 rounded border border-white/[0.06] ${ACTION_COLOR[a?.split(':')[0]] || 'text-neutral-500'}`}>
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>
      )}

      {/* Modals */}
      {editRule && (
        <RuleFormModal
          initial={editRule !== true ? editRule : null}
          onSave={handleSaveRule}
          onClose={() => setEditRule(null)}
        />
      )}
      {simRule  && <SimulateModal  rule={simRule}  onClose={() => setSimRule(null)} />}
      {histRule && <HistoryModal   rule={histRule}  onClose={() => setHistRule(null)} onRollback={fetchAll} />}
      {feedRule && <FeedbackModal  rule={feedRule}  onClose={() => setFeedRule(null)} onDone={fetchAll} />}
    </div>
  )
}

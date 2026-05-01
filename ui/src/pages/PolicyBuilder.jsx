import React, { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  GitMerge, Plus, Trash2, ChevronRight, Eye, Save,
  AlertTriangle, CheckCircle2, Info, FlaskConical, X,
} from 'lucide-react'
import Card from '../components/Common/Card'
import Button from '../components/Common/Button'
import Modal from '../components/Common/Modal'
import { registryService, policyService } from '../services/api'
import { useAgents } from '../hooks/useAgents'
import { eventBus } from '../lib/eventBus'

const CONDITION_FIELDS = [
  { value: 'risk_score',     label: 'Risk Score',     type: 'number', placeholder: '0.0 – 1.0' },
  { value: 'tool',           label: 'Tool Name',      type: 'text',   placeholder: 'read_file' },
  { value: 'inference_risk', label: 'Inference Risk', type: 'number', placeholder: '0.0 – 1.0' },
  { value: 'behavior_risk',  label: 'Behavior Risk',  type: 'number', placeholder: '0.0 – 1.0' },
  { value: 'anomaly_score',  label: 'Anomaly Score',  type: 'number', placeholder: '0.0 – 1.0' },
]

const OPERATORS = [
  { value: 'gt',  label: '>' },
  { value: 'gte', label: '≥' },
  { value: 'lt',  label: '<' },
  { value: 'lte', label: '≤' },
  { value: 'eq',  label: '=' },
  { value: 'neq', label: '≠' },
]

const ACTIONS = ['DENY', 'ALLOW', 'MONITOR', 'THROTTLE', 'ESCALATE']

const ACTION_STYLES = {
  DENY:     'text-red-400    bg-red-500/10    border-red-500/20',
  ALLOW:    'text-green-400  bg-green-500/10  border-green-500/20',
  MONITOR:  'text-blue-400   bg-blue-500/10   border-blue-500/20',
  THROTTLE: 'text-amber-400  bg-amber-500/10  border-amber-500/20',
  ESCALATE: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
}

function makeRule() {
  return {
    id:          crypto.randomUUID(),
    conditions:  [{ id: crypto.randomUUID(), field: 'risk_score', operator: 'gt', value: '0.7' }],
    action:      'DENY',
    description: '',
  }
}

function buildPermissionPayload(rule) {
  return {
    tool_name:   rule.conditions.find(c => c.field === 'tool')?.value || '*',
    action:      rule.action,
    constraints: rule.conditions.reduce((acc, c) => {
      if (c.field !== 'tool') acc[c.field] = { op: c.operator, value: parseFloat(c.value) || c.value }
      return acc
    }, {}),
    description: rule.description || `Auto-policy: ${rule.action}`,
  }
}

function RuleBlock({ rule, idx, onChange, onDelete, onMoveUp, onMoveDown, isFirst, isLast }) {
  const updateCondition = (cid, key, val) => {
    onChange({
      ...rule,
      conditions: rule.conditions.map(c => c.id === cid ? { ...c, [key]: val } : c),
    })
  }

  const addCondition = () => {
    onChange({
      ...rule,
      conditions: [...rule.conditions, { id: crypto.randomUUID(), field: 'risk_score', operator: 'gt', value: '0.5' }],
    })
  }

  const removeCondition = (cid) => {
    if (rule.conditions.length <= 1) return
    onChange({ ...rule, conditions: rule.conditions.filter(c => c.id !== cid) })
  }

  return (
    <div className="relative border border-[var(--border-default)] rounded-xl overflow-hidden bg-[var(--bg-surface)]">
      {/* Rule header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-white/[0.02] border-b border-[var(--border-subtle)]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-neutral-500 uppercase tracking-widest">Rule {idx + 1}</span>
          <span className={`status-badge text-[10px] ${ACTION_STYLES[rule.action] ?? ''}`}>{rule.action}</span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={onMoveUp} disabled={isFirst}
            className="p-1 rounded text-neutral-600 hover:text-white disabled:opacity-20 transition-colors"
            aria-label="Move rule up"
          >↑</button>
          <button
            onClick={onMoveDown} disabled={isLast}
            className="p-1 rounded text-neutral-600 hover:text-white disabled:opacity-20 transition-colors"
            aria-label="Move rule down"
          >↓</button>
          <button
            onClick={onDelete}
            className="p-1 rounded text-neutral-600 hover:text-red-400 transition-colors"
            aria-label="Delete rule"
          >
            <Trash2 size={12} aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Conditions */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">IF</span>
          </div>
          {rule.conditions.map((cond, ci) => (
            <div key={cond.id} className="flex items-center gap-2 flex-wrap">
              {ci > 0 && (
                <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600 w-8">AND</span>
              )}
              <select
                value={cond.field}
                onChange={(e) => updateCondition(cond.id, 'field', e.target.value)}
                aria-label="Condition field"
                className="input-standard input-compact h-8 text-xs w-36"
              >
                {CONDITION_FIELDS.map(f => (
                  <option key={f.value} value={f.value} className="bg-[#080808]">{f.label}</option>
                ))}
              </select>
              <select
                value={cond.operator}
                onChange={(e) => updateCondition(cond.id, 'operator', e.target.value)}
                aria-label="Condition operator"
                className="input-standard input-compact h-8 text-xs w-16"
              >
                {OPERATORS.map(o => (
                  <option key={o.value} value={o.value} className="bg-[#080808]">{o.label}</option>
                ))}
              </select>
              <input
                type="text"
                value={cond.value}
                onChange={(e) => updateCondition(cond.id, 'value', e.target.value)}
                placeholder={CONDITION_FIELDS.find(f => f.value === cond.field)?.placeholder || ''}
                aria-label="Condition value"
                className="input-standard input-compact h-8 text-xs w-28 font-mono"
              />
              <button
                onClick={() => removeCondition(cond.id)}
                disabled={rule.conditions.length <= 1}
                className="p-1 text-neutral-600 hover:text-red-400 disabled:opacity-20 transition-colors"
                aria-label="Remove condition"
              >
                <Trash2 size={11} aria-hidden="true" />
              </button>
            </div>
          ))}
          <button
            onClick={addCondition}
            className="flex items-center gap-1.5 text-[11px] text-neutral-500 hover:text-white transition-colors mt-1"
          >
            <Plus size={11} aria-hidden="true" /> Add condition
          </button>
        </div>

        {/* Action */}
        <div className="flex items-center gap-3 pt-2 border-t border-[var(--border-subtle)]">
          <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">THEN</span>
          <div className="flex items-center gap-1.5 flex-wrap">
            {ACTIONS.map(action => (
              <button
                key={action}
                onClick={() => onChange({ ...rule, action })}
                className={`status-badge cursor-pointer transition-all ${
                  rule.action === action
                    ? ACTION_STYLES[action]
                    : 'text-neutral-600 bg-white/[0.02] border-white/[0.05] hover:border-white/10 hover:text-neutral-400'
                }`}
              >
                {action}
              </button>
            ))}
          </div>
        </div>

        {/* Description */}
        <div>
          <input
            type="text"
            value={rule.description}
            onChange={(e) => onChange({ ...rule, description: e.target.value })}
            placeholder="Rule description (optional)…"
            className="input-standard input-compact h-8 text-xs w-full"
          />
        </div>
      </div>
    </div>
  )
}

export default function PolicyBuilder() {
  const navigate = useNavigate()
  const { agents } = useAgents()
  const [rules,        setRules]        = useState([makeRule()])
  const [selectedAgent,setSelectedAgent]= useState('')
  const [saving,       setSaving]       = useState(false)
  const [saved,        setSaved]        = useState(false)
  const [error,        setError]        = useState('')
  const [showPreview,  setShowPreview]  = useState(false)
  const [simulating,   setSimulating]   = useState(false)
  const [simResult,    setSimResult]    = useState(null)
  const [simTimeRange, setSimTimeRange] = useState('24h')

  const addRule = () => setRules(prev => [...prev, makeRule()])

  const updateRule = useCallback((id, updated) => {
    setRules(prev => prev.map(r => r.id === id ? updated : r))
  }, [])

  const deleteRule = (id) => setRules(prev => prev.filter(r => r.id !== id))

  const moveRule = (idx, dir) => {
    setRules(prev => {
      const next = [...prev]
      const target = idx + dir
      if (target < 0 || target >= next.length) return prev
      ;[next[idx], next[target]] = [next[target], next[idx]]
      return next
    })
  }

  const preview = rules.map(buildPermissionPayload)

  const handleSave = async () => {
    if (!selectedAgent) { setError('Select an agent to apply this policy.'); return }
    setSaving(true)
    setError('')
    setSaved(false)
    try {
      for (const rule of rules) {
        const payload = buildPermissionPayload(rule)
        await registryService.addPermission(selectedAgent, payload)
      }
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      setError(err.message || 'Failed to save policy rules.')
    } finally {
      setSaving(false)
    }
  }

  const handleSimulate = async () => {
    if (!selectedAgent) { setError('Select an agent to simulate against.'); return }
    setSimulating(true)
    setSimResult(null)
    setError('')
    try {
      const payload = {
        policy: rules.map(r => ({
          conditions: r.conditions.map(c => ({ field: c.field, operator: c.operator, value: c.value })),
          action: r.action,
          description: r.description || '',
        })),
        agent_id: selectedAgent,
        time_range: simTimeRange,
      }
      const res = await policyService.simulate(payload)
      setSimResult(res?.data || res)
    } catch (err) {
      setError(err.message || 'Simulation failed.')
    } finally {
      setSimulating(false)
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="page-header">
        <div className="flex items-center gap-3">
          <GitMerge size={22} className="text-neutral-400" aria-hidden="true" />
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Visual Policy Builder</h1>
            <p className="text-xs text-neutral-500 mt-0.5">Build governance rules without writing Rego</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowPreview(v => !v)}
            className="flex items-center gap-2 px-3 py-2 text-xs text-neutral-400 bg-white/[0.02] border border-[var(--border-subtle)] rounded-lg hover:border-white/[0.12] hover:text-white transition-colors"
          >
            <Eye size={13} aria-hidden="true" />
            {showPreview ? 'Hide' : 'Preview'} JSON
          </button>
          <button
            onClick={handleSimulate}
            disabled={simulating || !selectedAgent}
            className="flex items-center gap-2 px-3 py-2 text-xs text-purple-400 bg-purple-500/[0.06] border border-purple-500/20 rounded-lg hover:border-purple-500/40 hover:text-purple-300 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <FlaskConical size={13} aria-hidden="true" />
            {simulating ? 'Simulating…' : 'Simulate'}
          </button>
          <Button size="sm" onClick={addRule}>
            <Plus size={13} aria-hidden="true" /> Add Rule
          </Button>
        </div>
      </div>

      {/* Info banner */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/[0.04] border border-blue-500/10">
        <Info size={14} className="text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
        <p className="text-xs text-blue-300/70 leading-relaxed">
          Rules are evaluated top-to-bottom. The first matching rule wins. Conditions within a rule use AND logic.
          Save applies rules as agent permissions to the selected agent.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Rule editor */}
        <div className="xl:col-span-2 space-y-4">
          {rules.map((rule, idx) => (
            <RuleBlock
              key={rule.id}
              rule={rule}
              idx={idx}
              onChange={(updated) => updateRule(rule.id, updated)}
              onDelete={() => deleteRule(rule.id)}
              onMoveUp={() => moveRule(idx, -1)}
              onMoveDown={() => moveRule(idx, 1)}
              isFirst={idx === 0}
              isLast={idx === rules.length - 1}
            />
          ))}

          <button
            onClick={addRule}
            className="
              w-full p-4 border-2 border-dashed border-[var(--border-default)]
              rounded-xl text-neutral-600 hover:text-neutral-400
              hover:border-[var(--border-strong)] transition-colors
              flex items-center justify-center gap-2 text-sm
            "
            aria-label="Add new rule"
          >
            <Plus size={16} aria-hidden="true" />
            Add Rule Block
          </button>
        </div>

        {/* Right panel: agent selector + preview + save */}
        <div className="space-y-4">
          <Card title="Apply to Agent" icon={ChevronRight}>
            <div className="space-y-3">
              <select
                value={selectedAgent}
                onChange={(e) => { setSelectedAgent(e.target.value); setError('') }}
                aria-label="Select agent for policy"
                className="input-standard h-9 text-xs w-full"
              >
                <option value="" className="bg-[#080808]">Select agent…</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id} className="bg-[#080808]">
                    {a.name} ({a.id.slice(0, 8)})
                  </option>
                ))}
              </select>

              {error && (
                <div className="flex items-center gap-2 p-2.5 rounded-lg bg-red-500/[0.06] border border-red-500/15">
                  <AlertTriangle size={12} className="text-red-400 shrink-0" aria-hidden="true" />
                  <p className="text-xs text-red-400">{error}</p>
                </div>
              )}

              {saved && (
                <div className="flex items-center gap-2 p-2.5 rounded-lg bg-green-500/[0.06] border border-green-500/15">
                  <CheckCircle2 size={12} className="text-green-400 shrink-0" aria-hidden="true" />
                  <p className="text-xs text-green-400">Policy applied successfully.</p>
                </div>
              )}

              <Button
                className="w-full"
                loading={saving}
                disabled={!selectedAgent || rules.length === 0}
                onClick={handleSave}
              >
                <Save size={13} aria-hidden="true" />
                Save Policy ({rules.length} rule{rules.length !== 1 ? 's' : ''})
              </Button>
            </div>
          </Card>

          {/* Rule summary */}
          <Card title="Rule Summary">
            <div className="space-y-2">
              {rules.map((rule, idx) => (
                <div key={rule.id} className="flex items-center gap-2 p-2.5 rounded-lg bg-white/[0.02] border border-[var(--border-subtle)]">
                  <span className="text-[10px] font-bold text-neutral-600">{idx + 1}</span>
                  <div className="flex-1 min-w-0">
                    <span className="text-xs text-neutral-400 truncate block">
                      {rule.conditions.length} condition{rule.conditions.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <span className={`status-badge text-[10px] ${ACTION_STYLES[rule.action] ?? ''}`}>
                    {rule.action}
                  </span>
                </div>
              ))}
            </div>
          </Card>

          {/* JSON Preview */}
          {showPreview && (
            <Card title="JSON Preview" icon={Eye}>
              <pre className="text-[10px] text-neutral-400 bg-black/30 border border-[var(--border-subtle)] rounded-xl p-3 overflow-x-auto leading-relaxed max-h-80">
                {JSON.stringify(preview, null, 2)}
              </pre>
            </Card>
          )}

          {/* Simulation time range + trigger */}
          <Card title="Simulation" icon={FlaskConical}>
            <div className="space-y-3">
              <div>
                <label className="text-[10px] text-neutral-500 uppercase tracking-widest block mb-1.5">
                  Replay window
                </label>
                <div className="flex gap-1.5">
                  {['1h', '6h', '24h', '7d'].map(r => (
                    <button
                      key={r}
                      onClick={() => setSimTimeRange(r)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors border ${
                        simTimeRange === r
                          ? 'text-purple-300 bg-purple-500/10 border-purple-500/30'
                          : 'text-neutral-600 bg-white/[0.02] border-white/[0.06] hover:text-neutral-400 hover:border-white/10'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={handleSimulate}
                disabled={simulating || !selectedAgent}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 text-xs text-purple-400 bg-purple-500/[0.06] border border-purple-500/20 rounded-lg hover:border-purple-500/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <FlaskConical size={12} />
                {simulating ? 'Running simulation…' : 'Run Dry-Run Simulation'}
              </button>
            </div>
          </Card>

          {/* Simulation Results */}
          {simResult && (
            <Card title="Simulation Results" icon={FlaskConical}>
              <div className="space-y-3">
                {/* Summary stats */}
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { label: 'Events', val: simResult.total_events, cls: 'text-white' },
                    { label: '% Blocked', val: simResult.total_events > 0 ? `${((simResult.would_deny / simResult.total_events) * 100).toFixed(0)}%` : '0%', cls: 'text-red-400' },
                    { label: 'Changed', val: simResult.diff?.length ?? 0, cls: 'text-amber-400' },
                  ].map(({ label, val, cls }) => (
                    <div key={label} className="text-center p-2 rounded-lg bg-white/[0.02] border border-white/[0.05]">
                      <p className={`text-base font-bold ${cls}`}>{val}</p>
                      <p className="text-[10px] text-neutral-600">{label}</p>
                    </div>
                  ))}
                </div>

                {/* Allow vs Deny bar */}
                {simResult.total_events > 0 && (
                  <div>
                    <div className="flex justify-between text-[10px] text-neutral-600 mb-1">
                      <span className="text-green-400">{simResult.would_allow} allow</span>
                      <span className="text-red-400">{simResult.would_deny} deny</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-white/[0.05] overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-green-500 to-red-500 rounded-full"
                        style={{ width: `${(simResult.would_allow / simResult.total_events) * 100}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Changed decisions sample */}
                {simResult.diff?.length > 0 && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-600 mb-2">
                      Sample decision changes
                    </p>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {simResult.diff.map((d) => (
                        <div key={d.event_id} className="flex items-center gap-2 text-[10px] p-1.5 rounded bg-white/[0.02] border border-white/[0.04]">
                          <span className="font-mono text-neutral-500 shrink-0 w-12 truncate">{d.tool}</span>
                          <span className="font-mono text-neutral-700">
                            risk {(d.risk_score * 100).toFixed(0)}%
                          </span>
                          <span className="ml-auto flex items-center gap-1 shrink-0">
                            <span className={d.old_decision === 'deny' ? 'text-red-400' : 'text-green-400'}>
                              {d.old_decision}
                            </span>
                            <span className="text-neutral-700">→</span>
                            <span className={d.new_decision === 'deny' ? 'text-red-400' : 'text-green-400'}>
                              {d.new_decision}
                            </span>
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {simResult.diff?.length === 0 && simResult.total_events > 0 && (
                  <p className="text-[11px] text-green-400 text-center py-1">
                    No decision changes — policy matches existing behaviour.
                  </p>
                )}

                {simResult.total_events === 0 && (
                  <p className="text-[11px] text-neutral-500 text-center py-1">
                    No audit events found for this agent in the selected window.
                  </p>
                )}

                <button
                  onClick={() => setSimResult(null)}
                  className="text-[10px] text-neutral-600 hover:text-neutral-400 transition-colors w-full text-center"
                >
                  Clear results
                </button>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

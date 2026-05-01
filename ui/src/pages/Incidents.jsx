import React, { useState, useEffect, useCallback, useContext } from 'react';
import {
  AlertTriangle, Shield, Clock, CheckCircle2, XCircle,
  RefreshCw, Filter, ChevronRight, Zap, User,
  Activity, TrendingDown, Eye, Lock, Slash, ArrowUpRight,
} from 'lucide-react';
import Card from '../components/Common/Card';
import Button from '../components/Common/Button';
import SkeletonLoader from '../components/Common/SkeletonLoader';
import Modal from '../components/Common/Modal';
import { incidentService, socService } from '../services/api';
import { AuthContext } from '../context/AuthContext';
import { eventBus } from '../lib/eventBus';

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_CONFIG = {
  CRITICAL: { cls: 'text-red-400 bg-red-500/10 border-red-500/30',   dot: 'bg-red-500',    label: 'Critical' },
  HIGH:     { cls: 'text-orange-400 bg-orange-500/10 border-orange-500/30', dot: 'bg-orange-500', label: 'High' },
  MEDIUM:   { cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30',  dot: 'bg-amber-500',  label: 'Medium' },
  LOW:      { cls: 'text-green-400 bg-green-500/10 border-green-500/30',   dot: 'bg-green-500',  label: 'Low' },
};

const STATUS_CONFIG = {
  OPEN:          { cls: 'text-red-400 bg-red-500/10 border-red-500/20',       label: 'Open' },
  INVESTIGATING: { cls: 'text-amber-400 bg-amber-500/10 border-amber-500/20', label: 'Investigating' },
  ESCALATED:     { cls: 'text-purple-400 bg-purple-500/10 border-purple-500/20', label: 'Escalated' },
  MITIGATED:     { cls: 'text-blue-400 bg-blue-500/10 border-blue-500/20',    label: 'Mitigated' },
  RESOLVED:      { cls: 'text-green-400 bg-green-500/10 border-green-500/20', label: 'Resolved' },
};

// Must mirror backend _ALLOWED_TRANSITIONS exactly
const VALID_TRANSITIONS = {
  OPEN:          ['INVESTIGATING'],
  INVESTIGATING: ['MITIGATED', 'ESCALATED', 'RESOLVED'],
  ESCALATED:     ['MITIGATED', 'RESOLVED'],
  MITIGATED:     ['RESOLVED'],
  RESOLVED:      [],
};

const ACTION_TYPES = [
  { value: 'KILL_AGENT',  label: 'Kill Agent',    icon: Slash,    cls: 'text-red-400' },
  { value: 'BLOCK_AGENT', label: 'Block Agent',   icon: Lock,     cls: 'text-orange-400' },
  { value: 'ISOLATE',     label: 'Isolate Agent', icon: Shield,   cls: 'text-amber-400' },
  { value: 'ESCALATE',    label: 'Escalate',      icon: ArrowUpRight, cls: 'text-blue-400' },
  { value: 'REASSIGN',    label: 'Reassign',      icon: User,     cls: 'text-purple-400' },
  { value: 'NOTE',        label: 'Add Note',      icon: Eye,      cls: 'text-neutral-400' },
];

function SeverityBadge({ severity }) {
  const cfg = SEV_CONFIG[severity] || SEV_CONFIG.LOW;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.OPEN;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.cls}`}>
      {cfg.label}
    </span>
  );
}

function ScoreGauge({ score }) {
  const n = Number(score) || 0;
  const color = n >= 80 ? 'text-green-400' : n >= 60 ? 'text-amber-400' : 'text-red-400';
  const ring  = n >= 80 ? 'stroke-green-500' : n >= 60 ? 'stroke-amber-500' : 'stroke-red-500';
  const r = 28, circ = 2 * Math.PI * r;
  const dash = (n / 100) * circ;
  return (
    <div className="relative inline-flex items-center justify-center w-20 h-20">
      <svg className="-rotate-90" width="72" height="72" viewBox="0 0 72 72">
        <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
        <circle cx="36" cy="36" r={r} fill="none" className={ring} strokeWidth="6"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-lg font-bold ${color}`}>{n}</span>
        <span className="text-[9px] text-neutral-500 font-mono -mt-0.5">SCORE</span>
      </div>
    </div>
  );
}

// ── Detail Modal ──────────────────────────────────────────────────────────────

function IncidentDetail({ incident, onClose, onRefresh }) {
  const { addToast } = useContext(AuthContext);
  const [loading,    setLoading]    = useState(false);
  const [actionType, setActionType] = useState('NOTE');
  const [note,       setNote]       = useState('');
  const [by,         setBy]         = useState('');

  const transitions = VALID_TRANSITIONS[incident.status] || [];

  const handleStatus = async (newStatus) => {
    try {
      setLoading(true);
      await incidentService.update(incident.id, { status: newStatus, note: `Status changed to ${newStatus}` });
      addToast(`Incident moved to ${newStatus}`, 'success');
      onRefresh();
      onClose();
    } catch (err) {
      const detail = err?.response?.data?.detail || err?.message || 'Transition not allowed';
      addToast(`Failed: ${detail}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async () => {
    if (!by.trim()) { addToast('Enter responder name', 'error'); return; }
    try {
      setLoading(true);
      await incidentService.addAction(incident.id, { type: actionType, by: by.trim(), note: note.trim() });
      addToast('Action recorded', 'success');
      setNote(''); setBy('');
      onRefresh();
    } catch {
      addToast('Failed to record action', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Modal isOpen onClose={onClose} title={`${incident.incident_number} — Detail`} size="xl">
      <div className="space-y-5">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-white">{incident.title}</h3>
            <p className="text-xs text-neutral-500 mt-0.5 font-mono">
              Agent {incident.agent_id?.slice(0, 8)} · {incident.tool || 'N/A'} · Risk {(incident.risk_score * 100).toFixed(0)}%
            </p>
            {incident.explanation && (
              <p className="text-xs text-neutral-400 mt-2 leading-relaxed bg-white/[0.03] rounded px-2 py-1.5 border border-white/[0.06]">
                {incident.explanation}
              </p>
            )}
            {/* SLA timestamps */}
            <div className="flex gap-4 mt-2 text-[10px] text-neutral-600 font-mono">
              {incident.acknowledged_at && <span>ACK {new Date(incident.acknowledged_at).toLocaleTimeString()}</span>}
              {incident.mitigated_at    && <span>MIT {new Date(incident.mitigated_at).toLocaleTimeString()}</span>}
              {incident.resolved_at     && <span>RES {new Date(incident.resolved_at).toLocaleTimeString()}</span>}
              {incident.violation_count > 1 && (
                <span className="text-amber-600">{incident.violation_count}x repeated</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
        </div>

        {/* Status transitions */}
        {transitions.length > 0 && (
          <div>
            <p className="text-xs text-neutral-500 mb-2 font-medium">Move Status</p>
            <div className="flex gap-2 flex-wrap">
              {transitions.map((s) => (
                <Button key={s} size="sm" variant="secondary" onClick={() => handleStatus(s)} disabled={loading}>
                  {STATUS_CONFIG[s]?.label || s}
                </Button>
              ))}
            </div>
          </div>
        )}

        {/* Timeline */}
        {incident.timeline?.length > 0 && (
          <div>
            <p className="text-xs text-neutral-500 mb-2 font-medium">Timeline</p>
            <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
              {[...incident.timeline].reverse().map((e, i) => (
                <div key={i} className="flex gap-2.5 text-xs">
                  <span className="text-neutral-600 font-mono shrink-0 mt-0.5">
                    {new Date(e.ts || e.timestamp).toLocaleTimeString()}
                  </span>
                  <div>
                    <span className="text-neutral-300">{e.event || e.action}</span>
                    {e.note && <span className="text-neutral-500 ml-1.5">— {e.note}</span>}
                    {e.by  && <span className="text-neutral-600 ml-1.5">by {e.by}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Response action */}
        <div className="border border-white/[0.06] rounded-lg p-4 space-y-3">
          <p className="text-xs font-medium text-neutral-400">Add Response Action</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-neutral-500 block mb-1">Action</label>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="input-standard input-compact w-full text-xs"
              >
                {ACTION_TYPES.map((a) => (
                  <option key={a.value} value={a.value}>{a.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-neutral-500 block mb-1">Responder</label>
              <input
                type="text"
                placeholder="Your name"
                value={by}
                onChange={(e) => setBy(e.target.value)}
                className="input-standard input-compact w-full text-xs"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-neutral-500 block mb-1">Note (optional)</label>
            <textarea
              rows={2}
              placeholder="What was done..."
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="input-standard w-full text-xs resize-none"
            />
          </div>
          <Button size="sm" onClick={handleAction} disabled={loading}>
            {loading ? 'Saving…' : 'Record Action'}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

// ── SOC Feed ──────────────────────────────────────────────────────────────────

const SOC_SEV = {
  CRITICAL: { cls: 'text-red-400',    bar: 'bg-red-500',    dot: 'bg-red-500' },
  HIGH:     { cls: 'text-orange-400', bar: 'bg-orange-500', dot: 'bg-orange-500' },
  MEDIUM:   { cls: 'text-amber-400',  bar: 'bg-amber-500',  dot: 'bg-amber-500' },
  LOW:      { cls: 'text-neutral-400',bar: 'bg-neutral-600',dot: 'bg-neutral-600' },
};

const SOC_TYPE_LABEL = {
  agent_kill:  'Agent Kill',
  escalation:  'Escalation',
  policy_deny: 'Policy Deny',
  high_risk:   'High Risk',
};

function SocFeed() {
  const { addToast } = useContext(AuthContext);
  const [events,  setEvents]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit,   setLimit]   = useState(60);

  const fetchFeed = useCallback(async () => {
    setLoading(true);
    try {
      const res = await socService.getTimeline(limit);
      setEvents(res?.data || []);
    } catch {
      addToast('Failed to load SOC feed', 'error');
    } finally {
      setLoading(false);
    }
  }, [limit, addToast]);

  useEffect(() => { fetchFeed(); }, [fetchFeed]);

  useEffect(() => {
    const u1 = eventBus.on('policy_decision', fetchFeed);
    const u2 = eventBus.on('incident_updated', fetchFeed);
    return () => { u1(); u2(); };
  }, [fetchFeed]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-purple-400" />
          <span className="text-xs text-neutral-400">Live security event feed — deny, kill, escalation, high-risk</span>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="input-standard input-compact text-xs w-24"
          >
            {[30, 60, 100, 200].map(n => <option key={n} value={n}>Last {n}</option>)}
          </select>
          <Button variant="secondary" size="sm" onClick={fetchFeed} disabled={loading}>
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </Button>
        </div>
      </div>

      <Card>
        {loading ? (
          <div className="p-4"><SkeletonLoader count={8} /></div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16">
            <Shield size={32} className="text-neutral-700 mb-3" />
            <p className="text-sm text-neutral-500">No security events in the selected window</p>
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {events.map((ev, i) => {
              const sev = SOC_SEV[ev.severity] || SOC_SEV.LOW;
              return (
                <div key={ev.id || i} className="flex items-start gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors">
                  {/* Severity bar */}
                  <div className={`w-0.5 self-stretch rounded-full shrink-0 ${sev.bar}`} />

                  {/* Dot + type */}
                  <div className="shrink-0 pt-0.5">
                    <span className={`inline-flex items-center gap-1 text-[10px] font-medium ${sev.cls}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
                      {ev.severity}
                    </span>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-[10px] text-neutral-500 font-mono">
                        {SOC_TYPE_LABEL[ev.type] || ev.type}
                      </span>
                      <span className="text-[10px] text-neutral-700 font-mono">
                        agent {ev.agent_id?.slice(0, 8)}
                      </span>
                      {ev.tool && (
                        <span className="text-[10px] px-1.5 py-0 rounded border border-white/[0.06] text-neutral-600 font-mono">
                          {ev.tool}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-neutral-300 leading-snug truncate">{ev.message}</p>
                  </div>

                  {/* Risk + time */}
                  <div className="shrink-0 text-right">
                    <p className={`text-[11px] font-mono font-bold ${ev.risk_score >= 0.9 ? 'text-red-400' : ev.risk_score >= 0.7 ? 'text-orange-400' : 'text-neutral-500'}`}>
                      {(ev.risk_score * 100).toFixed(0)}%
                    </p>
                    <p className="text-[10px] text-neutral-700 font-mono mt-0.5">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const SEVERITY_OPTIONS = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUS_OPTIONS   = ['', 'OPEN', 'INVESTIGATING', 'ESCALATED', 'MITIGATED', 'RESOLVED'];

export default function Incidents() {
  const { addToast } = useContext(AuthContext);

  const [activeTab, setActiveTab] = useState('incidents');

  const [summary,  setSummary]  = useState(null);
  const [items,    setItems]    = useState([]);
  const [total,    setTotal]    = useState(0);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState(null);

  const [filterStatus,   setFilterStatus]   = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [page,           setPage]           = useState(0);
  const PAGE_SIZE = 25;

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [sumRes, listRes] = await Promise.all([
        incidentService.getSummary(),
        incidentService.list({
          status:   filterStatus   || undefined,
          severity: filterSeverity || undefined,
          limit:    PAGE_SIZE,
          offset:   page * PAGE_SIZE,
        }),
      ]);
      setSummary(sumRes?.data || sumRes || null);
      const listData = listRes?.data || listRes || {};
      setItems(listData.items || []);
      setTotal(listData.total || 0);
    } catch (e) {
      addToast('Failed to load incidents', 'error');
    } finally {
      setLoading(false);
    }
  }, [filterStatus, filterSeverity, page, addToast]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Real-time updates: SSE events + 30-second polling fallback
  useEffect(() => {
    const interval = setInterval(fetchAll, 30_000);
    const u1 = eventBus.on('incident_updated', fetchAll);
    const u2 = eventBus.on('policy_decision',  fetchAll);
    return () => { clearInterval(interval); u1(); u2(); };
  }, [fetchAll]);

  const s = summary || {};
  const secScore  = Number(s.security_score ?? 100);
  const openCrit  = Number(s.critical  ?? 0);
  const openHigh  = Number(s.high      ?? 0);
  const openCount = Number(s.open      ?? 0);
  const mttr      = Number(s.mttr_hours ?? 0).toFixed(1);
  const mtta      = Number(s.mtta_hours ?? 0).toFixed(1);
  const trend     = s.trend || 'stable';
  const trendIcon = trend === 'improving' ? '↑' : trend === 'degrading' ? '↓' : '→';
  const trendCls  = trend === 'improving' ? 'text-green-400' : trend === 'degrading' ? 'text-red-400' : 'text-neutral-500';

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-white">Incident Management</h1>
          <p className="text-xs text-neutral-500 mt-0.5">Security incidents auto-created from policy denials and agent kills</p>
        </div>
        <Button variant="secondary" size="sm" onClick={fetchAll} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </Button>
      </div>

      {/* Tab navigation */}
      <div className="flex gap-1 p-1 bg-white/[0.02] border border-white/[0.06] rounded-lg w-fit">
        {[
          { id: 'incidents', label: 'Incidents', icon: AlertTriangle },
          { id: 'soc',       label: 'SOC Feed',  icon: Activity },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
              activeTab === id
                ? 'bg-white/[0.08] text-white'
                : 'text-neutral-500 hover:text-neutral-300'
            }`}
          >
            <Icon size={12} />
            {label}
          </button>
        ))}
      </div>

      {/* SOC Feed tab */}
      {activeTab === 'soc' && <SocFeed />}

      {/* Incidents tab content */}
      {activeTab !== 'soc' && <>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4 flex items-center gap-4">
          <ScoreGauge score={secScore} />
          <div>
            <p className="text-xs text-neutral-500">Security Score</p>
            <p className="text-[10px] text-neutral-600 mt-0.5">
              {secScore >= 80 ? 'Healthy' : secScore >= 60 ? 'At Risk' : 'Critical'}
            </p>
            <p className={`text-[10px] font-mono mt-0.5 ${trendCls}`}>{trendIcon} {trend}</p>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={14} className="text-red-400" />
            <p className="text-xs text-neutral-500">Open Incidents</p>
          </div>
          <p className="text-2xl font-bold text-white">{openCount}</p>
          {openCrit > 0 && (
            <p className="text-[10px] text-red-400 mt-1">{openCrit} critical</p>
          )}
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={14} className="text-amber-400" />
            <p className="text-xs text-neutral-500">High Severity</p>
          </div>
          <p className="text-2xl font-bold text-white">{openHigh}</p>
          <p className="text-[10px] text-neutral-600 mt-1">open high-risk</p>
        </Card>

        <Card className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <Clock size={14} className="text-blue-400" />
            <p className="text-xs text-neutral-500">MTTR / MTTA</p>
          </div>
          <p className="text-2xl font-bold text-white">{mttr}h</p>
          <p className="text-[10px] text-neutral-600 mt-1">ack in {mtta}h · resolve in {mttr}h</p>
        </Card>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Filter size={13} className="text-neutral-500" />
          <select
            value={filterStatus}
            onChange={(e) => { setFilterStatus(e.target.value); setPage(0); }}
            className="input-standard input-compact text-xs w-36"
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>{s || 'All Statuses'}</option>
            ))}
          </select>
          <select
            value={filterSeverity}
            onChange={(e) => { setFilterSeverity(e.target.value); setPage(0); }}
            className="input-standard input-compact text-xs w-36"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>{s || 'All Severities'}</option>
            ))}
          </select>
          {(filterStatus || filterSeverity) && (
            <button
              onClick={() => { setFilterStatus(''); setFilterSeverity(''); setPage(0); }}
              className="text-xs text-neutral-500 hover:text-white transition-colors"
            >
              Clear filters
            </button>
          )}
          <span className="ml-auto text-xs text-neutral-600">{total} total</span>
        </div>
      </Card>

      {/* Cross-agent correlation (Gap 6) */}
      {items.length > 0 && (() => {
        const agentMap = {};
        for (const inc of items) {
          if (!agentMap[inc.agent_id]) agentMap[inc.agent_id] = { id: inc.agent_id, incidents: [], maxSev: 'LOW' };
          agentMap[inc.agent_id].incidents.push(inc);
          const sevOrd = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          if ((sevOrd[inc.severity] || 0) > (sevOrd[agentMap[inc.agent_id].maxSev] || 0)) {
            agentMap[inc.agent_id].maxSev = inc.severity;
          }
        }
        const correlated = Object.values(agentMap).filter(a => a.incidents.length > 1).sort((a, b) => b.incidents.length - a.incidents.length).slice(0, 5);
        if (!correlated.length) return null;
        return (
          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <Activity size={13} className="text-purple-400" />
              <p className="text-xs font-medium text-neutral-300">Cross-Agent Correlation</p>
              <span className="text-[10px] text-neutral-600 ml-auto">{correlated.length} agents with multiple incidents</span>
            </div>
            <div className="space-y-2">
              {correlated.map(a => (
                <div key={a.id} className="flex items-center gap-3 py-1.5 border-b border-white/[0.04] last:border-0">
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_CONFIG[a.maxSev]?.dot || 'bg-neutral-600'}`} />
                  <code className="text-xs text-neutral-400 font-mono">{a.id.slice(0, 8)}</code>
                  <div className="flex gap-1 flex-wrap flex-1">
                    {a.incidents.map(inc => (
                      <button key={inc.id} onClick={() => setSelected(inc)}
                        className="text-[10px] px-1.5 py-0.5 rounded border border-white/[0.08] text-neutral-500 hover:text-white hover:border-white/20 transition-colors font-mono">
                        {inc.incident_number}
                      </button>
                    ))}
                  </div>
                  <span className="text-[10px] text-neutral-600 shrink-0">{a.incidents.length} incidents</span>
                </div>
              ))}
            </div>
          </Card>
        );
      })()}

      {/* Incident list */}
      <Card>
        {loading ? (
          <div className="p-4"><SkeletonLoader count={6} /></div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <CheckCircle2 size={32} className="text-green-500 mb-3" />
            <p className="text-sm text-neutral-400">No incidents match the current filters</p>
            <p className="text-xs text-neutral-600 mt-1">Incidents are auto-created from policy denials and agent kills</p>
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {items.map((inc) => (
              <button
                key={inc.id}
                onClick={() => setSelected(inc)}
                className="w-full flex items-center gap-4 px-4 py-3.5 hover:bg-white/[0.03] transition-colors text-left group"
              >
                {/* Severity indicator */}
                <div className={`w-1 self-stretch rounded-full shrink-0 ${SEV_CONFIG[inc.severity]?.dot || 'bg-neutral-600'}`} />

                {/* Main info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-mono text-neutral-500 shrink-0">{inc.incident_number}</span>
                    <SeverityBadge severity={inc.severity} />
                    <StatusBadge status={inc.status} />
                  </div>
                  <p className="text-xs text-white font-medium truncate">{inc.title}</p>
                  <p className="text-[10px] text-neutral-600 mt-0.5 font-mono truncate">
                    Agent {inc.agent_id?.slice(0, 8)} · {inc.tool || 'N/A'} · Risk {(inc.risk_score * 100).toFixed(0)}%
                  </p>
                </div>

                {/* Meta */}
                <div className="shrink-0 text-right hidden sm:block">
                  <p className="text-[10px] text-neutral-600">
                    {new Date(inc.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  </p>
                  <p className="text-[10px] text-neutral-700 font-mono">
                    {new Date(inc.created_at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>

                <ChevronRight size={14} className="text-neutral-700 group-hover:text-neutral-400 transition-colors shrink-0" />
              </button>
            ))}
          </div>
        )}

        {/* Pagination */}
        {total > PAGE_SIZE && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-white/[0.04]">
            <Button size="sm" variant="secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>
              Previous
            </Button>
            <span className="text-xs text-neutral-500">
              {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
            </span>
            <Button size="sm" variant="secondary" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * PAGE_SIZE >= total}>
              Next
            </Button>
          </div>
        )}
      </Card>

      </> /* end incidents tab */}

      {/* Detail modal — shown regardless of active tab */}
      {selected && (
        <IncidentDetail
          incident={selected}
          onClose={() => setSelected(null)}
          onRefresh={fetchAll}
        />
      )}
    </div>
  );
}

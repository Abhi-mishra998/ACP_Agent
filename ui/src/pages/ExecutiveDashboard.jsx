import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, riskService, dashboardService } from '../services/api';
import {
  DollarSign,
  ShieldAlert,
  Activity,
  AlertOctagon,
  TrendingUp,
  ChevronRight,
  BrainCircuit,
  ShieldCheck,
  Zap,
  ExternalLink,
  FileDown,
  Printer,
} from 'lucide-react';
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import Card from '../components/Common/Card';
import Button from '../components/Common/Button';
import SkeletonLoader from '../components/Common/SkeletonLoader';

/* ── AI Insight card ───────────────────────────────────────────────────────── */
const CONFIDENCE_STYLES = {
  HIGH:   'text-green-400 bg-green-500/10 border-green-500/20',
  MEDIUM: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  LOW:    'text-red-400   bg-red-500/10   border-red-500/20',
};

function InsightCard({ insight }) {
  const conf = (insight.confidence || 'LOW').toUpperCase();
  return (
    <div className="p-4 bg-white/[0.02] border border-white/[0.06] rounded-xl space-y-3 hover:border-white/10 transition-colors animate-scale-in">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-1.5 rounded-lg bg-white/[0.04] text-neutral-400 shrink-0 mt-0.5">
            <BrainCircuit size={15} aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <h4 className="text-xs font-bold text-white uppercase tracking-wide truncate">
              {insight.threat_classification || 'Unknown Threat'}
            </h4>
            <p className="text-xs text-neutral-500 mt-0.5 truncate">
              {insight.root_cause || 'Root cause undetermined'}
            </p>
          </div>
        </div>
        <span
          className={`status-badge shrink-0 ${CONFIDENCE_STYLES[conf] ?? CONFIDENCE_STYLES.LOW}`}
        >
          {conf}
        </span>
      </div>

      <p className="text-xs leading-relaxed text-neutral-400 line-clamp-2">
        {insight.narrative || 'No narrative available for this event.'}
      </p>

      <div className="flex items-center justify-between pt-1">
        <span className="text-xs text-neutral-600">
          Rec: <span className="text-neutral-400 font-medium">{insight.recommendation || 'MONITOR'}</span>
        </span>
      </div>
    </div>
  );
}

/* ── Main component ────────────────────────────────────────────────────────── */
export default function ExecutiveDashboard() {
  const navigate = useNavigate();
  const [billing,  setBilling]  = useState(null);
  const [risk,     setRisk]     = useState(null);
  const [insights, setInsights] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState('');

  useEffect(() => {
    let mounted = true;
    const fetchData = async () => {
      try {
        // Single aggregated call instead of 3 separate requests
        const res = await dashboardService.getState();
        if (!mounted) return;
        const state = res.data || res;
        setBilling(state.billing || {});
        setRisk(state.audit || {});
        const ins = state.insights || [];
        setInsights(Array.isArray(ins) ? ins.slice(0, 3) : []);
        setError('');
      } catch (err) {
        // Fallback: try individual calls if aggregate endpoint is unreachable
        try {
          const [billingRes, riskRes, insightRes] = await Promise.all([
            api.getBilling(),
            api.getRisk(),
            riskService.getInsights(),
          ]);
          if (!mounted) return;
          setBilling(billingRes.data || billingRes);
          setRisk(riskRes.data || riskRes);
          const insData = insightRes.data || insightRes;
          setInsights(Array.isArray(insData) ? insData.slice(0, 3) : []);
          setError('');
        } catch (fallbackErr) {
          if (mounted) setError(fallbackErr.message || 'Failed to sync backend modules.');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  if (loading) return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        {[...Array(4)].map((_, i) => <SkeletonLoader key={i} variant="card" />)}
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2"><SkeletonLoader className="h-96" /></div>
        <SkeletonLoader className="h-96" />
      </div>
    </div>
  );

  const savedVal      = billing?.money_saved       || billing?.today?.money_saved       || 0;
  const costPrevVal   = billing?.cost_prevented    || billing?.today?.cost_prevented    || 0;
  const threatsBlocked = risk?.threats_blocked  || 0;
  const highRiskAgents = risk?.high_risk_agents || 0;
  const totalRequests  = risk?.total_requests   || 0;
  const chartData      = (risk?.metrics || []);

  return (
    <div className="space-y-8">
      {/* ── Page header ── */}
      <div className="page-header">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight text-white">Executive Overview</h1>
          <p className="text-xs text-neutral-500">ROI analytics and real-time threat intelligence</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => window.print()}
          >
            <Printer size={13} aria-hidden="true" />
            Export PDF
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/audit-logs')}
          >
            View Audit Logs
            <ChevronRight size={14} aria-hidden="true" />
          </Button>
        </div>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div className="error-banner" role="alert">
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      {/* ── ROI hero strip ── */}
      <div className="kpi-strip group">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-500/[0.04] to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" aria-hidden="true" />
        <div className="relative flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
          <div className="flex items-center gap-5">
            <div className="w-12 h-12 rounded-xl bg-white flex items-center justify-center shrink-0">
              <TrendingUp size={24} className="text-black" aria-hidden="true" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Total Value Secured</h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Automated risk mitigation secured{' '}
                <span className="text-white font-semibold">
                  ${(costPrevVal + savedVal).toLocaleString()}
                </span>{' '}
                in operational assets
              </p>
            </div>
          </div>
          <div className="text-3xl font-bold tracking-tight text-white shrink-0">
            ${(costPrevVal + savedVal).toLocaleString()}
          </div>
        </div>
      </div>

      {/* ── KPI cards ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        <Card
          title="Assets Saved"
          value={`$${savedVal.toLocaleString()}`}
          subtitle="Direct operational recovery"
          icon={DollarSign}
          trend={savedVal > 0 ? 'up' : undefined}
          trendValue={savedVal > 0 ? 'Protected' : undefined}
        />
        <Card
          title="Cost Aversion"
          value={`$${costPrevVal.toLocaleString()}`}
          subtitle="Prevented data-loss impact"
          icon={Activity}
          trend={costPrevVal > 0 ? 'up' : undefined}
          trendValue={costPrevVal > 0 ? 'Active' : undefined}
        />
        <Card
          title="Threats Neutralized"
          value={threatsBlocked.toLocaleString()}
          subtitle={`${totalRequests.toLocaleString()} total requests`}
          icon={ShieldAlert}
          trend={threatsBlocked > 0 ? 'up' : undefined}
          trendValue={threatsBlocked > 0 ? 'Blocking' : undefined}
        />
        <Card
          title="Volatility Index"
          value={highRiskAgents.toLocaleString()}
          subtitle="High-risk agent nodes"
          icon={AlertOctagon}
          trend={highRiskAgents > 0 ? 'down' : 'up'}
          trendValue={highRiskAgents > 0 ? 'Elevated' : 'Stable'}
        />
      </div>

      {/* ── Charts + AI stream ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 space-y-6">
          {/* Risk behavioural chart */}
          <div className="card-premium p-6 space-y-5">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">Risk Behavioral Flow</h3>
                <p className="text-xs text-neutral-500 mt-0.5">Continuous behavioral analysis</p>
              </div>
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-500/10 border border-green-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
                <span className="text-xs font-medium text-green-400">Live</span>
              </div>
            </div>

            <div className="h-72">
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#ffffff" stopOpacity={0.12} />
                        <stop offset="95%" stopColor="#ffffff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.03)" />
                    <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#525252', fontSize: 11 }} />
                    <YAxis axisLine={false} tickLine={false} tick={{ fill: '#525252', fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid rgba(255,255,255,0.06)', borderRadius: '10px' }}
                      itemStyle={{ fontSize: '11px', color: '#fff' }}
                    />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#ffffff"
                      strokeWidth={2}
                      fill="url(#scoreGrad)"
                      animationDuration={1500}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center gap-3 opacity-30">
                  <Activity size={32} className="text-neutral-700" aria-hidden="true" />
                  <p className="text-xs text-neutral-500">No behavioral data yet</p>
                </div>
              )}
            </div>
          </div>

          {/* System status cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
            <Card title="System Integrity">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-green-500/10">
                  <ShieldCheck size={18} className="text-green-400" aria-hidden="true" />
                </div>
                <div>
                  <p className="text-sm font-bold text-white">Active Defense</p>
                  <p className="text-xs text-neutral-500">99.99% resilience</p>
                </div>
              </div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-white/60 w-full rounded-full" aria-label="100% capacity" />
              </div>
              <p className="text-xs text-neutral-600 mt-2">All security nodes synchronized</p>
            </Card>

            <Card title="Detection Sensitivity">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-blue-500/10">
                  <Zap size={18} className="text-blue-400" aria-hidden="true" />
                </div>
                <div>
                  <p className="text-sm font-bold text-white">Neural Mode</p>
                  <p className="text-xs text-neutral-500">Strict calibration</p>
                </div>
              </div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 w-3/4 rounded-full"
                  style={{ boxShadow: '0 0 8px rgba(59,130,246,0.5)' }}
                  aria-label="75% sensitivity"
                />
              </div>
              <p className="text-xs text-neutral-600 mt-2">Optimized for enterprise traffic</p>
            </Card>
          </div>
        </div>

        {/* AI Intelligence stream */}
        <div className="card-premium p-6 flex flex-col gap-5">
          <div>
            <div className="flex items-center gap-2">
              <BrainCircuit size={16} className="text-neutral-400" aria-hidden="true" />
              <h3 className="text-sm font-bold text-white">AI Intelligence Stream</h3>
            </div>
            <p className="text-xs text-neutral-500 mt-0.5">Threat narratives by Groq LLM</p>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto">
            {insights.length > 0 ? (
              insights.map((insight, idx) => (
                <InsightCard key={insight.event_id || idx} insight={insight} />
              ))
            ) : (
              <div className="flex flex-col items-center justify-center py-12 gap-3 opacity-30">
                <BrainCircuit size={36} className="text-neutral-700" aria-hidden="true" />
                <p className="text-xs text-neutral-500 text-center">Scanning behavioral stream…</p>
              </div>
            )}
          </div>

          <Button
            variant="outline"
            size="sm"
            className="w-full"
            onClick={() => navigate('/risk')}
          >
            <ExternalLink size={13} aria-hidden="true" />
            View All Insights
          </Button>
        </div>
      </div>
    </div>
  );
}

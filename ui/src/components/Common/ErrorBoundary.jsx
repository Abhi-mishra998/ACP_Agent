import React from 'react'
import { AlertOctagon, RefreshCw, Copy, CheckCircle2, ChevronDown, ChevronUp } from 'lucide-react'

function buildReport(error, errorInfo, incidentId) {
  return [
    `ACP SYSTEM ERROR REPORT`,
    `──────────────────────────────────────`,
    `Incident ID  : ${incidentId}`,
    `Timestamp    : ${new Date().toISOString()}`,
    `Error        : ${error?.message || 'Unknown error'}`,
    `Component    : ${errorInfo?.componentStack?.trim().split('\n')[1]?.trim() ?? 'Unknown'}`,
    `Stack        :`,
    error?.stack || 'No stack trace',
  ].join('\n')
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = {
      hasError:    false,
      error:       null,
      errorInfo:   null,
      incidentId:  null,
      copied:      false,
      stackOpen:   false,
    }
    this.handleReload = this.handleReload.bind(this)
    this.handleCopy   = this.handleCopy.bind(this)
    this.toggleStack  = this.toggleStack.bind(this)
  }

  static getDerivedStateFromError(error) {
    return {
      hasError:   true,
      error,
      incidentId: crypto.randomUUID(),
    }
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo })
    console.error('ErrorBoundary caught:', error, errorInfo)
  }

  handleReload() {
    this.setState({ hasError: false, error: null, errorInfo: null, incidentId: null })
    window.location.reload()
  }

  async handleCopy() {
    const { error, errorInfo, incidentId } = this.state
    const report = buildReport(error, errorInfo, incidentId)
    await navigator.clipboard.writeText(report).catch(() => {})
    this.setState({ copied: true })
    setTimeout(() => this.setState({ copied: false }), 2500)
  }

  toggleStack() {
    this.setState((s) => ({ stackOpen: !s.stackOpen }))
  }

  render() {
    if (!this.state.hasError) return this.props.children

    const { error, errorInfo, incidentId, copied, stackOpen } = this.state
    const componentLine = errorInfo?.componentStack?.trim().split('\n')[1]?.trim() ?? null

    return (
      <div
        className="fixed inset-0 z-[300] flex items-center justify-center bg-black overflow-auto"
        style={{
          background: 'radial-gradient(ellipse at 50% 0%, rgba(239,68,68,0.08) 0%, #000 55%)',
        }}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="err-title"
      >
        {/* Scanlines */}
        <div
          className="absolute inset-0 pointer-events-none"
          aria-hidden="true"
          style={{
            backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(239,68,68,0.012) 3px, rgba(239,68,68,0.012) 6px)',
          }}
        />

        <div
          className="relative w-full max-w-xl mx-4 my-8 rounded-2xl overflow-hidden"
          style={{
            background: 'rgba(6, 3, 3, 0.99)',
            border:     '1px solid rgba(239,68,68,0.2)',
            boxShadow:  '0 0 100px rgba(239,68,68,0.1), 0 0 0 1px rgba(239,68,68,0.08)',
          }}
        >
          {/* Top accent bar */}
          <div
            className="h-0.5 bg-gradient-to-r from-red-500/60 via-red-400 to-red-500/60"
            aria-hidden="true"
          />

          {/* Header */}
          <div className="flex items-start gap-4 p-6 border-b border-red-500/10">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0 bg-red-500/10 border border-red-500/20"
              style={{ boxShadow: '0 0 24px rgba(239,68,68,0.2)' }}
              aria-hidden="true"
            >
              <AlertOctagon size={22} className="text-red-400" />
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-red-500 mb-1">
                System Integrity Violation
              </p>
              <h1 id="err-title" className="text-base font-bold text-white leading-tight">
                Render Failure Detected
              </h1>
              <p className="text-xs text-neutral-500 mt-0.5">
                A component crashed — the UI has been isolated to prevent data corruption
              </p>
            </div>
          </div>

          {/* Details */}
          <div className="p-6 space-y-5">
            {/* Metadata grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Incident ID',  value: incidentId?.slice(0, 18) + '…' },
                { label: 'Timestamp',    value: new Date().toLocaleTimeString() },
                { label: 'Error Type',   value: error?.name ?? 'UnknownError' },
                ...(componentLine ? [{ label: 'Component', value: componentLine }] : []),
              ].map(({ label, value }) => (
                <div key={label} className="space-y-1">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">{label}</p>
                  <p className="text-xs font-mono text-neutral-300 truncate">{value}</p>
                </div>
              ))}
            </div>

            {/* Error message */}
            <div className="p-3 rounded-xl bg-red-500/[0.04] border border-red-500/10 space-y-1">
              <p className="text-[10px] font-bold uppercase tracking-widest text-red-500/70">Error</p>
              <p className="text-xs font-mono text-red-300/80 leading-relaxed break-words">
                {error?.message ?? 'An unexpected error occurred.'}
              </p>
            </div>

            {/* Stack trace (collapsible) */}
            {error?.stack && (
              <div className="border border-white/[0.05] rounded-xl overflow-hidden">
                <button
                  onClick={this.toggleStack}
                  className="w-full flex items-center justify-between px-4 py-2.5 bg-white/[0.02] hover:bg-white/[0.04] transition-colors"
                  aria-expanded={stackOpen}
                  aria-label={stackOpen ? 'Collapse stack trace' : 'Expand stack trace'}
                >
                  <span className="text-[10px] font-bold uppercase tracking-widest text-neutral-600">
                    Stack Trace
                  </span>
                  {stackOpen
                    ? <ChevronUp size={12} className="text-neutral-600" aria-hidden="true" />
                    : <ChevronDown size={12} className="text-neutral-600" aria-hidden="true" />
                  }
                </button>
                {stackOpen && (
                  <pre className="px-4 py-3 text-[10px] font-mono text-neutral-600 leading-relaxed overflow-x-auto max-h-40 border-t border-white/[0.04]">
                    {error.stack}
                  </pre>
                )}
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3 px-6 py-4 border-t border-red-500/10 bg-red-500/[0.02]">
            <button
              onClick={this.handleReload}
              className="
                flex-1 flex items-center justify-center gap-2
                px-4 py-2.5 rounded-xl text-xs font-bold text-white
                bg-red-500/20 border border-red-500/30
                hover:bg-red-500/30 hover:border-red-500/50
                transition-all active:scale-[0.98]
              "
              style={{ boxShadow: '0 0 20px rgba(239,68,68,0.08)' }}
            >
              <RefreshCw size={13} aria-hidden="true" />
              Reload System
            </button>
            <button
              onClick={this.handleCopy}
              className="
                flex items-center justify-center gap-2
                px-4 py-2.5 rounded-xl text-xs font-bold shrink-0
                bg-white/[0.04] border border-white/[0.08]
                hover:bg-white/[0.07] hover:border-white/[0.14]
                transition-all active:scale-[0.98]
              "
              style={{ color: copied ? '#22c55e' : '#71717a' }}
              aria-label={copied ? 'Error report copied' : 'Copy error report'}
            >
              {copied
                ? <><CheckCircle2 size={13} aria-hidden="true" /> Copied</>
                : <><Copy size={13} aria-hidden="true" /> Copy Report</>
              }
            </button>
          </div>

          {/* Footer note */}
          <div className="px-6 pb-4 text-center">
            <p className="text-[10px] text-neutral-700">
              This incident has been logged locally. Incident ID:{' '}
              <span className="font-mono text-neutral-600">{incidentId?.slice(0, 8)}</span>
            </p>
          </div>
        </div>
      </div>
    )
  }
}

export default ErrorBoundary

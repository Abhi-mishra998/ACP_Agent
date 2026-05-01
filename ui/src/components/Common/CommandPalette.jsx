import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, Activity, Shield, FileText, Users,
  Zap, BarChart2, Terminal, CreditCard, Code2,
  Power, Radio, HeartPulse, GitMerge, Lock,
  Command,
} from 'lucide-react'

const COMMANDS = [
  { id: 'dashboard',    label: 'Overview',        path: '/dashboard',     icon: Activity,   group: 'Navigate' },
  { id: 'agents',       label: 'Agent Hub',        path: '/agents',        icon: Users,      group: 'Navigate' },
  { id: 'security',     label: 'Security Ops',     path: '/security',      icon: Shield,     group: 'Navigate' },
  { id: 'risk',         label: 'Risk Engine',      path: '/risk',          icon: Zap,        group: 'Navigate' },
  { id: 'audit',        label: 'Audit Logs',       path: '/audit-logs',    icon: BarChart2,  group: 'Navigate' },
  { id: 'forensics',    label: 'Forensics',        path: '/forensics',     icon: FileText,   group: 'Navigate' },
  { id: 'policy',       label: 'Policy Builder',   path: '/policy-builder',icon: GitMerge,   group: 'Navigate' },
  { id: 'rbac',         label: 'RBAC Manager',     path: '/rbac',          icon: Lock,       group: 'Navigate' },
  { id: 'playground',   label: 'Playground',       path: '/playground',    icon: Terminal,   group: 'Navigate' },
  { id: 'observability',label: 'Observability',    path: '/observability', icon: Radio,      group: 'Navigate' },
  { id: 'system',       label: 'System Health',    path: '/system-health', icon: HeartPulse, group: 'Navigate' },
  { id: 'billing',      label: 'Usage & Billing',  path: '/billing',       icon: CreditCard, group: 'Navigate' },
  { id: 'developer',    label: 'Developer Panel',  path: '/developer',     icon: Code2,      group: 'Navigate' },
  { id: 'kill-switch',  label: 'Kill Switch',      path: '/kill-switch',   icon: Power,      group: 'Danger',  danger: true },
]

export default function CommandPalette({ isOpen, onClose }) {
  const navigate    = useNavigate()
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef    = useRef(null)
  const listRef     = useRef(null)

  const filtered = query.trim()
    ? COMMANDS.filter((c) =>
        c.label.toLowerCase().includes(query.toLowerCase()) ||
        c.group.toLowerCase().includes(query.toLowerCase())
      )
    : COMMANDS

  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setActiveIdx(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  useEffect(() => { setActiveIdx(0) }, [query])

  const execute = useCallback((cmd) => {
    navigate(cmd.path)
    onClose()
  }, [navigate, onClose])

  const handleKeyDown = (e) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setActiveIdx((v) => Math.min(v + 1, filtered.length - 1))
        break
      case 'ArrowUp':
        e.preventDefault()
        setActiveIdx((v) => Math.max(v - 1, 0))
        break
      case 'Enter':
        e.preventDefault()
        if (filtered[activeIdx]) execute(filtered[activeIdx])
        break
      case 'Escape':
        onClose()
        break
      default:
        break
    }
  }

  useEffect(() => {
    const el = listRef.current?.children[activeIdx]
    el?.scrollIntoView({ block: 'nearest' })
  }, [activeIdx])

  if (!isOpen) return null

  const groups = [...new Set(filtered.map((c) => c.group))]

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh]"
      aria-modal="true"
      role="dialog"
      aria-label="Command palette"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Panel */}
      <div
        className="
          relative w-full max-w-lg mx-4
          bg-[var(--bg-surface-elevated)] border border-[var(--border-strong)]
          rounded-2xl shadow-2xl overflow-hidden
          animate-scale-in
        "
        style={{ boxShadow: '0 0 60px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.06)' }}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[var(--border-subtle)]">
          <Search size={16} className="text-neutral-500 shrink-0" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search commands…"
            aria-label="Search commands"
            aria-autocomplete="list"
            aria-controls="cmd-list"
            aria-activedescendant={filtered[activeIdx] ? `cmd-${filtered[activeIdx].id}` : undefined}
            className="flex-1 bg-transparent text-sm text-white placeholder-neutral-600 focus:outline-none"
          />
          <kbd className="hidden sm:flex items-center gap-1 px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/10 text-[10px] text-neutral-500">
            <Command size={9} />K
          </kbd>
        </div>

        {/* Results */}
        <div
          id="cmd-list"
          ref={listRef}
          role="listbox"
          aria-label="Commands"
          className="max-h-80 overflow-y-auto py-2"
        >
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-xs text-neutral-600">
              No commands found for "{query}"
            </div>
          ) : (
            groups.map((group) => (
              <div key={group}>
                <p className="px-4 py-1.5 text-[10px] font-bold uppercase tracking-widest text-neutral-600">
                  {group}
                </p>
                {filtered
                  .filter((c) => c.group === group)
                  .map((cmd) => {
                    const globalIdx = filtered.indexOf(cmd)
                    const isActive  = globalIdx === activeIdx
                    const Icon      = cmd.icon
                    return (
                      <div
                        key={cmd.id}
                        id={`cmd-${cmd.id}`}
                        role="option"
                        aria-selected={isActive}
                        onClick={() => execute(cmd)}
                        onMouseEnter={() => setActiveIdx(globalIdx)}
                        className={`
                          flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors
                          ${isActive ? 'bg-white/[0.07]' : 'hover:bg-white/[0.04]'}
                        `}
                      >
                        <div className={`
                          p-1.5 rounded-lg bg-white/[0.04] border border-white/[0.06] shrink-0
                          ${cmd.danger ? 'text-red-400' : 'text-neutral-400'}
                          ${isActive ? 'border-white/10' : ''}
                        `}>
                          <Icon size={13} aria-hidden="true" />
                        </div>
                        <span className={`text-sm font-medium ${cmd.danger ? 'text-red-400' : 'text-neutral-200'}`}>
                          {cmd.label}
                        </span>
                        {isActive && (
                          <kbd className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/10 text-neutral-500">
                            ↵ Enter
                          </kbd>
                        )}
                      </div>
                    )
                  })}
              </div>
            ))
          )}
        </div>

        <div className="px-4 py-2 border-t border-[var(--border-subtle)] flex items-center gap-4 text-[10px] text-neutral-600">
          <span><kbd className="font-mono">↑↓</kbd> Navigate</span>
          <span><kbd className="font-mono">↵</kbd> Select</span>
          <span><kbd className="font-mono">Esc</kbd> Close</span>
        </div>
      </div>
    </div>
  )
}

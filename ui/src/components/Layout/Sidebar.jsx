import React, { useEffect, useRef } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  Users, Shield, FileText, X, Activity, Power, Zap,
  LogOut, Terminal, Code2, BarChart2, CreditCard,
  Radio, HeartPulse, GitMerge, Lock, AlertTriangle, Crosshair, Bot,
} from 'lucide-react'
import { authService } from '../../services/api'
import { useAuth } from '../../hooks/useAuth'
import { useRole } from '../../hooks/useRole'

const baseNavItems = [
  { path: '/dashboard',      label: 'Overview',         icon: Activity  },
  { path: '/observability',  label: 'Observability',    icon: Radio     },
  { path: '/system-health',  label: 'System Health',    icon: HeartPulse},
  { path: '/agents',         label: 'Agent Hub',        icon: Users     },
  { path: '/security',       label: 'Security Ops',     icon: Shield    },
  { path: '/incidents',      label: 'Incidents',        icon: AlertTriangle },
  { path: '/risk',           label: 'Risk Engine',      icon: Zap       },
  { path: '/audit-logs',     label: 'Audit Logs',       icon: BarChart2 },
  { path: '/forensics',      label: 'Forensics',        icon: FileText  },
  { path: '/policy-builder', label: 'Policy Builder',   icon: GitMerge  },
  { path: '/rbac',           label: 'RBAC Manager',     icon: Lock      },
  { path: '/attack-sim',     label: 'Attack Simulation', icon: Crosshair },
  { path: '/auto-response',  label: 'Auto Response',    icon: Bot       },
  { path: '/playground',     label: 'Playground',       icon: Terminal  },
  { path: '/billing',        label: 'Usage & Billing',  icon: CreditCard},
  { path: '/developer',      label: 'Developer',        icon: Code2     },
]

const killSwitchItem = { path: '/kill-switch', label: 'Kill Switch', icon: Power, danger: true }

export default function Sidebar({ isOpen, onClose }) {
  const location  = useLocation()
  const navigate  = useNavigate()
  const { updateAuth } = useAuth()
  const { canViewKillSwitch } = useRole()
  const navRef    = useRef(null)

  const navItems = canViewKillSwitch ? [...baseNavItems, killSwitchItem] : baseNavItems

  // Keyboard navigation inside sidebar
  useEffect(() => {
    if (!isOpen) return
    const handleKey = (e) => {
      if (e.key !== 'Tab') return
      const focusables = navRef.current?.querySelectorAll('a, button')
      if (!focusables?.length) return
      const first = focusables[0]
      const last  = focusables[focusables.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [isOpen])

  const handleLogout = async () => {
    try { await authService.logout() } catch {}
    updateAuth({ isAuthenticated: false, user: null, tenant_id: null, token: null })
    navigate('/login')
  }

  return (
    <>
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/75 lg:hidden z-40 backdrop-blur-sm transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside
        ref={navRef}
        className={`
          fixed lg:static inset-y-0 left-0 z-50
          w-64 flex flex-col
          bg-[var(--bg-surface)]
          border-r border-[var(--border-subtle)]
          transition-transform duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]
          ${isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}
        aria-label="Main navigation"
      >
        {/* Brand */}
        <div className="h-14 px-5 flex items-center justify-between border-b border-[var(--border-subtle)] shrink-0">
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-7 rounded-md bg-white flex items-center justify-center shrink-0"
              style={{ boxShadow: '0 0 12px rgba(255,255,255,0.15)' }}
            >
              <Shield className="text-black" size={15} />
            </div>
            <span className="text-xs font-bold tracking-tight text-white font-mono">AgentControl</span>
          </div>
          <button
            onClick={onClose}
            aria-label="Close navigation"
            className="lg:hidden p-1.5 rounded-lg text-neutral-500 hover:text-white hover:bg-white/[0.06] transition-colors"
          >
            <X size={17} />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto" aria-label="Application pages">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path ||
              (item.path !== '/dashboard' && location.pathname.startsWith(item.path))

            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={() => window.innerWidth < 1024 && onClose()}
                aria-current={isActive ? 'page' : undefined}
                className={`
                  flex items-center gap-2.5 px-3 py-2.5 rounded-lg
                  text-xs font-medium transition-all duration-150 outline-none
                  focus-visible:ring-1 focus-visible:ring-white/30
                  ${isActive
                    ? item.danger
                      ? 'bg-red-500/15 text-red-400 border border-red-500/20'
                      : 'bg-white text-black shadow-sm'
                    : item.danger
                      ? 'text-neutral-500 hover:text-red-400 hover:bg-red-500/10 border border-transparent'
                      : 'text-neutral-500 hover:text-white hover:bg-white/[0.05] border border-transparent hover:border-white/[0.06]'
                  }
                `}
                style={isActive && !item.danger ? { boxShadow: '0 1px 8px rgba(255,255,255,0.12)' } : undefined}
              >
                <item.icon size={15} className="shrink-0" aria-hidden="true" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="px-3 py-4 border-t border-[var(--border-subtle)] space-y-2 shrink-0">
          <button
            onClick={handleLogout}
            className="flex items-center gap-2.5 w-full px-3 py-2.5 rounded-lg text-xs font-medium text-neutral-500 hover:text-white hover:bg-red-500/10 transition-all duration-150"
          >
            <LogOut size={15} className="shrink-0" aria-hidden="true" />
            <span>Sign Out</span>
          </button>
          <div className="flex items-center gap-2.5 px-3 py-2">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 shrink-0" aria-hidden="true" />
            <span className="text-xs text-neutral-600 font-mono">v4.3.0</span>
          </div>
        </div>
      </aside>
    </>
  )
}
